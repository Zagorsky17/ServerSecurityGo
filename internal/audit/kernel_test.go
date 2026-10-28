package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// procTree пишет поддельный /proc/sys: путь относительно /proc/sys →
// значение.
func procTree(t *testing.T, vals map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, v := range vals {
		full := filepath.Join(root, "sys", name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func kernelRun(t *testing.T, hostRoot, procRoot string) map[string]model.AuditCheck {
	t.Helper()
	checks, _ := Run(Options{HostRoot: hostRoot, ProcRoot: procRoot, RootUID: os.Getuid()})
	m := map[string]model.AuditCheck{}
	for _, c := range checks {
		m[c.ID] = c
	}
	return m
}

// TestKernelSysctl: значения /proc/sys сверяются с ожидаемыми; файла
// conntrack нет — проверка неприменима, а не «нет данных».
func TestKernelSysctl(t *testing.T) {
	procRoot := procTree(t, map[string]string{
		"net/ipv4/tcp_syncookies":              "0\n",
		"net/ipv4/tcp_max_syn_backlog":         "256\n",
		"net/core/somaxconn":                   "4096\n",
		"net/ipv4/tcp_synack_retries":          "5\n",
		"net/ipv4/icmp_echo_ignore_broadcasts": "1\n",
	})
	m := kernelRun(t, t.TempDir(), procRoot)
	c := expect(t, m, "net_syncookies", model.AuditWarn)
	if c.Group != model.AuditGroupKernel {
		t.Errorf("группа %q", c.Group)
	}
	if !strings.Contains(c.FixCommand, "net.ipv4.tcp_syncookies = 1") || !strings.Contains(c.FixCommand, "sysctl --system") {
		t.Errorf("команда исправления: %q", c.FixCommand)
	}
	if !strings.Contains(evText(c), "/proc/sys/net/ipv4/tcp_syncookies = 0") {
		t.Errorf("факты: %s", evText(c))
	}
	expect(t, m, "net_syn_backlog", model.AuditInfo)
	expect(t, m, "net_somaxconn", model.AuditPass)
	expect(t, m, "net_synack_retries", model.AuditInfo)
	expect(t, m, "net_icmp_broadcast", model.AuditPass)
	expect(t, m, "net_conntrack_max", model.AuditNA)

	// Значения в порядке, conntrack на месте.
	procRoot = procTree(t, map[string]string{
		"net/ipv4/tcp_syncookies":              "1\n",
		"net/ipv4/tcp_max_syn_backlog":         "1024\n",
		"net/core/somaxconn":                   "4096\n",
		"net/ipv4/tcp_synack_retries":          "2\n",
		"net/ipv4/icmp_echo_ignore_broadcasts": "1\n",
		"net/netfilter/nf_conntrack_max":       "262144\n",
	})
	m = kernelRun(t, t.TempDir(), procRoot)
	for _, id := range []string{"net_syncookies", "net_syn_backlog", "net_somaxconn", "net_synack_retries", "net_icmp_broadcast", "net_conntrack_max"} {
		expect(t, m, id, model.AuditPass)
	}
	// Маленькая таблица conntrack — требует внимания.
	m = kernelRun(t, t.TempDir(), procTree(t, map[string]string{"net/netfilter/nf_conntrack_max": "16384\n"}))
	expect(t, m, "net_conntrack_max", model.AuditWarn)
	// Без /proc данных нет — это не «в порядке».
	m = kernelRun(t, t.TempDir(), "")
	expect(t, m, "net_syncookies", model.AuditUnknown)
}

// TestSSHRateLimit: ограничение частоты даёт либо ufw limit на порту из
// sshd_config, либо jail fail2ban.
func TestSSHRateLimit(t *testing.T) {
	proc := procTree(t, nil)
	// Ничего не ограничивает.
	m := kernelRun(t, t.TempDir(), proc)
	c := expect(t, m, "fw_ssh_ratelimit", model.AuditInfo)
	if c.FixCommand != "ufw limit 22/tcp" {
		t.Errorf("команда исправления: %q", c.FixCommand)
	}
	// Нестандартный порт SSH и правило limit именно на него.
	root := tree(t, map[string]file{
		"etc/ssh/sshd_config": {data: "Port 2222\n"},
		"etc/ufw/ufw.conf":    {data: "ENABLED=yes\n"},
		"etc/ufw/user.rules": {data: "### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in\n" +
			"### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n"},
	})
	expect(t, kernelRun(t, root, proc), "fw_ssh_ratelimit", model.AuditPass)
	// Правило limit на 22, а SSH слушает 2222: ограничения нет.
	root = tree(t, map[string]file{
		"etc/ssh/sshd_config": {data: "Port 2222\n"},
		"etc/ufw/ufw.conf":    {data: "ENABLED=yes\n"},
		"etc/ufw/user.rules":  {data: "### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"},
	})
	c = expect(t, kernelRun(t, root, proc), "fw_ssh_ratelimit", model.AuditInfo)
	if c.FixCommand != "ufw limit 2222/tcp" {
		t.Errorf("команда исправления: %q", c.FixCommand)
	}
	// fail2ban с включённым jail для SSH — тоже ограничение.
	root = tree(t, map[string]file{
		"etc/fail2ban/jail.conf":     {data: "[DEFAULT]\nenabled = false\n\n[sshd]\nport = ssh\n"},
		"etc/fail2ban/jail.local":    {data: "[sshd]\nenabled = true\n"},
		"etc/fail2ban/fail2ban.conf": {data: "[Definition]\nlogtarget = /var/log/fail2ban.log\n"},
	})
	expect(t, kernelRun(t, root, proc), "fw_ssh_ratelimit", model.AuditPass)
}
