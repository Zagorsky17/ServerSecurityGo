package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// file — содержимое и права файла поддельного дерева.
type file struct {
	data string
	mode os.FileMode
}

// tree пишет файлы относительно корня хоста; права по умолчанию 0644,
// каталоги 0755.
func tree(t *testing.T, files map[string]file) string {
	t.Helper()
	root := t.TempDir()
	for p, f := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(full, []byte(f.data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil { // umask
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, root string, b *Baseline) (map[string]model.AuditCheck, Baseline) {
	t.Helper()
	checks, next := Run(Options{HostRoot: root, RootUID: os.Getuid(), Baseline: b})
	m := map[string]model.AuditCheck{}
	for _, c := range checks {
		if _, dup := m[c.ID]; dup {
			t.Fatalf("повтор проверки %s", c.ID)
		}
		if c.Title.IsZero() || strings.HasPrefix(c.Title.String(), "audit.") {
			t.Errorf("%s без заголовка: %q", c.ID, c.Title.String())
		}
		m[c.ID] = c
	}
	return m, next
}

func evText(c model.AuditCheck) string { return i18n.Join("\n", c.Evidence...).String() }

func expect(t *testing.T, m map[string]model.AuditCheck, id, status string) model.AuditCheck {
	t.Helper()
	c, ok := m[id]
	if !ok {
		t.Fatalf("нет проверки %s", id)
	}
	if c.Status != status {
		t.Errorf("%s: статус %s, ожидался %s\n%s", id, c.Status, status, evText(c))
	}
	if (status == model.AuditFail || status == model.AuditWarn) && c.Recommendation.IsZero() {
		t.Errorf("%s: нет рекомендации", id)
	}
	return c
}

const osUbuntu = "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nID_LIKE=debian\n"

// TestSSHUbuntu — типичная Ubuntu: Include .d первой строкой, cloud-init
// включил вход по паролю, более поздний файл пытается его выключить.
func TestSSHUbuntu(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/os-release": {data: osUbuntu},
		"etc/ssh/sshd_config": {data: "Include /etc/ssh/sshd_config.d/*.conf\n\nKbdInteractiveAuthentication no\nUsePAM yes\n" +
			"X11Forwarding yes\nPrintMotd no\nSubsystem sftp /usr/lib/openssh/sftp-server\n"},
		"etc/ssh/sshd_config.d/50-cloud-init.conf": {data: "PasswordAuthentication yes\n"},
		"etc/ssh/sshd_config.d/60-local.conf":      {data: "PasswordAuthentication no\nPermitRootLogin yes\n"},
		"etc/ssh/sshd_config.d/notes.txt":          {data: "PermitEmptyPasswords yes\n"}, // не *.conf — не читается
		"etc/ssh/ssh_host_ed25519_key":             {data: "secret", mode: 0o600},
		"etc/ssh/ssh_host_rsa_key":                 {data: "secret", mode: 0o644},
	})
	m, _ := run(t, root, nil)
	c := expect(t, m, "ssh_password_auth", model.AuditFail)
	if !strings.Contains(evText(c), "50-cloud-init.conf:1") {
		t.Errorf("источник значения: %s", evText(c))
	}
	// Include .d стоит первым — исправление отдельным файлом 00-….
	if !strings.Contains(c.FixCommand, "sshd_config.d/00-passwordauthentication.conf") || !strings.Contains(c.FixCommand, "sshd -t") {
		t.Errorf("исправление: %s", c.FixCommand)
	}
	expect(t, m, "ssh_root_login", model.AuditFail) // 60-local.conf: yes, раньше нет других значений
	expect(t, m, "ssh_empty_passwords", model.AuditPass)
	expect(t, m, "ssh_kbd_interactive", model.AuditPass)
	expect(t, m, "ssh_x11_forwarding", model.AuditWarn)
	expect(t, m, "ssh_max_auth_tries", model.AuditWarn) // по умолчанию 6
	expect(t, m, "ssh_weak_crypto", model.AuditPass)
	expect(t, m, "ssh_authkeys_file", model.AuditPass)
	if c := expect(t, m, "ssh_host_keys_perms", model.AuditFail); !strings.Contains(evText(c), "ssh_host_rsa_key") || strings.Contains(evText(c), "ed25519") {
		t.Errorf("ключи хоста: %s", evText(c))
	}
	expect(t, m, "ssh_config_perms", model.AuditPass)
	expect(t, m, "ssh_allow_users", model.AuditInfo)
	expect(t, m, "ssh_banner_version", model.AuditInfo)
	expect(t, m, "ssh_port", model.AuditInfo)
}

// TestSSHMatchAndCrypto — блоки Match, синтаксис «Ключ=значение»,
// кавычки, устаревшие алгоритмы, нестандартные ключи.
func TestSSHMatchAndCrypto(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/os-release": {data: "ID=fedora\n"},
		"etc/ssh/sshd_config": {data: "# комментарий\nPasswordAuthentication=no\nPermitRootLogin \"no\"\nMaxAuthTries 3\n" +
			"Ciphers aes256-gcm@openssh.com,aes128-cbc\nMACs -hmac-sha1\nKexAlgorithms +diffie-hellman-group1-sha1\n" +
			"AuthorizedKeysFile .ssh/authorized_keys /tmp/.k/%u\nAuthorizedKeysCommand /opt/keys/get.sh %u\nAuthorizedKeysCommandUser nobody\n" +
			"GatewayPorts clientspecified\nKbdInteractiveAuthentication yes\nUsePAM yes\nPort 2222\nAllowUsers deploy\n" +
			"Match User deploy\n  PasswordAuthentication yes\nMatch all\n  PermitRootLogin yes\n"},
		"opt/keys/get.sh": {data: "#!/bin/sh\n", mode: 0o777},
	})
	m, _ := run(t, root, nil)
	if c := expect(t, m, "ssh_password_auth", model.AuditWarn); !strings.Contains(evText(c), "Match User deploy") {
		t.Errorf("Match: %s", evText(c))
	}
	// Match all действует на всех — это провал, а не предупреждение.
	expect(t, m, "ssh_root_login", model.AuditFail)
	c := expect(t, m, "ssh_weak_crypto", model.AuditFail)
	if ev := evText(c); !strings.Contains(ev, "aes128-cbc") || !strings.Contains(ev, "diffie-hellman-group1-sha1") || strings.Contains(ev, "устаревшие: hmac-sha1") {
		t.Errorf("алгоритмы: %s", ev)
	}
	if c := expect(t, m, "ssh_authkeys_file", model.AuditFail); !strings.Contains(evText(c), "/tmp/.k/%u") || !strings.Contains(evText(c), "/opt/keys/get.sh") {
		t.Errorf("ключи: %s", evText(c))
	}
	expect(t, m, "ssh_tcp_forwarding", model.AuditFail)
	expect(t, m, "ssh_kbd_interactive", model.AuditFail)
	expect(t, m, "ssh_max_auth_tries", model.AuditPass)
	expect(t, m, "ssh_port", model.AuditPass)
	expect(t, m, "ssh_allow_users", model.AuditPass)
	expect(t, m, "ssh_banner_version", model.AuditNA)
	// Без Include .d в начале исправление вставляет строку в начало файла.
	if c := m["ssh_tcp_forwarding"]; !strings.Contains(c.FixCommand, "sed -i '1i GatewayPorts no' /etc/ssh/sshd_config") {
		t.Errorf("исправление: %s", c.FixCommand)
	}
	// Значение из блока Match глобальной строкой не исправить: команды
	// нет, в фактах сказано, где править.
	if c := m["ssh_password_auth"]; c.FixCommand != "" || !strings.Contains(evText(c), "/etc/ssh/sshd_config:17") || !strings.Contains(evText(c), "исправьте его там") {
		t.Errorf("Match: %q\n%s", c.FixCommand, evText(c))
	}
	if c := m["ssh_root_login"]; c.FixCommand != "" {
		t.Errorf("Match all: %q", c.FixCommand)
	}
}

func TestSSHAbsentAndDefaults(t *testing.T) {
	m, _ := run(t, tree(t, map[string]file{"etc/os-release": {data: osUbuntu}}), nil)
	for id, c := range m {
		if strings.HasPrefix(id, "ssh_") && c.Status != model.AuditNA {
			t.Errorf("%s без sshd: %s", id, c.Status)
		}
	}
	// sshd есть, файла настроек нет — значения по умолчанию OpenSSH.
	m, _ = run(t, tree(t, map[string]file{"usr/sbin/sshd": {data: "elf", mode: 0o755}}), nil)
	if c := expect(t, m, "ssh_password_auth", model.AuditFail); !strings.Contains(evText(c), "по умолчанию") {
		t.Errorf("по умолчанию: %s", evText(c))
	}
	expect(t, m, "ssh_root_login", model.AuditPass) // prohibit-password
}

// TestSSHIncludeLoop — файл, включающий сам себя, не зацикливает разбор,
// а права на включённые файлы проверяются.
func TestSSHIncludeLoop(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/ssh/sshd_config":          {data: "Include sshd_config\nInclude conf/*.conf\nPasswordAuthentication no\n"},
		"etc/ssh/conf/a.conf":          {data: "Include /etc/ssh/conf/a.conf\nX11Forwarding no\n", mode: 0o666},
		"etc/ssh/sshd_config.d/x.conf": {data: "PasswordAuthentication yes\n"},
	})
	m, _ := run(t, root, nil)
	expect(t, m, "ssh_password_auth", model.AuditPass)
	if c := expect(t, m, "ssh_config_perms", model.AuditFail); !strings.Contains(evText(c), "/etc/ssh/conf/a.conf") {
		t.Errorf("права: %s", evText(c))
	}
}

// TestSSHDropInDirWritable: файлы в порядке, но каталог sshd_config.d
// доступен на запись всем — это провал.
func TestSSHDropInDirWritable(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/ssh/sshd_config":                      {data: "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"},
		"etc/ssh/sshd_config.d/50-cloud-init.conf": {data: "X11Forwarding no\n"},
	})
	if err := os.Chmod(filepath.Join(root, "etc/ssh/sshd_config.d"), 0o777); err != nil {
		t.Fatal(err)
	}
	m, _ := run(t, root, nil)
	if c := expect(t, m, "ssh_config_perms", model.AuditFail); !strings.Contains(evText(c), "/etc/ssh/sshd_config.d") {
		t.Errorf("каталог: %s", evText(c))
	}
}

func TestSplitSSHLine(t *testing.T) {
	for line, want := range map[string]string{
		"PasswordAuthentication yes":      "passwordauthentication|yes",
		"  PermitRootLogin=no  ":          "permitrootlogin|no",
		"Banner \"/etc/my banner\"":       "banner|/etc/my banner",
		"AllowUsers a b # comment":        "allowusers|a b",
		"# PasswordAuthentication yes":    "|",
		"":                                "|",
		"Subsystem\tsftp\t/usr/lib/sftp ": "subsystem|sftp /usr/lib/sftp",
	} {
		k, args := splitSSHLine(line)
		if got := k + "|" + strings.Join(args, " "); got != want {
			t.Errorf("%q → %q, ожидалось %q", line, got, want)
		}
	}
}

const passwd = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"toor:x:0:0::/root:/bin/bash\n" +
	"www-data:x:33:33:www-data:/var/www:/bin/bash\n" +
	"postgres:x:113:120:PostgreSQL:/var/lib/postgresql:/bin/bash\n" +
	"deploy:x:1000:1000::/home/deploy:/bin/bash\n" +
	"alice:x:1001:1001::/home/alice:/bin/bash\n" +
	"twin:x:1001:1001::/home/twin:/bin/bash\n" +
	"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"

const shadow = "root:!:19000:0:99999:7:::\n" +
	"toor::19000:0:99999:7:::\n" +
	"www-data:$6$salt$hash:19000::::::\n" +
	"postgres:*:19000::::::\n" +
	"deploy:$1$abcdefgh$SECRETHASHVALUE:19000::::::\n" +
	"alice:$y$j9T$salt$hash:19000::::::\n"

const group = "root:x:0:\nsudo:x:27:deploy\ndocker:x:999:alice\nadm:x:4:syslog\ndeploy:x:1000:\nalice:x:1001:\n"

func accountsTree(t *testing.T, extra map[string]file) string {
	files := map[string]file{
		"etc/passwd":      {data: passwd},
		"etc/shadow":      {data: shadow, mode: 0o644}, // читается всеми — провал
		"etc/group":       {data: group},
		"etc/gshadow":     {data: "", mode: 0o640},
		"etc/environment": {data: "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:.\"\n"},
		"root/.profile":   {data: "export PATH=$PATH:/opt/tools\n"},
		"opt/tools/x":     {data: ""},
	}
	for k, v := range extra {
		files[k] = v
	}
	root := tree(t, files)
	if err := os.MkdirAll(filepath.Join(root, "home/deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "home/deploy"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "opt/tools"), 0o777); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAccounts(t *testing.T) {
	root := accountsTree(t, nil)
	m, next := run(t, root, nil)
	if c := expect(t, m, "acct_uid0_extra", model.AuditFail); !strings.Contains(evText(c), "toor") {
		t.Errorf("uid0: %s", evText(c))
	}
	if c := expect(t, m, "acct_empty_password", model.AuditFail); !strings.Contains(evText(c), "toor") {
		t.Errorf("пустой пароль: %s", evText(c))
	}
	// www-data с паролем — провал; postgres с заблокированным — только факт.
	if c := expect(t, m, "acct_service_shell", model.AuditFail); !strings.Contains(evText(c), "www-data") || !strings.Contains(evText(c), "postgres (UID 113): оболочка /bin/bash, пароль заблокирован") {
		t.Errorf("оболочки: %s", evText(c))
	}
	if c := expect(t, m, "acct_weak_hash", model.AuditFail); !strings.Contains(evText(c), "deploy: хеш MD5") {
		t.Errorf("хеши: %s", evText(c))
	}
	if c := expect(t, m, "acct_priv_groups", model.AuditInfo); !strings.Contains(evText(c), "sudo: deploy") || !strings.Contains(evText(c), "docker: alice") {
		t.Errorf("группы: %s", evText(c))
	}
	if c := expect(t, m, "acct_duplicate_ids", model.AuditFail); !strings.Contains(evText(c), "1001") || !strings.Contains(evText(c), "«0»") {
		t.Errorf("повторы: %s", evText(c))
	}
	if c := expect(t, m, "acct_passwd_perms", model.AuditFail); !strings.Contains(evText(c), "/etc/shadow") || strings.Contains(evText(c), "/etc/gshadow") {
		t.Errorf("права: %s", evText(c))
	}
	if c := expect(t, m, "acct_home_perms", model.AuditFail); !strings.Contains(evText(c), "/home/deploy") {
		t.Errorf("домашние каталоги: %s", evText(c))
	}
	if c := expect(t, m, "acct_root_path", model.AuditFail); !strings.Contains(evText(c), "/etc/environment:1") || !strings.Contains(evText(c), "/opt/tools") {
		t.Errorf("PATH: %s", evText(c))
	}
	expect(t, m, "acct_new", model.AuditNA) // разовый запуск без базовой линии

	// Хеши паролей не попадают никуда.
	b, _ := json.Marshal(m)
	bn, _ := json.Marshal(next)
	for _, s := range []string{"SECRETHASHVALUE", "$6$salt", "$y$j9T"} {
		if strings.Contains(string(b), s) || strings.Contains(string(bn), s) {
			t.Errorf("хеш %q в результате", s)
		}
	}
	if next.Users["toor"] != 0 || next.Users["alice"] != 1001 || len(next.Priv["sudo"]) != 1 {
		t.Errorf("базовая линия: %+v", next)
	}
}

// TestAccountChanges — новые пользователи и члены групп между запусками.
func TestAccountChanges(t *testing.T) {
	root := accountsTree(t, nil)
	m, first := run(t, root, &Baseline{})
	expect(t, m, "acct_new", model.AuditPass)
	expect(t, m, "acct_priv_groups", model.AuditInfo)

	// Повтор без изменений.
	m, second := run(t, root, &first)
	expect(t, m, "acct_new", model.AuditPass)
	expect(t, m, "acct_priv_groups", model.AuditInfo)

	// Обычный новый пользователь — предупреждение.
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd+"bob:x:1002:1002::/home/bob:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, third := run(t, root, &second)
	if c := expect(t, m, "acct_new", model.AuditWarn); !strings.Contains(evText(c), "bob") {
		t.Errorf("новый пользователь: %s", evText(c))
	}
	// Новый член группы sudo и новый пользователь в ней — провал.
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd+"bob:x:1002:1002::/home/bob:/bin/bash\neve:x:1003:1003::/home/eve:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/group"), []byte(strings.Replace(group, "sudo:x:27:deploy", "sudo:x:27:deploy,eve", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	m, _ = run(t, root, &third)
	expect(t, m, "acct_new", model.AuditFail)
	if c := expect(t, m, "acct_priv_groups", model.AuditFail); !strings.Contains(evText(c), "eve добавлен в группу sudo") {
		t.Errorf("группы: %s", evText(c))
	}
}

func TestAccountsNoShadowAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root читает файл и с правами 000")
	}
	root := accountsTree(t, map[string]file{"etc/shadow": {data: shadow, mode: 0o200}})
	m, _ := run(t, root, nil)
	expect(t, m, "acct_empty_password", model.AuditUnknown)
	expect(t, m, "acct_weak_hash", model.AuditUnknown)
}

const sudoersText = `#
# This file MUST be edited with the 'visudo' command as root.
Defaults	env_reset
Defaults	env_keep += "LD_PRELOAD TERM"
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"

Cmnd_Alias EDIT = /usr/bin/vim /etc/nginx/*, /usr/bin/less : SVC = /usr/bin/systemctl restart nginx
User_Alias OPS = alice, bob

root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL # группа sudo
#1001	ALL=(ALL) /usr/bin/id
OPS ALL = (root) NOPASSWD: EDIT, \
	SVC, !/usr/bin/su
deploy ALL=(www-data) /usr/bin/find
@includedir /etc/sudoers.d
`

func sudoTree(t *testing.T, extra map[string]file) string {
	files := map[string]file{
		"etc/sudoers":                       {data: sudoersText, mode: 0o440},
		"etc/sudoers.d/90-cloud-init-users": {data: "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n", mode: 0o440},
		"etc/sudoers.d/README":              {data: "# комментарий\n", mode: 0o440},
		// Файл с точкой в имени sudo не читает.
		"etc/sudoers.d/old.bak": {data: "Defaults !authenticate\n", mode: 0o440},
	}
	for k, v := range extra {
		files[k] = v
	}
	return tree(t, files)
}

func TestSudo(t *testing.T) {
	m, next := run(t, sudoTree(t, nil), nil)
	c := expect(t, m, "sudo_nopasswd_all", model.AuditFail)
	if c.Severity != model.RiskMedium || !strings.Contains(evText(c), "90-cloud-init-users:2") {
		t.Errorf("NOPASSWD для облачного пользователя: %s %s", c.Severity, evText(c))
	}
	c = expect(t, m, "sudo_gtfobins", model.AuditFail)
	for _, want := range []string{"vim:", "less:", "find: /usr/bin/find — от пользователя www-data"} {
		if !strings.Contains(evText(c), want) {
			t.Errorf("GTFOBins без %s: %s", want, evText(c))
		}
	}
	// systemctl с фиксированными аргументами оболочку не даёт.
	if strings.Contains(evText(c), "systemctl:") {
		t.Errorf("systemctl restart nginx в GTFOBins: %s", evText(c))
	}
	if strings.Contains(evText(c), "su:") {
		t.Errorf("запрещённая команда !/usr/bin/su попала в список: %s", evText(c))
	}
	if c := expect(t, m, "sudo_wildcard", model.AuditWarn); !strings.Contains(evText(c), "/etc/sudoers:") {
		t.Errorf("шаблоны: %s", evText(c))
	}
	expect(t, m, "sudo_env_keep", model.AuditFail)
	expect(t, m, "sudo_no_auth", model.AuditPass) // old.bak не читается
	expect(t, m, "sudo_writable_cmd", model.AuditPass)
	expect(t, m, "sudo_files_perms", model.AuditPass)
	expect(t, m, "sudo_changed", model.AuditNA)
	if len(next.Sudoers) != 3 {
		t.Errorf("файлы sudoers: %v", next.Sudoers)
	}
}

func TestSudoDangerous(t *testing.T) {
	root := sudoTree(t, map[string]file{
		"etc/sudoers.d/zz":   {data: "Defaults:deploy !authenticate\nDefaults !env_reset\ndeploy ALL=(root) /opt/tool/run.sh\nadmin2 ALL=(ALL) NOPASSWD: ALL\n", mode: 0o666},
		"opt/tool/run.sh":    {data: "#!/bin/sh\n", mode: 0o755},
		"etc/sudoers.d/perm": {data: "x ALL=(ALL) /usr/bin/id\n", mode: 0o444},
	})
	if err := os.Chmod(filepath.Join(root, "opt/tool"), 0o777); err != nil {
		t.Fatal(err)
	}
	m, _ := run(t, root, nil)
	expect(t, m, "sudo_no_auth", model.AuditFail)
	expect(t, m, "sudo_env_keep", model.AuditFail)
	if c := expect(t, m, "sudo_writable_cmd", model.AuditFail); !strings.Contains(evText(c), "/opt/tool ") {
		t.Errorf("доступный на запись каталог: %s", evText(c))
	}
	if c := expect(t, m, "sudo_nopasswd_all", model.AuditFail); c.Severity != model.RiskHigh {
		t.Errorf("NOPASSWD: ALL у обычного пользователя: %s", c.Severity)
	}
	c := expect(t, m, "sudo_files_perms", model.AuditFail)
	if !strings.Contains(evText(c), "/etc/sudoers.d/zz") || !strings.Contains(evText(c), "/etc/sudoers.d/perm") {
		t.Errorf("права: %s", evText(c))
	}
}

func TestSudoChanges(t *testing.T) {
	root := sudoTree(t, nil)
	m, first := run(t, root, &Baseline{})
	expect(t, m, "sudo_changed", model.AuditPass)
	m, second := run(t, root, &first)
	expect(t, m, "sudo_changed", model.AuditPass)
	cloud := filepath.Join(root, "etc/sudoers.d/90-cloud-init-users")
	if err := os.Chmod(cloud, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cloud, []byte("ubuntu ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sudoers.d/new"), []byte("eve ALL=(ALL) ALL\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "etc/sudoers.d/README")); err != nil {
		t.Fatal(err)
	}
	m, _ = run(t, root, &second)
	c := expect(t, m, "sudo_changed", model.AuditFail)
	for _, want := range []string{"изменён /etc/sudoers.d/90-cloud-init-users", "новый файл /etc/sudoers.d/new", "удалён /etc/sudoers.d/README"} {
		if !strings.Contains(evText(c), want) {
			t.Errorf("нет «%s»: %s", want, evText(c))
		}
	}
}

func TestSudoAbsent(t *testing.T) {
	m, _ := run(t, tree(t, nil), nil)
	for id, c := range m {
		if strings.HasPrefix(id, "sudo_") && c.Status != model.AuditNA {
			t.Errorf("%s без sudo: %s", id, c.Status)
		}
	}
}

func TestSudoParsing(t *testing.T) {
	if got := stripSudoComment(`%sudo ALL=(ALL) ALL # группа`); got != "%sudo ALL=(ALL) ALL" {
		t.Errorf("комментарий: %q", got)
	}
	if got := stripSudoComment(`#1000 ALL=(ALL) /usr/bin/id`); got != "#1000 ALL=(ALL) /usr/bin/id" {
		t.Errorf("UID: %q", got)
	}
	if got := splitTop(`(root, bob) /bin/a, /bin/b\, x, "c,d"`, ','); len(got) != 3 {
		t.Errorf("splitTop: %q", got)
	}
	lines := logicalLines("a \\\n  b\nc\n\n  \nd \\")
	if len(lines) != 3 || lines[0].text != "a    b" || lines[1].line != 3 || lines[2].text != "d" {
		t.Errorf("logicalLines: %+v", lines)
	}
	if !runsAsRoot("") || !runsAsRoot("ALL : ALL") || !runsAsRoot("root") || runsAsRoot("www-data") {
		t.Error("runsAsRoot")
	}
	for name, want := range map[string]bool{"/usr/bin/python3.12": true, "/usr/bin/vim.basic": true, "/usr/bin/id": false, "/bin/bash": true, "/usr/bin/sudoedit": false} {
		if _, got := gtfoName(name); got != want {
			t.Errorf("gtfoName(%s) = %v", name, got)
		}
	}
}

func TestSummary(t *testing.T) {
	pass, total := Summary([]model.AuditCheck{{Status: model.AuditPass}, {Status: model.AuditFail}, {Status: model.AuditWarn},
		{Status: model.AuditInfo}, {Status: model.AuditNA}, {Status: model.AuditUnknown}})
	if pass != 1 || total != 3 {
		t.Errorf("Summary = %d из %d", pass, total)
	}
}

// TestSudoGTFOUserOnly: команды только от другого пользователя — «требует
// внимания», а не «опасно».
func TestSudoGTFOUserOnly(t *testing.T) {
	root := tree(t, map[string]file{"etc/sudoers": {data: "deploy ALL=(www-data) /usr/bin/find\nops ALL=(root) /usr/bin/apt-get update\n", mode: 0o440}})
	m, _ := run(t, root, nil)
	expect(t, m, "sudo_gtfobins", model.AuditWarn)
}

// TestSudoMissingCmdInWritableDir: разрешённой команды нет, но каталог
// доступен на запись — пользователь создаст её и получит root.
func TestSudoMissingCmdInWritableDir(t *testing.T) {
	root := tree(t, map[string]file{"etc/sudoers": {data: "deploy ALL=(root) NOPASSWD: /opt/app/deploy.sh\n", mode: 0o440}})
	if err := os.MkdirAll(filepath.Join(root, "opt/app"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "opt/app"), 0o777); err != nil {
		t.Fatal(err)
	}
	m, _ := run(t, root, nil)
	if c := expect(t, m, "sudo_writable_cmd", model.AuditFail); !strings.Contains(evText(c), "/opt/app ") {
		t.Errorf("факты: %s", evText(c))
	}
}

// TestServiceShellEmptyAndUnknown: пустой пароль — не «заблокирован»;
// без прав на shadow — unknown, а не fail.
func TestServiceShellEmptyAndUnknown(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/passwd": {data: "root:x:0:0::/root:/bin/bash\npostgres:x:113:120::/var/lib/postgresql:/bin/bash\n"},
		"etc/shadow": {data: "root:!:1::::::\npostgres::1::::::\n", mode: 0o640},
	})
	m, _ := run(t, root, nil)
	if c := expect(t, m, "acct_service_shell", model.AuditFail); !strings.Contains(evText(c), "пароль не заблокирован") {
		t.Errorf("пустой пароль: %s", evText(c))
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Join(root, "etc/shadow"), 0o200); err != nil {
			t.Fatal(err)
		}
		m, _ = run(t, root, nil)
		expect(t, m, "acct_service_shell", model.AuditUnknown)
	}
}

func TestRootPathTilde(t *testing.T) {
	root := tree(t, map[string]file{
		"etc/passwd":    {data: "root:x:0:0::/root:/bin/bash\n"},
		"root/.bashrc":  {data: "export PATH=~/.local/bin:$PATH\nexport PATH=~deploy/bin:$PATH\n"},
		"root/.local/x": {data: ""},
	})
	m, _ := run(t, root, nil)
	expect(t, m, "acct_root_path", model.AuditPass)
}

// TestChangeWindow: изменение держит проверку в fail сутки, затем
// забывается; базовая линия не теряется, если файл не прочитался.
func TestChangeWindow(t *testing.T) {
	root := accountsTree(t, nil)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	runAt := func(at time.Time, b *Baseline) (map[string]model.AuditCheck, Baseline) {
		checks, next := Run(Options{HostRoot: root, RootUID: os.Getuid(), Baseline: b, Now: at})
		m := map[string]model.AuditCheck{}
		for _, c := range checks {
			m[c.ID] = c
		}
		return m, next
	}
	_, b := runAt(t0, &Baseline{})
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(passwd+"bob:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, b := runAt(t0.Add(time.Hour), &b)
	expect(t, m, "acct_new", model.AuditFail)
	// Следующий запуск: в базовой линии bob уже есть, но тревога держится.
	m, b = runAt(t0.Add(2*time.Hour), &b)
	if c := expect(t, m, "acct_new", model.AuditFail); !strings.Contains(evText(c), "bob") || !c.Change {
		t.Errorf("тревога погасла: %s", evText(c))
	}
	// /etc/passwd временно не читается — базовая линия не теряется.
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Join(root, "etc/passwd"), 0o200); err != nil {
			t.Fatal(err)
		}
		_, b = runAt(t0.Add(3*time.Hour), &b)
		if len(b.Users) == 0 {
			t.Fatal("базовая линия пользователей потеряна")
		}
		if err := os.Chmod(filepath.Join(root, "etc/passwd"), 0o644); err != nil {
			t.Fatal(err)
		}
		m, b = runAt(t0.Add(4*time.Hour), &b)
		if c := m["acct_new"]; strings.Contains(evText(c), "root") {
			t.Errorf("после сбоя чтения все пользователи «новые»: %s", evText(c))
		}
	}
	// Через сутки изменение забывается.
	m, _ = runAt(t0.Add(ChangeWindow+2*time.Hour), &b)
	expect(t, m, "acct_new", model.AuditPass)
}
