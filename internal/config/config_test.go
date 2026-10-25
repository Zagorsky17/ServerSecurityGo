package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

func TestValidateSecurity(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"loopback без пароля", Config{ListenAddr: "127.0.0.1:8090"}, true},
		{"localhost", Config{ListenAddr: "localhost:8090"}, true},
		{"ipv6 loopback", Config{ListenAddr: "[::1]:8090"}, true},
		{"сеть без пароля", Config{ListenAddr: "0.0.0.0:8090"}, false},
		{"сеть с паролем без TLS", Config{ListenAddr: "0.0.0.0:8090", AuthPasswordHash: "x"}, false},
		{"сеть с паролем и TLS", Config{ListenAddr: "0.0.0.0:8443", AuthPasswordHash: "x", TLSCert: "c", TLSKey: "k"}, true},
		{"сеть за прокси", Config{ListenAddr: "10.0.0.5:8090", AuthPasswordHash: "x", TrustProxyTLS: true}, true},
		{"прокси без пароля", Config{ListenAddr: "127.0.0.1:8090", TrustProxyTLS: true}, false},
		{"только сертификат", Config{ListenAddr: "127.0.0.1:8090", TLSCert: "c"}, false},
	}
	for _, c := range cases {
		err := c.cfg.ValidateSecurity()
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestFromEnvAndEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# комментарий\nSSG_SCAN_INTERVAL=15s\nSSG_LISTEN_ADDR=\"127.0.0.1:9000\"\nexport SSG_CPU_THRESHOLD=70\nSSG_ALLOWED_HOSTS=Mon.Example.com, 10.0.0.5\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"SSG_SCAN_INTERVAL", "SSG_LISTEN_ADDR", "SSG_CPU_THRESHOLD", "SSG_ALLOWED_HOSTS"} {
		t.Setenv(k, "") // восстановится после теста
		os.Unsetenv(k)
	}
	if err := LoadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.ScanInterval != 15*time.Second || c.ListenAddr != "127.0.0.1:9000" || c.CPUThreshold != 70 {
		t.Errorf("значения: %+v", c)
	}
	if len(c.AllowedHosts) != 2 || c.AllowedHosts[0] != "mon.example.com" {
		t.Errorf("hosts: %v", c.AllowedHosts)
	}
	t.Setenv("SSG_SCAN_INTERVAL", "abc")
	if _, err := FromEnv(); err == nil {
		t.Error("неверная длительность принята")
	}
	t.Setenv("SSG_SCAN_INTERVAL", "1s")
	if _, err := FromEnv(); err == nil {
		t.Error("слишком частое сканирование принято")
	}
}

func TestAllowlistFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow.json")
	os.WriteFile(path, []byte(`{"rules":[{"exe":"/opt/app/*","rules":["exe_in_temp"],"comment":"x"}]}`), 0o644)
	rules, err := LoadAllowlist(path)
	if err != nil || len(rules) != 1 || rules[0].Exe != "/opt/app/*" {
		t.Errorf("%v %v", rules, err)
	}
	c := Default()
	c.AllowlistFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := c.DetectConfig(); err != nil {
		t.Errorf("отсутствующий allowlist должен быть допустим: %v", err)
	}
	os.WriteFile(path, []byte("{bad"), 0o644)
	c.AllowlistFile = path
	if _, err := c.DetectConfig(); err == nil {
		t.Error("битый allowlist принят")
	}
}

func TestLocalUIDs(t *testing.T) {
	t.Setenv("SSG_LOCAL_UIDS", "")
	os.Unsetenv("SSG_LOCAL_UIDS")
	if c, _ := FromEnv(); len(c.LocalUIDs) != 1 || c.LocalUIDs[0] != 0 {
		t.Errorf("по умолчанию: %v", c.LocalUIDs)
	}
	t.Setenv("SSG_LOCAL_UIDS", "0, 1000")
	if c, err := FromEnv(); err != nil || len(c.LocalUIDs) != 2 || c.LocalUIDs[1] != 1000 {
		t.Errorf("0,1000: %v %v", c.LocalUIDs, err)
	}
	for _, bad := range []string{"root", "-1", "1000x"} {
		t.Setenv("SSG_LOCAL_UIDS", bad)
		if _, err := FromEnv(); err == nil {
			t.Errorf("%q принято", bad)
		}
	}
}

func TestLang(t *testing.T) {
	t.Setenv("SSG_LANG", "")
	if c, err := FromEnv(); err != nil || c.Lang != "" {
		t.Errorf("пусто — автоопределение: %v %q", err, c.Lang)
	}
	t.Setenv("SSG_LANG", "EN")
	if c, err := FromEnv(); err != nil || c.Lang != i18n.EN {
		t.Errorf("EN: %v %q", err, c.Lang)
	}
	t.Setenv("SSG_LANG", "de")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "SSG_LANG") {
		t.Errorf("неизвестный язык должен быть ошибкой: %v", err)
	}
}

func TestAuditSettings(t *testing.T) {
	t.Setenv("SSG_AUDIT_ENABLED", "false")
	t.Setenv("SSG_AUDIT_INTERVAL", "30m")
	c, err := FromEnv()
	if err != nil || c.AuditEnabled || c.AuditInterval != 30*time.Minute {
		t.Fatalf("%v %+v", err, c)
	}
	if d := Default(); !d.AuditEnabled || d.AuditInterval != time.Hour {
		t.Errorf("по умолчанию: %v %v", d.AuditEnabled, d.AuditInterval)
	}
	for k, v := range map[string]string{"SSG_AUDIT_ENABLED": "maybe", "SSG_AUDIT_INTERVAL": "10s"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := FromEnv(); err == nil {
				t.Errorf("%s=%s принят", k, v)
			}
		})
	}
}

func TestLogDays(t *testing.T) {
	if d := Default(); d.LogDays != 14 {
		t.Errorf("по умолчанию: %d", d.LogDays)
	}
	t.Setenv("SSG_AUTH_LOG_DAYS", "30")
	if c, err := FromEnv(); err != nil || c.LogDays != 30 {
		t.Fatalf("%v %d", err, c.LogDays)
	}
	for _, v := range []string{"0", "366", "-1", "abc"} {
		t.Setenv("SSG_AUTH_LOG_DAYS", v)
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "SSG_AUTH_LOG_DAYS") {
			t.Errorf("SSG_AUTH_LOG_DAYS=%s принят: %v", v, err)
		}
	}
}
