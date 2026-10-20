package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
