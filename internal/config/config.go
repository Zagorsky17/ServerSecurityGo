// Пакет config загружает настройки из переменных окружения.
//
// На сервере переменные задаёт systemd из файла /opt/serversecuritygo/.env
// (EnvironmentFile). Для ручного запуска тот же файл можно передать
// флагом --env-file. Полный список переменных с пояснениями — в
// .env.example.
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

// Config — все настройки приложения.
type Config struct {
	ListenAddr       string
	SocketPath       string // локальный Unix-сокет для терминального интерфейса; "" — выключен
	ScanInterval     time.Duration
	DataDir          string
	ProcRoot         string
	HostRoot         string
	AuthPasswordHash string
	SessionTTL       time.Duration
	TLSCert          string
	TLSKey           string
	TrustProxyTLS    bool
	AllowedHosts     []string
	LocalUIDs        []int // кому разрешена панель без пароля по loopback
	Retention        time.Duration
	EventsMaxMB      int
	CPUThreshold     float64
	CPUSustainScans  int
	MemThreshold     float64
	RecentDays       int
	AllowlistFile    string
	MaxFiles         int
	LogLevel         string
	// AuditEnabled — служба проверяет настройки безопасности (SSH,
	// учётные записи, sudo) при запуске и затем каждые AuditInterval.
	AuditEnabled  bool
	AuditInterval time.Duration
	// Lang — язык по умолчанию (SSG_LANG): вывод CLI, журнал и первое
	// открытие панели. Пусто — определяется автоматически (локаль
	// терминала, язык браузера).
	Lang i18n.Lang
}

// DefaultSocketPath — Unix-сокет службы. Каталог /run/serversecuritygo
// создаёт systemd (RuntimeDirectory) с правами 0700.
const DefaultSocketPath = "/run/serversecuritygo/api.sock"

// Default возвращает значения по умолчанию.
func Default() Config {
	return Config{
		ListenAddr:      "127.0.0.1:8090",
		SocketPath:      DefaultSocketPath,
		ScanInterval:    30 * time.Second,
		DataDir:         "/var/lib/serversecuritygo",
		ProcRoot:        "/proc",
		HostRoot:        "/",
		SessionTTL:      12 * time.Hour,
		Retention:       7 * 24 * time.Hour,
		EventsMaxMB:     20,
		CPUThreshold:    80,
		CPUSustainScans: 10,
		MemThreshold:    50,
		RecentDays:      7,
		AllowlistFile:   "/opt/serversecuritygo/allowlist.json",
		LocalUIDs:       []int{0},
		MaxFiles:        200,
		LogLevel:        "info",
		AuditEnabled:    true,
		AuditInterval:   time.Hour,
	}
}

// LoadEnvFile читает файл формата KEY=VALUE и выставляет переменные,
// которые ещё не заданы в окружении (окружение главнее файла).
// Поддерживаются комментарии (#) и значения в кавычках.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return i18n.Errorf("err.env_line", fmt.Sprintf("%s:%d", path, n))
		}
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return sc.Err()
}

// FromEnv собирает конфигурацию из переменных окружения SSG_*.
func FromEnv() (Config, error) {
	c := Default()
	var errs []error
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				errs = append(errs, i18n.Errorf("err.env_duration", key, strconv.Quote(v)))
				return
			}
			*dst = d
		}
	}
	num := func(key string, dst *int) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				errs = append(errs, i18n.Errorf("err.env_int", key, strconv.Quote(v)))
				return
			}
			*dst = n
		}
	}
	flt := func(key string, dst *float64) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 {
				errs = append(errs, i18n.Errorf("err.env_number", key, strconv.Quote(v)))
				return
			}
			*dst = f
		}
	}
	str("SSG_LISTEN_ADDR", &c.ListenAddr)
	str("SSG_SOCKET_PATH", &c.SocketPath)
	if strings.EqualFold(c.SocketPath, "off") {
		c.SocketPath = ""
	}
	dur("SSG_SCAN_INTERVAL", &c.ScanInterval)
	str("SSG_DATA_DIR", &c.DataDir)
	str("SSG_PROC_ROOT", &c.ProcRoot)
	str("SSG_HOST_ROOT", &c.HostRoot)
	str("SSG_AUTH_PASSWORD_HASH", &c.AuthPasswordHash)
	dur("SSG_SESSION_TTL", &c.SessionTTL)
	str("SSG_TLS_CERT", &c.TLSCert)
	str("SSG_TLS_KEY", &c.TLSKey)
	if v := os.Getenv("SSG_TRUST_PROXY_TLS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, i18n.Errorf("err.env_bool", "SSG_TRUST_PROXY_TLS"))
		}
		c.TrustProxyTLS = b
	}
	if v := os.Getenv("SSG_AUDIT_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, i18n.Errorf("err.env_bool", "SSG_AUDIT_ENABLED"))
		}
		c.AuditEnabled = b
	}
	dur("SSG_AUDIT_INTERVAL", &c.AuditInterval)
	if v := os.Getenv("SSG_ALLOWED_HOSTS"); v != "" {
		for h := range strings.SplitSeq(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.AllowedHosts = append(c.AllowedHosts, strings.ToLower(h))
			}
		}
	}
	if v := os.Getenv("SSG_LOCAL_UIDS"); strings.TrimSpace(v) != "" {
		c.LocalUIDs = nil
		for f := range strings.SplitSeq(v, ",") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			uid, err := strconv.Atoi(f)
			if err != nil || uid < 0 {
				errs = append(errs, i18n.Errorf("err.env_uids", strconv.Quote(f)))
				continue
			}
			c.LocalUIDs = append(c.LocalUIDs, uid)
		}
	}
	dur("SSG_HISTORY_RETENTION", &c.Retention)
	num("SSG_EVENTS_MAX_MB", &c.EventsMaxMB)
	flt("SSG_CPU_THRESHOLD", &c.CPUThreshold)
	num("SSG_CPU_SUSTAIN_SCANS", &c.CPUSustainScans)
	flt("SSG_MEM_THRESHOLD", &c.MemThreshold)
	num("SSG_RECENT_DAYS", &c.RecentDays)
	str("SSG_ALLOWLIST_FILE", &c.AllowlistFile)
	num("SSG_MAX_FILES_PER_PROCESS", &c.MaxFiles)
	str("SSG_LOG_LEVEL", &c.LogLevel)
	if v := strings.TrimSpace(os.Getenv("SSG_LANG")); v != "" {
		if l, ok := i18n.Parse(v); ok {
			c.Lang = l
		} else {
			errs = append(errs, i18n.Errorf("err.env_lang", strconv.Quote(v)))
		}
	}
	if c.ScanInterval < 2*time.Second {
		errs = append(errs, i18n.Errorf("err.env_interval_min"))
	}
	if c.AuditInterval < time.Minute {
		errs = append(errs, i18n.Errorf("err.env_audit_interval_min"))
	}
	return c, errors.Join(errs...)
}

// IsLoopback сообщает, что адрес прослушивания доступен только локально.
func (c Config) IsLoopback() bool {
	host, _, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TLSEnabled — заданы сертификат и ключ.
func (c Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// ValidateSecurity проверяет, что удалённый доступ настроен безопасно:
// вне loopback обязательны пароль и TLS (свой или на reverse proxy).
func (c Config) ValidateSecurity() error {
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return i18n.Errorf("err.tls_pair")
	}
	// За reverse proxy панель может быть доступна из интернета, даже если
	// приложение слушает 127.0.0.1, поэтому пароль обязателен.
	if c.TrustProxyTLS && c.AuthPasswordHash == "" {
		return i18n.Errorf("err.proxy_needs_password")
	}
	if c.IsLoopback() {
		return nil
	}
	if c.AuthPasswordHash == "" {
		return i18n.Errorf("err.network_needs_password", c.ListenAddr)
	}
	if !c.TLSEnabled() && !c.TrustProxyTLS {
		return i18n.Errorf("err.network_needs_tls", c.ListenAddr)
	}
	return nil
}

// DetectConfig переводит настройки в параметры анализа.
func (c Config) DetectConfig() (detect.Config, error) {
	d := detect.DefaultConfig()
	d.CPUThreshold = c.CPUThreshold
	d.CPUSustainScan = c.CPUSustainScans
	d.MemThreshold = c.MemThreshold
	d.ScanInterval = c.ScanInterval
	d.RecentDays = c.RecentDays
	if c.AllowlistFile != "" {
		rules, err := LoadAllowlist(c.AllowlistFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return d, err
		}
		d.Allow = rules
	}
	return d, nil
}

// LoadAllowlist читает JSON-файл со списком правил подавления.
func LoadAllowlist(path string) ([]detect.AllowRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rules []detect.AllowRule `json:"rules"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc.Rules, nil
}
