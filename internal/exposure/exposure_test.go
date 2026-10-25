package exposure

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		addr     string
		scope    string
		wildcard bool
	}{
		{"0.0.0.0", model.ScopePublic, true},
		{"::", model.ScopePublic, true},
		{"127.0.0.1", model.ScopeLoopback, false},
		{"127.0.0.53", model.ScopeLoopback, false},
		{"::1", model.ScopeLoopback, false},
		{"::ffff:127.0.0.1", model.ScopeLoopback, false},
		{"10.1.2.3", model.ScopePrivate, false},
		{"172.16.0.1", model.ScopePrivate, false},
		{"172.31.255.255", model.ScopePrivate, false},
		{"172.32.0.1", model.ScopePublic, false},
		{"192.168.1.1", model.ScopePrivate, false},
		{"100.64.0.1", model.ScopePrivate, false},
		{"100.128.0.1", model.ScopePublic, false},
		{"169.254.1.1", model.ScopePrivate, false},
		{"fe80::1", model.ScopePrivate, false},
		{"fd00::1", model.ScopePrivate, false},
		{"8.8.8.8", model.ScopePublic, false},
		{"2a00:1450::1", model.ScopePublic, false},
		{"::ffff:203.0.113.5", model.ScopePublic, false},
		// Нераспознанный адрес считается публичным: лучше показать лишнее.
		{"не адрес", model.ScopePublic, false},
		{"", model.ScopePublic, false},
	}
	for _, c := range cases {
		s, w := Classify(c.addr)
		if s != c.scope || w != c.wildcard {
			t.Errorf("Classify(%q) = %s,%v; ожидалось %s,%v", c.addr, s, w, c.scope, c.wildcard)
		}
	}
}

func TestRecognize(t *testing.T) {
	cases := []struct {
		name      string
		t         target
		want      string
		match     string
		confident bool
	}{
		{"redis по порту и процессу", target{proto: "tcp", port: 6379, names: []string{"redis-server"}}, "redis", "port+process", true},
		{"redis на нестандартном порту", target{proto: "tcp", port: 7000, names: []string{"redis-server"}}, "redis", "process", true},
		{"по одному порту — неуверенно", target{proto: "tcp", port: 6379, names: []string{"python3"}}, "redis", "port", false},
		{"владелец неизвестен — тоже неуверенно", target{proto: "tcp", port: 27017}, "mongodb", "port", false},
		{"NFS ядра без процесса — уверенно", target{proto: "tcp", port: 2049}, "nfs", "port", true},
		{"образ контейнера", target{proto: "tcp", port: 6379, image: "redis"}, "redis", "port+image", true},
		{"образ на другом порту", target{proto: "tcp", port: 8080, image: "mongo"}, "mongodb", "image", true},
		{"dockerd на порту Swarm — не Docker API", target{proto: "tcp", port: 2377, names: []string{"dockerd"}}, "", "", false},
		{"Docker API", target{proto: "tcp", port: 2375, names: []string{"dockerd"}}, "docker_api", "port+process", true},
		{"Elasticsearch по командной строке java", target{proto: "tcp", port: 9200, names: []string{"java"}, text: "/usr/share/elasticsearch/jdk/bin/java -des.path.home=/usr/share/elasticsearch org.elasticsearch.bootstrap.elasticsearch"}, "elasticsearch", "port+process", true},
		{"экспортер по шаблону имени", target{proto: "tcp", port: 9187, names: []string{"postgres_export", "postgres_exporter"}}, "prometheus_exporter", "process", true},
		{"SNMP только UDP", target{proto: "tcp", port: 161, names: []string{"snmpd"}}, "", "", false},
		{"SNMP UDP", target{proto: "udp", port: 161, names: []string{"snmpd"}}, "snmp", "port+process", true},
		{"memcached UDP", target{proto: "udp", port: 11211, names: []string{"memcached"}}, "memcached", "port+process", true},
		{"VNC диапазон", target{proto: "tcp", port: 5905, names: []string{"Xtigervnc"}}, "vnc", "port+process", true},
		{"jupyter без порта по командной строке", target{proto: "tcp", port: 9999, names: []string{"python3"}, text: "/usr/bin/python3 -m jupyter lab"}, "jupyter", "process", true},
		{"слово jupyter в пути чужого приложения", target{proto: "tcp", port: 8000, names: []string{"gunicorn"}, text: "/usr/bin/python3 /usr/bin/gunicorn app:app --chdir /srv/jupyter-dashboard"}, "", "", false},
		{"слово elasticsearch в пути не делает процесс Elasticsearch", target{proto: "tcp", port: 9600, names: []string{"java"}, text: "/usr/share/logstash/jdk/bin/java -path.config /etc/elasticsearch/pipeline"}, "", "", false},
		{"rabbit hint без порта не узнаётся", target{proto: "tcp", port: 25672, names: []string{"beam.smp"}, text: "/usr/lib/erlang/erts/bin/beam.smp -- -root /usr/lib/erlang -rabbit"}, "", "", false},
		{"неизвестный сервис", target{proto: "tcp", port: 8443, names: []string{"myapp"}}, "", "", false},
	}
	for _, c := range cases {
		svc, match, confident := recognize(c.t)
		got := ""
		if svc != nil {
			got = svc.id
		}
		if got != c.want || match != c.match || confident != c.confident {
			t.Errorf("%s: %q %q %v; ожидалось %q %q %v", c.name, got, match, confident, c.want, c.match, c.confident)
		}
	}
}

// TestServiceTable: таблица согласована — у каждой строки есть ключи
// каталога, класс известен, уровень не INFO.
func TestServiceTable(t *testing.T) {
	ids := map[string]bool{}
	for _, s := range services {
		if ids[s.id] {
			t.Errorf("повтор id %q", s.id)
		}
		ids[s.id] = true
		if !i18n.Has(s.rec) {
			t.Errorf("%s: нет ключа %q", s.id, s.rec)
		}
		k, ok := classKeys[s.class]
		if !ok || !i18n.Has(k[0]) || !i18n.Has(k[1]) {
			t.Errorf("%s: класс %q без ключей каталога", s.id, s.class)
		}
		if s.sev < model.RiskLow {
			t.Errorf("%s: уровень %s", s.id, s.sev)
		}
		if len(s.ports) == 0 {
			t.Errorf("%s: нет портов", s.id)
		}
		for _, p := range s.procs {
			if _, err := filepath.Match(p, "x"); err != nil {
				t.Errorf("%s: неверный шаблон %q", s.id, p)
			}
		}
	}
}

func TestImageBase(t *testing.T) {
	for in, want := range map[string]string{
		"redis":                             "redis",
		"redis:7-alpine":                    "redis",
		"docker.io/library/redis:7":         "redis",
		"bitnami/redis:latest":              "redis",
		"localhost:5000/team/mongo:7":       "mongo",
		"ghcr.io/org/app@sha256:0123456789": "app",
		"Postgres:16":                       "postgres",
		"":                                  "",
	} {
		if got := ImageBase(in); got != want {
			t.Errorf("ImageBase(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestParseDockerProxyArgs(t *testing.T) {
	b, ok := ParseDockerProxyArgs([]string{"/usr/bin/docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0", "-host-port", "8080",
		"-container-ip", "172.17.0.2", "-container-port", "80", "-use-listen-fd"})
	if !ok || b.Proto != "tcp" || b.HostIP != "0.0.0.0" || b.HostPort != 8080 || b.ContainerPort != 80 || b.Source != "docker-proxy" {
		t.Errorf("обычный формат: %+v %v", b, ok)
	}
	b, ok = ParseDockerProxyArgs([]string{"docker-proxy", "--proto=udp", "--host-ip=::", "--host-port=53", "--container-port=53"})
	if !ok || b.Proto != "udp" || b.HostIP != "::" || b.HostPort != 53 {
		t.Errorf("формат с =: %+v %v", b, ok)
	}
	b, ok = ParseDockerProxyArgs([]string{"docker-proxy", "-host-port", "443", "-container-port", "8443"})
	if !ok || b.Proto != "tcp" || b.HostIP != "0.0.0.0" {
		t.Errorf("значения по умолчанию: %+v %v", b, ok)
	}
	for _, bad := range [][]string{
		nil,
		{"docker-proxy"},
		{"docker-proxy", "-host-port", "x", "-container-port", "80"},
		{"docker-proxy", "-host-port", "70000", "-container-port", "80"},
		{"docker-proxy", "-host-port", "0", "-container-port", "80"},
		{"docker-proxy", "-proto", "sctp", "-host-port", "80", "-container-port", "80"},
		{"docker-proxy", "-host-port"},
	} {
		if b, ok := ParseDockerProxyArgs(bad); ok {
			t.Errorf("%q разобран: %+v", bad, b)
		}
	}
}

func TestParseContainerConfig(t *testing.T) {
	cfg := `{"ID":"0123456789abcdef0123","Name":"/web","Config":{"Image":"nginx:1.27","Env":["DB_PASSWORD=secret"]},"State":{"Running":true},
	"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}],"443/tcp":null,
	"53/udp":[{"HostIp":"","HostPort":"5353"}],"bad/tcp":[{"HostIp":"","HostPort":"1"}],"81/sctp":[{"HostIp":"","HostPort":"81"}],
	"82/tcp":[{"HostIp":"","HostPort":"0"}],"83/tcp":[{"HostIp":"","HostPort":""}]}}}`
	got := ParseContainerConfig([]byte(cfg))
	if len(got) != 3 {
		t.Fatalf("привязки: %+v", got)
	}
	slices.SortFunc(got, func(a, b model.PortBinding) int {
		return strings.Compare(a.Proto+a.HostIP, b.Proto+b.HostIP)
	})
	if b := got[0]; b.HostIP != "0.0.0.0" || b.HostPort != 8080 || b.ContainerPort != 80 || b.ContainerName != "web" || b.Image != "nginx:1.27" || b.ContainerID != "0123456789ab" {
		t.Errorf("tcp 0.0.0.0: %+v", b)
	}
	if b := got[2]; b.Proto != "udp" || b.HostIP != "0.0.0.0" || b.HostPort != 5353 {
		t.Errorf("udp с пустым HostIp: %+v", b)
	}
	// Остановленный контейнер и мусор — без привязок.
	if got := ParseContainerConfig([]byte(strings.Replace(cfg, `"Running":true`, `"Running":false`, 1))); len(got) != 0 {
		t.Errorf("остановленный контейнер: %+v", got)
	}
	for _, bad := range []string{"", "{", "null", "[]", `{"State":{"Running":"yes"}}`} {
		if got := ParseContainerConfig([]byte(bad)); len(got) != 0 {
			t.Errorf("%q: %+v", bad, got)
		}
	}
}

// writeFiles пишет файлы относительно корня хоста.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const (
	cid1 = "1111111111111111111111111111111111111111111111111111111111111111"
	cid2 = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestReadDocker(t *testing.T) {
	root := t.TempDir()
	// Нет Docker — пусто и без предупреждений.
	if b, w := ReadDocker(root); len(b) != 0 || len(w) != 0 {
		t.Errorf("без Docker: %v %v", b, w)
	}
	cfg := `{"ID":"%s","Name":"/%s","Config":{"Image":"redis:7"},"State":{"Running":true},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"","HostPort":"%s"}]}}}`
	writeFiles(t, root, map[string]string{
		"etc/docker/daemon.json":                            `{"data-root": "/srv/docker"}`,
		"srv/docker/containers/" + cid1 + "/config.v2.json": fmt.Sprintf(cfg, cid1, "cache", "6379"),
		// Каталог с неподходящим именем пропускается.
		"srv/docker/containers/not-a-container/config.v2.json": fmt.Sprintf(cfg, cid1, "fake", "1"),
	})
	// Симлинк вместо config.v2.json не читается: файл подменить на
	// чужой нельзя.
	dir2 := filepath.Join(root, "srv/docker/containers", cid2)
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other.json")
	writeFiles(t, root, map[string]string{"other.json": fmt.Sprintf(cfg, cid2, "evil", "9999")})
	if err := os.Symlink(other, filepath.Join(dir2, "config.v2.json")); err != nil {
		t.Fatal(err)
	}
	b, w := ReadDocker(root)
	if len(w) != 0 || len(b) != 1 || b[0].ContainerName != "cache" || b[0].HostPort != 6379 {
		t.Errorf("привязки: %+v %v", b, w)
	}
	// Относительный data-root игнорируется — используется путь по умолчанию.
	writeFiles(t, root, map[string]string{"etc/docker/daemon.json": `{"data-root": "srv/docker"}`})
	if got := dockerRoot(root); got != filepath.Join(root, defaultDockerRoot) {
		t.Errorf("относительный data-root: %s", got)
	}
}

const ufwRules = `*filter
### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 80,443,8000:8100 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in
### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=6462
### tuple ### deny tcp 9000 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 9000 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow udp 53 192.0.2.10 any 0.0.0.0/0 in_eth0
### tuple ### allow any 7000 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### route:allow tcp 6000 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp
not a tuple
`

func TestUFW(t *testing.T) {
	root := t.TempDir()
	if u := ReadUFW(root); u.Info.UFW != "absent" || u.PortState("tcp", 22, Fam4) != "" {
		t.Errorf("без ufw: %+v", u.Info)
	}
	writeFiles(t, root, map[string]string{
		"etc/ufw/ufw.conf":   "# комментарий\nENABLED=no\nLOGLEVEL=low\n",
		"etc/ufw/user.rules": ufwRules,
	})
	if u := ReadUFW(root); u.Info.UFW != "inactive" || u.PortState("tcp", 6379, Fam4) != "" {
		t.Errorf("выключенный ufw: %+v", u.Info)
	}
	writeFiles(t, root, map[string]string{"etc/ufw/ufw.conf": "ENABLED='yes'\n"})
	u := ReadUFW(root)
	if u.Info.UFW != "active" || u.Info.DefaultInput != "DROP" || u.Info.Rules != 7 {
		t.Fatalf("включённый ufw: %+v", u.Info)
	}
	for _, c := range []struct {
		proto string
		port  int
		want  string
	}{
		{"tcp", 22, model.FwOpen},       // limit тоже открывает
		{"tcp", 443, model.FwOpen},      // список портов
		{"tcp", 8050, model.FwOpen},     // диапазон
		{"tcp", 8101, model.FwFiltered}, // за диапазоном
		{"udp", 80, model.FwFiltered},   // другой протокол
		{"tcp", 5432, model.FwFiltered}, // только из 10.0.0.0/8 — для интернета закрыт
		{"tcp", 9000, model.FwFiltered}, // deny раньше allow: первое правило решает
		{"udp", 53, model.FwOpen},       // правило с конкретным dst и интерфейсом
		{"tcp", 7000, model.FwFiltered}, // исходящее правило не открывает входящие
		{"tcp", 6000, model.FwFiltered}, // route-правило не про сервер
		{"tcp", 6379, model.FwFiltered},
	} {
		if got := u.PortState(c.proto, c.port, Fam4); got != c.want {
			t.Errorf("%d/%s: %q, ожидалось %q", c.port, c.proto, got, c.want)
		}
	}
	// Политика ACCEPT: ufw ничего не закрывает — состояние неизвестно.
	writeFiles(t, root, map[string]string{"etc/default/ufw": `DEFAULT_INPUT_POLICY="ACCEPT"` + "\n"})
	if u := ReadUFW(root); u.Info.DefaultInput != "ACCEPT" || u.PortState("tcp", 6379, Fam4) != "" {
		t.Errorf("политика ACCEPT: %+v %q", u.Info, u.PortState("tcp", 6379, Fam4))
	}
}

// TestUFWFamilies: правила IPv4 и IPv6 раздельны; правило с журналом
// (allow_log) открывает порт так же, как allow.
func TestUFWFamilies(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"etc/ufw/ufw.conf": "ENABLED=yes\n",
		// IPv4: 5432 запрещён раньше разрешения; 6379 разрешён с журналом.
		"etc/ufw/user.rules": "### tuple ### deny tcp 5432 0.0.0.0/0 any 0.0.0.0/0 in\n" +
			"### tuple ### allow tcp 5432 0.0.0.0/0 any 0.0.0.0/0 in\n" +
			"### tuple ### allow_log tcp 6379 0.0.0.0/0 any 0.0.0.0/0 in\n" +
			"### tuple ### deny_log-all tcp 9000 0.0.0.0/0 any 0.0.0.0/0 in\n",
		// IPv6: 5432 только разрешён.
		"etc/ufw/user6.rules": "### tuple ### allow tcp 5432 ::/0 any ::/0 in\n",
	})
	u := ReadUFW(root)
	if u.Info.Rules != 5 {
		t.Errorf("правил %d", u.Info.Rules)
	}
	for _, c := range []struct {
		port, fam int
		want      string
	}{
		{5432, Fam4, model.FwFiltered},
		{5432, Fam6, model.FwOpen},
		{5432, FamBoth, model.FwOpen}, // [::] принимает и IPv6, где порт открыт
		{6379, Fam4, model.FwOpen},
		{6379, Fam6, model.FwFiltered},
		{9000, Fam4, model.FwFiltered},
	} {
		if got := u.PortState("tcp", c.port, c.fam); got != c.want {
			t.Errorf("%d fam %d: %q, ожидалось %q", c.port, c.fam, got, c.want)
		}
	}
	for addr, want := range map[string]int{"0.0.0.0": Fam4, "::": FamBoth, "::ffff:192.0.2.1": Fam4, "2001:db8::1": Fam6} {
		proto := "tcp6"
		if !strings.Contains(addr, ":") {
			proto = "tcp"
		}
		if got := family(proto, addr); got != want {
			t.Errorf("family(%s, %s) = %d", proto, addr, got)
		}
	}
}

// TestDockerSamePortDifferentIPs: два контейнера публикуют один порт на
// разных адресах — docker-proxy получает имя своего контейнера.
func TestDockerSamePortDifferentIPs(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"var/lib/docker/containers/" + cid1 + "/config.v2.json": `{"ID":"` + cid1 + `","Name":"/local","Config":{"Image":"postgres:16"},"State":{"Running":true},` +
			`"NetworkSettings":{"Ports":{"8888/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}}}`,
		"var/lib/docker/containers/" + cid2 + "/config.v2.json": `{"ID":"` + cid2 + `","Name":"/lab","Config":{"Image":"jupyter/base-notebook"},"State":{"Running":true},` +
			`"NetworkSettings":{"Ports":{"8888/tcp":[{"HostIp":"192.0.2.10","HostPort":"8080"}]}}}`,
	})
	proxy := proc(20, "docker-proxy", "/usr/bin/docker-proxy", "docker-proxy", "-proto", "tcp", "-host-ip", "192.0.2.10", "-host-port", "8080", "-container-port", "8888")
	rep := Build(Input{Procs: []*model.Process{proxy}, Sockets: []model.Socket{sock(proxy, "tcp", "192.0.2.10", 8080, 1)}, HostRoot: root})
	e := entry(t, rep, "192.0.2.10", 8080)
	if e.Container != "lab" || e.Service == nil || e.Service.ID != "jupyter" || e.Risk != model.RiskCritical {
		t.Errorf("docker-proxy: %+v %+v", e, e.Service)
	}
	// Привязка 127.0.0.1:8080 без своего docker-proxy видна отдельно.
	if e := entry(t, rep, "127.0.0.1", 8080); e.Scope != model.ScopeLoopback || e.Container != "local" {
		t.Errorf("loopback-привязка: %+v", e)
	}
}

func TestPortIn(t *testing.T) {
	for _, c := range []struct {
		spec string
		port int
		want bool
	}{
		{"any", 1, true}, {"22", 22, true}, {"22", 23, false}, {"80,443", 443, true}, {"1000:2000", 1000, true},
		{"1000:2000", 2000, true}, {"1000:2000", 2001, false}, {"80,1000:2000", 1500, true}, {"", 0, false},
		{":", 0, false}, {"a:b", 1, false}, {"2000:1000", 1500, false},
	} {
		if got := portIn(c.spec, c.port); got != c.want {
			t.Errorf("portIn(%q, %d) = %v", c.spec, c.port, got)
		}
	}
}

// --- Построение отчёта ---

func proc(pid int, name, exe string, args ...string) *model.Process {
	return &model.Process{Key: name + "-key", PID: pid, Name: name, Exe: exe, Args: args, Cmdline: strings.Join(args, " "), User: "root",
		Namespaces: map[string]string{"net": "net:[1]"}}
}

func sock(p *model.Process, proto, addr string, port int, inode uint64) model.Socket {
	s := model.Socket{Proto: proto, LocalAddr: addr, LocalPort: port, State: "LISTEN", Inode: inode, NetNS: "net:[1]"}
	if strings.HasPrefix(proto, "udp") {
		s.State = "UNCONN"
	}
	if p != nil {
		s.PID, s.ProcKey, s.ProcName, s.User = p.PID, p.Key, p.Name, p.User
		s.NetNS = p.Namespaces["net"]
	}
	return s
}

func entry(t *testing.T, rep *model.ExposureReport, addr string, port int) model.Exposure {
	t.Helper()
	for _, e := range rep.Entries {
		if e.Addr == addr && e.Port == port {
			return e
		}
	}
	t.Fatalf("нет записи %s:%d в %+v", addr, port, rep.Entries)
	return model.Exposure{}
}

func TestBuild(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"etc/ufw/ufw.conf":   "ENABLED=yes\n",
		"etc/ufw/user.rules": "### tuple ### allow tcp 22,8443 0.0.0.0/0 any 0.0.0.0/0 in\n",
		"var/lib/docker/containers/" + cid1 + "/config.v2.json": `{"ID":"` + cid1 + `","Name":"/cache","Config":{"Image":"redis:7"},"State":{"Running":true},` +
			`"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"16379"},{"HostIp":"::","HostPort":"16379"}]}}}`,
		"var/lib/docker/containers/" + cid2 + "/config.v2.json": `{"ID":"` + cid2 + `","Name":"/db","Config":{"Image":"nginx:1.27"},"State":{"Running":true},` +
			`"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}],"8443/tcp":[{"HostIp":"","HostPort":"8443"}]}}}`,
	})
	initP := proc(1, "systemd", "/usr/lib/systemd/systemd")
	redis := proc(10, "redis-server", "/usr/bin/redis-server", "/usr/bin/redis-server", "*:6379")
	mongo := proc(11, "mongod", "/usr/bin/mongod")
	pg := proc(12, "postgres", "/usr/lib/postgresql/16/bin/postgres")
	proxy := proc(13, "docker-proxy", "/usr/bin/docker-proxy", "/usr/bin/docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0", "-host-port", "16379",
		"-container-ip", "172.17.0.2", "-container-port", "6379")
	inCont := proc(14, "redis-server", "/usr/local/bin/redis-server")
	inCont.Key = "redis-in-container"
	inCont.Namespaces = map[string]string{"net": "net:[2]"}
	sshd := proc(15, "sshd", "/usr/sbin/sshd")
	procs := []*model.Process{initP, redis, mongo, pg, proxy, inCont, sshd}
	sockets := []model.Socket{
		sock(redis, "tcp", "0.0.0.0", 6379, 100),
		sock(redis, "tcp6", "::", 6379, 101),
		sock(mongo, "tcp", "192.0.2.10", 27017, 102),
		sock(pg, "tcp", "127.0.0.1", 5432, 103),
		sock(proxy, "tcp", "0.0.0.0", 16379, 104),
		sock(inCont, "tcp", "0.0.0.0", 6379, 105),
		sock(sshd, "tcp", "0.0.0.0", 22, 106),
		// Соединение и UDP-клиент не слушают.
		{Proto: "tcp", LocalAddr: "192.0.2.10", LocalPort: 22, RemoteAddr: "198.51.100.1", RemotePort: 50000, State: "ESTABLISHED", Inode: 107, NetNS: "net:[1]"},
		{Proto: "udp", LocalAddr: "192.0.2.10", LocalPort: 40000, RemoteAddr: "8.8.8.8", RemotePort: 53, State: "ESTABLISHED", Inode: 108, NetNS: "net:[1]"},
		// NFS ядра — владельца нет.
		{Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 2049, State: "LISTEN", NetNS: "net:[1]"},
	}
	allowed := func(p *model.Process, id string) bool { return p.Name == "mongod" && id == "exposed_database" }
	rep := Build(Input{Procs: procs, Sockets: sockets, HostRoot: root, Allowed: allowed,
		Addrs: []model.IfaceAddr{{Addr: "127.0.0.1"}, {Addr: "192.0.2.10"}, {Addr: "10.0.0.5"}}})

	if rep.Firewall.UFW != "active" {
		t.Errorf("ufw: %+v", rep.Firewall)
	}
	if len(rep.Addrs) != 3 || rep.Addrs[1].Scope != model.ScopePublic || rep.Addrs[2].Scope != model.ScopePrivate {
		t.Errorf("адреса: %+v", rep.Addrs)
	}
	// 7 слушающих сокетов + NFS + привязки без своего docker-proxy:
	// [::]:16379 (proxy есть только на 0.0.0.0), 8443 и 127.0.0.1:5432
	// контейнера db. Соединения не входят.
	if len(rep.Entries) != 11 {
		for _, e := range rep.Entries {
			t.Logf("%s %s:%d", e.Proto, e.Addr, e.Port)
		}
		t.Fatalf("записей %d", len(rep.Entries))
	}

	// Redis на всех интерфейсах, ufw порт не открывает: уровень снижен до LOW.
	e := entry(t, rep, "0.0.0.0", 6379)
	if e.Scope != model.ScopePublic || !e.AllInterfaces || e.Service == nil || e.Service.ID != "redis" || e.Firewall != model.FwFiltered ||
		e.Risk != model.RiskLow || e.FindingID != "exposed_database" || e.PID != 10 {
		t.Errorf("redis: %+v", e)
	}
	if !strings.Contains(e.Evidence[1].String(), "192.0.2.10") || strings.Contains(e.Evidence[1].String(), "10.0.0.5") {
		t.Errorf("пояснение про все интерфейсы: %s", e.Evidence[1])
	}
	// MongoDB на публичном адресе, порт не открыт ufw, подавлен allowlist.
	if e := entry(t, rep, "192.0.2.10", 27017); e.AllInterfaces || e.Risk != model.RiskLow || !e.Suppressed {
		t.Errorf("mongo: %+v", e)
	}
	if e := entry(t, rep, "127.0.0.1", 5432); e.Scope != model.ScopeLoopback || e.Risk != model.RiskInfo || e.FindingID != "" || e.Firewall != "" {
		t.Errorf("postgres на loopback: %+v", e)
	}
	// Redis в контейнере слушает 0.0.0.0, но в своём пространстве имён.
	if e := entry(t, rep, "0.0.0.0", 6379); e.PID == 14 {
		t.Error("перепутаны записи")
	}
	for _, e := range rep.Entries {
		if e.PID == 14 && (e.Scope != model.ScopeNetNS || e.Risk != model.RiskInfo || e.AllInterfaces) {
			t.Errorf("redis в контейнере: %+v", e)
		}
	}
	// docker-proxy: сервис узнан по образу и порту контейнера, ufw обойдён.
	e = entry(t, rep, "0.0.0.0", 16379)
	if e.Docker == nil || e.Docker.ContainerName != "cache" || e.Docker.Image != "redis:7" || e.Service == nil || e.Service.Match != "port+image" ||
		e.Firewall != model.FwBypassed || e.Risk != model.RiskCritical || e.Container != "cache" {
		t.Errorf("docker-proxy: %+v %+v", e, e.Docker)
	}
	// Порт контейнера db без docker-proxy; ufw его разрешает — обхода нет.
	e = entry(t, rep, "0.0.0.0", 8443)
	if e.Docker == nil || e.PID != 0 || e.Firewall != model.FwOpen || e.Service != nil || e.Risk != model.RiskInfo {
		t.Errorf("порт контейнера без proxy: %+v", e)
	}
	// [::]:16379 из config.v2.json: docker-proxy слушает только 0.0.0.0,
	// IPv6 заворачивают правила Docker — запись без процесса.
	if e := entry(t, rep, "::", 16379); e.PID != 0 || e.Docker == nil || e.Proto != "tcp6" || e.Risk != model.RiskCritical || e.Container != "cache" {
		t.Errorf("[::]:16379: %+v", e)
	}
	// NFS ядра: уверенно по порту, MEDIUM снижен ufw до LOW.
	if e := entry(t, rep, "0.0.0.0", 2049); e.Service == nil || e.Service.ID != "nfs" || e.Risk != model.RiskLow {
		t.Errorf("nfs: %+v", e)
	}
	// SSH: публичный, сервис не из таблицы, ufw открыт.
	if e := entry(t, rep, "0.0.0.0", 22); e.Risk != model.RiskInfo || e.Firewall != model.FwOpen {
		t.Errorf("ssh: %+v", e)
	}
	// Сортировка: первым — самый опасный.
	if rep.Entries[0].Port != 16379 {
		t.Errorf("первая запись: %+v", rep.Entries[0])
	}

	pub, danger := Stats(rep)
	// Публичные порты (0.0.0.0 и :: одного порта — один): 6379, 27017,
	// 16379, 8443, 2049, 22 = 6; опасные без подавленного mongo: 6379,
	// 16379, 2049 = 3.
	if pub != 6 || danger != 3 {
		t.Errorf("Stats = %d, %d", pub, danger)
	}

	sys := SystemFindings(rep)
	got := map[string]model.SystemFinding{}
	for _, f := range sys {
		got[f.ID+"|"+f.Path] = f
	}
	if len(sys) != 5 {
		t.Errorf("системные находки: %+v", sys)
	}
	// 0.0.0.0 и :: одного Redis — одна находка с обоими адресами.
	f := got["exposed_database|6379/tcp"]
	if f.Risk != model.RiskLow || f.Category != model.CatExposure || !strings.Contains(f.Title.String(), "закрыт только ufw") {
		t.Errorf("redis: %+v", f)
	}
	ev := i18n.Join("\n", f.Evidence...).String()
	if !strings.Contains(ev, "0.0.0.0:6379") || !strings.Contains(ev, "[::]:6379") {
		t.Errorf("факты redis: %s", ev)
	}
	if f := got["exposed_database|16379/tcp"]; f.Risk != model.RiskCritical || !strings.Contains(f.Title.String(), "Redis доступен из интернета") {
		t.Errorf("redis в docker: %+v", f)
	}
	if f := got["fw_docker_bypass|16379/tcp"]; f.Risk != model.RiskHigh || !strings.Contains(f.Recommendation.String(), "127.0.0.1:16379:6379") {
		t.Errorf("обход ufw: %+v", f)
	}
	if _, ok := got["fw_docker_bypass|8443/tcp"]; ok {
		t.Error("обход ufw для порта, который ufw и так открывает")
	}
	// Подавленная находка видна, но не влияет на сводку.
	if f := got["exposed_database|27017/tcp"]; !f.Suppressed || f.Risk != model.RiskInfo {
		t.Errorf("подавленная mongo: %+v", f)
	}
	if f := got["exposed_file_sharing|2049/tcp"]; f.Risk != model.RiskLow {
		t.Errorf("nfs: %+v", f)
	}
}

// TestBuildNoUFW: без ufw обхода нет, уровни не снижаются, а сокет на
// всех интерфейсах без публичных адресов поясняется через NAT.
func TestBuildNoUFW(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"var/lib/docker/containers/" + cid1 + "/config.v2.json": `{"ID":"` + cid1 + `","Name":"/m","Config":{"Image":"mongo"},"State":{"Running":true},` +
			`"NetworkSettings":{"Ports":{"27017/tcp":[{"HostIp":"","HostPort":"27017"}]}}}`,
	})
	redis := proc(10, "redis-server", "/usr/bin/redis-server")
	rep := Build(Input{Procs: []*model.Process{redis}, Sockets: []model.Socket{sock(redis, "tcp", "0.0.0.0", 6379, 1)}, HostRoot: root,
		Addrs: []model.IfaceAddr{{Addr: "10.0.0.5"}}})
	e := entry(t, rep, "0.0.0.0", 6379)
	if e.Risk != model.RiskCritical || e.Firewall != "" || !strings.Contains(e.Evidence[1].String(), "NAT") {
		t.Errorf("redis без ufw: %+v", e)
	}
	if e := entry(t, rep, "0.0.0.0", 27017); e.Risk != model.RiskCritical || e.Firewall != "" {
		t.Errorf("mongo без ufw: %+v", e)
	}
	for _, f := range SystemFindings(rep) {
		if f.ID == "fw_docker_bypass" {
			t.Errorf("обход ufw без ufw: %+v", f)
		}
	}
	// Пустой ввод — пустой, но не nil отчёт.
	if r := Build(Input{HostRoot: root + "/нет"}); r.Entries == nil || r.Bindings == nil || len(r.Entries) != 0 {
		t.Errorf("пустой отчёт: %+v", r)
	}
	if SystemFindings(nil) != nil {
		t.Error("SystemFindings(nil)")
	}
}

func TestListening(t *testing.T) {
	for _, c := range []struct {
		s    model.Socket
		want bool
	}{
		{model.Socket{Proto: "tcp", State: "LISTEN", LocalPort: 80}, true},
		{model.Socket{Proto: "tcp6", State: "ESTABLISHED", LocalPort: 80}, false},
		{model.Socket{Proto: "udp", State: "UNCONN", LocalPort: 53}, true},
		{model.Socket{Proto: "udp6", State: "UNCONN", LocalPort: 0}, false},
		{model.Socket{Proto: "udp", State: "ESTABLISHED", LocalPort: 4000, RemotePort: 53}, false},
		{model.Socket{Proto: "unix", State: "LISTEN"}, false},
	} {
		if got := Listening(c.s); got != c.want {
			t.Errorf("%+v: %v", c.s, got)
		}
	}
}

func TestEndpoint(t *testing.T) {
	if Endpoint("::", 22) != "[::]:22" || Endpoint("0.0.0.0", 22) != "0.0.0.0:22" {
		t.Error(Endpoint("::", 22), Endpoint("0.0.0.0", 22))
	}
}
