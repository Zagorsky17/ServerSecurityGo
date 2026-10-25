package exposure

import (
	"path/filepath"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Классы сервисов. Каждому классу соответствует признак exposed_<класс>.
const (
	ClassDatabase     = "database"      // базы данных, хранилища, брокеры
	ClassDockerAPI    = "docker_api"    // API управления контейнерами: Docker, kubelet
	ClassAdminPanel   = "admin_panel"   // панели администрирования и выполнения кода
	ClassRemoteAccess = "remote_access" // удалённый рабочий стол и терминал
	ClassFileSharing  = "file_sharing"  // общий доступ к файлам
	ClassInfoService  = "info_service"  // сервисы, раскрывающие сведения о системе
)

// FindingID — ID признака для класса сервиса.
func FindingID(class string) string { return "exposed_" + class }

// classKeys — ключи каталога для признака каждого класса: заголовок
// (аргумент {0} — имя сервиса) и общая рекомендация. Литералы, а не
// склейка строк: keys_test сверяет ключи из кода с каталогом.
var classKeys = map[string][2]string{
	ClassDatabase:     {"rule.exposed_database.title", "rule.exposed_database.rec"},
	ClassDockerAPI:    {"rule.exposed_docker_api.title", "rule.exposed_docker_api.rec"},
	ClassAdminPanel:   {"rule.exposed_admin_panel.title", "rule.exposed_admin_panel.rec"},
	ClassRemoteAccess: {"rule.exposed_remote_access.title", "rule.exposed_remote_access.rec"},
	ClassFileSharing:  {"rule.exposed_file_sharing.title", "rule.exposed_file_sharing.rec"},
	ClassInfoService:  {"rule.exposed_info_service.title", "rule.exposed_info_service.rec"},
}

// Title — заголовок признака доступности сервиса. Если порт закрыт
// ufw, «доступен из интернета» было бы неправдой — заголовок другой.
func Title(e *model.Exposure) i18n.Msg {
	if e.Firewall == model.FwFiltered {
		return i18n.T("rule.exposed.title_filtered", e.Service.Name)
	}
	return i18n.T(classKeys[e.Service.Class][0], e.Service.Name)
}

// portRange — диапазон портов одного протокола.
type portRange struct {
	proto  string // tcp или udp
	lo, hi int
}

// service — строка встроенной таблицы опасных сервисов.
type service struct {
	id, name, class string
	ports           []portRange
	// procs — имена процесса (comm или имя исполняемого файла), шаблоны
	// filepath.Match. Сравниваются без учёта регистра.
	procs []string
	// hints — подстроки пути exe или командной строки (для программ на
	// Java/Erlang/Python, у которых имя процесса — java, beam.smp или
	// python3). Только характерные для самой программы строки (класс
	// запуска, модуль): слово из пути каталога узнало бы постороннее
	// приложение, и anyPort дал бы ему уровень сервиса.
	hints []string
	// images — имена образов Docker без реестра и тега.
	images []string
	// anyPort — совпадение по процессу или образу узнаёт сервис и на
	// нестандартном порту. Выключено, если программа слушает и другие,
	// неопасные порты (dockerd — порты Swarm, kubelet — healthz).
	anyPort bool
	// sev — опасность при доступе из интернета (таблица из плана 2.2).
	sev model.Risk
	// rec — ключ каталога с конкретным исправлением для этого сервиса.
	rec string
}

func tcp(ports ...int) []portRange {
	out := make([]portRange, len(ports))
	for i, p := range ports {
		out[i] = portRange{"tcp", p, p}
	}
	return out
}

// services — встроенная таблица. Порядок важен только при равных
// совпадениях: побеждает первая строка.
var services = []service{
	{id: "redis", name: "Redis", class: ClassDatabase, ports: tcp(6379, 26379), procs: []string{"redis-server", "redis-sentinel", "valkey-server", "keydb-server"},
		images: []string{"redis", "valkey", "keydb", "redis-stack-server"}, anyPort: true, rec: "rec.exp_redis", sev: model.RiskCritical},
	{id: "docker_api", name: "Docker API", class: ClassDockerAPI, ports: tcp(2375), procs: []string{"dockerd"}, rec: "rec.exp_docker_api", sev: model.RiskCritical},
	{id: "docker_api_tls", name: "Docker API (TLS)", class: ClassDockerAPI, ports: tcp(2376), procs: []string{"dockerd"}, rec: "rec.exp_docker_api_tls", sev: model.RiskHigh},
	{id: "mongodb", name: "MongoDB", class: ClassDatabase, ports: tcp(27017, 27018, 27019), procs: []string{"mongod", "mongos"},
		images: []string{"mongo", "mongodb-community-server"}, anyPort: true, rec: "rec.exp_mongodb", sev: model.RiskCritical},
	{id: "elasticsearch", name: "Elasticsearch/OpenSearch", class: ClassDatabase, ports: tcp(9200, 9300),
		hints:  []string{"org.elasticsearch.bootstrap", "org.opensearch.bootstrap"},
		images: []string{"elasticsearch", "opensearch"}, anyPort: true, rec: "rec.exp_elasticsearch", sev: model.RiskCritical},
	{id: "etcd", name: "etcd", class: ClassDatabase, ports: tcp(2379, 2380), procs: []string{"etcd"}, images: []string{"etcd"}, rec: "rec.exp_etcd", sev: model.RiskCritical},
	{id: "kubelet", name: "kubelet", class: ClassDockerAPI, ports: tcp(10250, 10255), procs: []string{"kubelet"}, rec: "rec.exp_kubelet", sev: model.RiskCritical},
	{id: "jupyter", name: "Jupyter", class: ClassAdminPanel, ports: tcp(8888), procs: []string{"jupyter-lab", "jupyter-noteboo*", "jupyter-server"},
		hints: []string{"-m jupyter", "jupyter-lab", "jupyter-notebook", "jupyter-server", "jupyterlab.labapp", "jupyter_server.serverapp", "notebook.notebookapp"}, images: []string{"jupyter", "base-notebook", "minimal-notebook", "scipy-notebook", "datascience-notebook"}, anyPort: true, rec: "rec.exp_jupyter", sev: model.RiskCritical},
	{id: "memcached", name: "memcached", class: ClassDatabase, ports: []portRange{{"tcp", 11211, 11211}, {"udp", 11211, 11211}}, procs: []string{"memcached"},
		images: []string{"memcached"}, anyPort: true, rec: "rec.exp_memcached", sev: model.RiskHigh},
	{id: "postgresql", name: "PostgreSQL", class: ClassDatabase, ports: tcp(5432), procs: []string{"postgres", "postmaster"},
		images: []string{"postgres", "postgis", "timescaledb"}, anyPort: true, rec: "rec.exp_postgresql", sev: model.RiskHigh},
	{id: "mysql", name: "MySQL/MariaDB", class: ClassDatabase, ports: tcp(3306, 33060), procs: []string{"mysqld", "mariadbd"},
		images: []string{"mysql", "mariadb", "percona", "percona-server"}, anyPort: true, rec: "rec.exp_mysql", sev: model.RiskHigh},
	{id: "rabbitmq", name: "RabbitMQ", class: ClassDatabase, ports: tcp(5672), hints: []string{"rabbit"}, images: []string{"rabbitmq"}, rec: "rec.exp_rabbitmq", sev: model.RiskHigh},
	{id: "rabbitmq_mgmt", name: "RabbitMQ management", class: ClassAdminPanel, ports: tcp(15672), hints: []string{"rabbit"}, images: []string{"rabbitmq"}, rec: "rec.exp_rabbitmq_mgmt", sev: model.RiskHigh},
	{id: "couchdb", name: "CouchDB", class: ClassDatabase, ports: tcp(5984), hints: []string{"couchdb"}, images: []string{"couchdb"}, rec: "rec.exp_couchdb", sev: model.RiskHigh},
	{id: "smb", name: "SMB/NetBIOS", class: ClassFileSharing, ports: []portRange{{"tcp", 139, 139}, {"tcp", 445, 445}, {"udp", 137, 138}},
		procs: []string{"smbd", "nmbd", "samba"}, images: []string{"samba"}, anyPort: true, rec: "rec.exp_smb", sev: model.RiskHigh},
	{id: "rdp", name: "RDP", class: ClassRemoteAccess, ports: tcp(3389), procs: []string{"xrdp"}, anyPort: true, rec: "rec.exp_rdp", sev: model.RiskHigh},
	{id: "vnc", name: "VNC", class: ClassRemoteAccess, ports: []portRange{{"tcp", 5900, 5910}}, procs: []string{"Xvnc", "x11vnc", "Xtightvnc", "vncserver", "Xtigervnc"},
		anyPort: true, rec: "rec.exp_vnc", sev: model.RiskHigh},
	{id: "telnet", name: "Telnet", class: ClassRemoteAccess, ports: tcp(23), procs: []string{"telnetd", "in.telnetd"}, anyPort: true, rec: "rec.exp_telnet", sev: model.RiskHigh},
	{id: "ftp", name: "FTP", class: ClassFileSharing, ports: tcp(21), procs: []string{"vsftpd", "proftpd", "pure-ftpd"}, anyPort: true, rec: "rec.exp_ftp", sev: model.RiskHigh},
	{id: "rpcbind", name: "rpcbind", class: ClassFileSharing, ports: []portRange{{"tcp", 111, 111}, {"udp", 111, 111}}, procs: []string{"rpcbind", "portmap"},
		anyPort: true, rec: "rec.exp_rpcbind", sev: model.RiskMedium},
	{id: "nfs", name: "NFS", class: ClassFileSharing, ports: []portRange{{"tcp", 2049, 2049}, {"udp", 2049, 2049}}, rec: "rec.exp_nfs", sev: model.RiskMedium},
	{id: "snmp", name: "SNMP", class: ClassInfoService, ports: []portRange{{"udp", 161, 161}}, procs: []string{"snmpd"}, rec: "rec.exp_snmp", sev: model.RiskMedium},
	{id: "prometheus_exporter", name: "Prometheus exporter", class: ClassInfoService, ports: tcp(9100), procs: []string{"node_exporter", "*_exporter"},
		images: []string{"node-exporter", "*-exporter", "*_exporter"}, anyPort: true, rec: "rec.exp_prometheus_exporter", sev: model.RiskLow},
}

// target — что известно о слушающем сокете для распознавания.
type target struct {
	proto string // tcp или udp (без 6)
	port  int
	names []string // comm и имя исполняемого файла
	text  string   // exe + командная строка, в нижнем регистре
	image string   // имя образа контейнера без реестра и тега
}

func (s *service) hasPort(proto string, port int) bool {
	for _, r := range s.ports {
		if r.proto == proto && port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

func (s *service) procMatch(t target) bool {
	for _, n := range t.names {
		for _, pat := range s.procs {
			if globFold(pat, n) {
				return true
			}
		}
	}
	for _, h := range s.hints {
		if t.text != "" && strings.Contains(t.text, h) {
			return true
		}
	}
	return false
}

func (s *service) imageMatch(t target) bool {
	if t.image == "" {
		return false
	}
	for _, pat := range s.images {
		if globFold(pat, t.image) {
			return true
		}
	}
	return false
}

func globFold(pattern, s string) bool {
	if strings.EqualFold(pattern, s) {
		return true
	}
	ok, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(s))
	return err == nil && ok
}

// recognize ищет сервис в таблице. Совпадение по процессу или образу
// надёжнее совпадения только по порту, поэтому выбирается лучшее.
// confident = false — сервис узнан только по номеру порта, и на этом
// порту может работать другая программа; тогда уровень снижается.
// Исключение — сервисы ядра без процесса (NFS): у их сокетов владельца
// нет, и порт — единственный и достаточный признак.
func recognize(t target) (svc *service, match string, confident bool) {
	bestRank := 0
	for i := range services {
		s := &services[i]
		port := s.hasPort(t.proto, t.port)
		proc, img := s.procMatch(t), s.imageMatch(t)
		rank, m := 0, ""
		switch {
		case port && proc:
			rank, m = 3, "port+process"
		case port && img:
			rank, m = 3, "port+image"
		case proc && s.anyPort:
			rank, m = 2, "process"
		case img && s.anyPort:
			rank, m = 2, "image"
		case port:
			rank, m = 1, "port"
		}
		if rank > bestRank {
			svc, bestRank, match = s, rank, m
		}
	}
	if svc == nil {
		return nil, "", false
	}
	kernelOnly := len(svc.procs) == 0 && len(svc.hints) == 0 && len(t.names) == 0 && t.image == ""
	return svc, match, bestRank > 1 || kernelOnly
}

// ImageBase — имя образа без реестра, тега и дайджеста:
// docker.io/library/redis:7-alpine → redis, ghcr.io/org/app@sha256:… → app.
func ImageBase(image string) string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, '/'); i >= 0 {
		image = image[i+1:]
	}
	if i := strings.IndexByte(image, ':'); i >= 0 {
		image = image[:i]
	}
	return strings.ToLower(image)
}

// lower снижает уровень на одну ступень, но не ниже LOW.
func lower(r model.Risk) model.Risk {
	if r > model.RiskLow {
		return r - 1
	}
	return model.RiskLow
}
