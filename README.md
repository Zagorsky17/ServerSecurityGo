# ServerSecurityGo

**English** | [Русский](README.ru.md) | [简体中文](README.zh-CN.md)

[![CI](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml/badge.svg)](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Zagorsky17/ServerSecurityGo)](https://github.com/Zagorsky17/ServerSecurityGo/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Process monitoring and analysis for Linux servers (Ubuntu, Debian). It looks for suspicious processes, signs of malware and unauthorized access. The scanner reads `/proc` and scores every process on a combination of verifiable indicators. It explains each score, keeps a history of changes and shows everything in a web dashboard and a terminal UI. The interface is available in English and Russian (see [Language](#language)).

**The application only observes.** It never kills processes, deletes files or blocks connections. All decisions stay with the administrator.

- A lazygit-style terminal UI: on the server, just type `serversecuritygo`. The web dashboard over an SSH tunnel is optional.
- A single static binary with no dependencies: only the Go standard library, with both interfaces embedded in the binary.
- By default the dashboard is reachable only at `127.0.0.1:8090`.
- Risk levels are `INFO`, `LOW`, `MEDIUM`, `HIGH` and `CRITICAL`. Every level comes with an explanation: which rules fired, with what weight and on which facts.

## Contents

- [Installation from GitHub](#installation-from-github)
- [Terminal UI](#terminal-ui)
- [Web dashboard (optional)](#web-dashboard-optional)
- [Features](#features)
  - [Open ports](#open-ports)
  - [Security settings](#security-settings)
  - [fail2ban](#fail2ban)
- [How risk is scored](#how-risk-is-scored)
- [Examples of detected anomalies](#examples-of-detected-anomalies)
- [Detection limitations](#detection-limitations)
- [Where it has been tested](#where-it-has-been-tested)
- [Configuration](#configuration)
- [Language](#language)
- [Remote access](#remote-access)
- [Updating, rollback, removal, logs](#updating-rollback-removal-logs)
- [Console mode and demo](#console-mode-and-demo)
- [Building and testing](#building-and-testing)
- [Project layout](#project-layout)
- [Security](#security)
- [Contributing](#contributing)

## Installation from GitHub

On the server, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | bash
```

To install a specific version:

```bash
curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | SSG_VERSION=v0.1.1 bash
```

What the installer does:

1. Clones the repository into `/opt/serversecuritygo`. The repository is public, so no deploy key is needed.
2. Builds the binary from source if Go 1.24+ is installed. Otherwise it downloads a prebuilt binary from [GitHub Releases](https://github.com/Zagorsky17/ServerSecurityGo/releases) and verifies its SHA256. Go is not required on the server.
3. Creates `/opt/serversecuritygo/.env` from `.env.example` with permissions `600`.
4. Installs `serversecuritygo.service`, enables and starts it, then checks `/healthz`.
5. Creates the link `/usr/local/bin/serversecuritygo`, so the interface opens with a single command.

If `git` or `curl` is missing, the installer installs it with `apt-get`. It makes no other changes to the system and does not touch other directories in `/opt`.

Where things live:

| What | Where |
|---|---|
| Code and binary | `/opt/serversecuritygo`, `/opt/serversecuritygo/bin/serversecuritygo` |
| Settings | `/opt/serversecuritygo/.env` (mode 600, never committed) |
| Allowlist (optional) | `/opt/serversecuritygo/allowlist.json` |
| History | `/var/lib/serversecuritygo` (mode 700): `state.json`, `events.jsonl` |
| Backups | `/var/backups/serversecuritygo` (mode 700) |
| Logs | journald: `journalctl -u serversecuritygo` |
| systemd unit | `/etc/systemd/system/serversecuritygo.service` |
| Launch command | `/usr/local/bin/serversecuritygo` (link to the binary) |
| Terminal UI socket | `/run/serversecuritygo/api.sock` (mode 600, root only; created when the service starts) |

Manual installation without the script:

```bash
git clone https://github.com/Zagorsky17/ServerSecurityGo /opt/serversecuritygo
cd /opt/serversecuritygo
make build          # or download a release binary into bin/serversecuritygo
install -m 600 .env.example .env
install -m 644 deploy/serversecuritygo.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now serversecuritygo
```

## Terminal UI

This is the main way to work. Connect to the server over SSH and type:

```bash
serversecuritygo
```

```
╭ [1] Сводка ──────────────────────────────╮╭ PID 3202 · bash ─────────────────────────────────────╮
│ web-01 · Ubuntu 24.04 LTS · 6.8.0-147    ││  CRITICAL   102 балл. · www-data · bash              │
│ Скан 21:37:58 (56 мс) · каждые 30s · …   ││                                                      │
│ CRIT 4  HIGH 1  MED 1  LOW 3             ││ Оценка риска                                         │
╰──────────────────────────────────────────╯│   Итог CRITICAL: 102 балл(ов), признаков — 4, …      │
╭ [2] Подозрительные (9) ──────────────────╮│ Признаки                                             │
│CRITICAL  3202 www-data bash     /usr/bin…││   ● Ввод/вывод оболочки подключён к сетевому сокету  │
│CRITICAL  3101 root     kworkerds /dev/sh…││       · /proc/3202/fd/0 → socket:[2002] tcp … 4444   │
╰──────────────────────────────────────────╯│   ● Командная строка содержит конструкцию reverse …  │
╭ [3] Процессы (47) · риск ────────────────╮│ Командная строка  (y — копировать)                   │
╭ [4] Сеть (17) ───────────────────────────╮│   bash -i                                            │
╭ [5] Порты (9) ───────────────────────────╮│                                                      │
╭ [6] Настройки (32) ──────────────────────╮│                                                      │
╭ [7] История (25) ────────────────────────╮│ Цепочка запуска                                      │
╭ [8] Система (2) ─────────────────────────╮│   systemd(1) → nginx(720) → nginx(721) → sh(3201) →… │
↑↓ выбор  1-8/Tab панели  Enter подробности  / фильтр  r сканировать  y копировать  ? помощь  q выход
```

On the left are eight panels: summary, suspicious processes, all processes (as a list or a tree), network connections, open ports, security settings, history and system checks. If fail2ban is installed, a ninth panel, fail2ban, appears before history, and the panels after it are renumbered. On the right are the details of the selected item: the risk score with its explanation, indicators with facts, recommendations, the command line, the launch chain, sockets, open files and the process history. `L` switches the interface language between English and Russian.

| Keys | Action |
|---|---|
| `1`…`8` (`9` with fail2ban), `Tab` / `Shift+Tab` | switch panel |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `g` `G` | select a row; scroll in the details |
| `Enter` / `→`, `Esc` / `←` | go to the details and back |
| `/` | filter the panel by name, PID, path, user, indicator or risk level |
| `s`, `t`, `K` | sort processes (risk, CPU, memory, PID, name), tree view, kernel threads |
| `r`, `p` | scan now (on the Settings panel — check settings now), pause auto-refresh |
| `y` | copy the main value of the selected item to your computer's clipboard (OSC 52, works over SSH): the command line of a process, the fix command of an audit check, the IP of a fail2ban ban, the address:port of an open port, the remote IP of a connection |
| `c` | copy menu: everything in the details — IPs, commands, paths, facts, recommendations; `Enter` or `1`…`9` copies an item |
| `Y` | copy the selected item as JSON |
| `v` | plain text mode: the details as plain text without frames, colors or wrapping, for selecting with the mouse; any key returns to the interface |
| `m` | turn the mouse off and on; while it is off, the terminal's own text selection works |
| `+` / `z` | expand the active side to full screen (press again to return) |
| `L` | interface language: English / Russian |
| `?`, `q` | help, quit |

The mouse works too: a click selects a panel and row, and the wheel scrolls. Because the interface takes the mouse, the terminal cannot select text at the same time: press `m` to hand the mouse back to the terminal (or hold `Option` in iTerm2, `Shift` in most Linux terminals and Windows Terminal), or use `v` for plain text.

**Where the data comes from.** If the service is running, the interface connects to it through the Unix socket `/run/serversecuritygo/api.sock`. Only root can access the socket, so no password or tunnel is needed, and the full collected history is visible. If the service is not running, or an older version without the socket is installed, the interface scans processes itself, and the history then lasts only for the session. The source is shown in the Summary panel.

```bash
serversecuritygo tui --local            # always scan on its own
serversecuritygo tui --refresh 2s       # refresh the screen more often
```

To see the processes of all users, run the interface as root. In service mode the service already collects the data.

If copying with `y` or `c` does not work: OSC 52 is supported by iTerm2, kitty, WezTerm, Alacritty, Windows Terminal and modern xterm. In tmux, it needs `set -g set-clipboard on`. macOS Terminal.app does not support OSC 52: use `v` (plain text mode) and select the text with the mouse — a long command is wrapped by the terminal and copied as one line.

## Web dashboard (optional)

The web dashboard shows the same data in a browser. It listens only on `127.0.0.1:8090`. To open it from your own computer, use an SSH tunnel:

```bash
ssh -L 8090:127.0.0.1:8090 root@<server-IP>
# then open http://127.0.0.1:8090 in your browser
```

If you connect with a dedicated key, add `-i ~/.ssh/<key> -o IdentitiesOnly=yes`.

While no password is set, the service lets only root into the dashboard: for every connection to `127.0.0.1` it looks up the socket owner in `/proc/net/tcp`. A tunnel opened as root works, while other users on the server (for example, a compromised `www-data`) get error 403. If you log in over SSH as your own user, add its UID to `SSG_LOCAL_UIDS` (for example, `0,1000`) or set a password.

## Features

**Data collection** reads `/proc` and related sources:

| Data | Source |
|---|---|
| PID, PPID, name, state, threads, start time, CPU (utime+stime) | `/proc/PID/stat` |
| UID/EUID/GID, RSS, PID inside namespaces | `/proc/PID/status` |
| Command line (secrets are masked) | `/proc/PID/cmdline` |
| Executable, deleted flag, permissions, owner | `/proc/PID/exe` (readlink + stat) |
| Working directory | `/proc/PID/cwd` |
| Open files and sockets | `/proc/PID/fd/*` |
| TCP/UDP/Unix sockets for every network namespace | `/proc/PID/net/{tcp,tcp6,udp,udp6,unix}` |
| Namespaces and containers (docker, containerd, kubernetes, podman, lxc) | `/proc/PID/ns/*`, `/proc/PID/cgroup` |
| Presence of `LD_PRELOAD`/`LD_AUDIT` (names only, values are never stored) | `/proc/PID/environ` |
| Users | `/etc/passwd` |
| Server addresses (to tell public ports from private ones) | `/proc/net/fib_trie`, `/proc/net/if_inet6` |
| ufw state and rules | `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user.rules`, `/etc/ufw/user6.rules` |
| SSH settings | `/etc/ssh/sshd_config` with `Include` and `Match`, `/etc/ssh/ssh_host_*_key` permissions |
| Accounts (password hashes are never shown or stored — only the algorithm type) | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/login.defs`, `/etc/environment`, root's `.profile` and `.bashrc` |
| sudo rules | `/etc/sudoers` with `@include`/`@includedir`, aliases and `Defaults` |
| Published Docker ports, container name and image | `docker-proxy` arguments, `<data-root>/containers/*/config.v2.json` (environment variables are not read into memory structures and never shown) |
| Boot time, memory, kernel | `/proc/stat`, `/proc/meminfo`, `/proc/sys/kernel/osrelease` |

System persistence checks cover `/etc/ld.so.preload`, cron (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`), systemd units in `/etc/systemd/system`, `/etc/rc.local`, `/etc/init.d`, `/etc/profile.d`, `.bashrc`, `update-motd.d` and `authorized_keys`.

The **terminal UI** is described [above](#terminal-ui). **Web dashboard** (light and dark themes):

1. **Suspicious** — processes with indicators, sorted by risk. Each row shows the indicators, score, first and last seen time, and a recommendation.
2. **All processes** — search, sorting by any column, filters by PID/PPID, user, name, path and minimum risk level.
3. **Tree** — parent and child relationships, collapsible branches, highlighting of matches.
4. **Network** — sockets with their owning processes, filters by protocol, state and external addresses.
5. **Open ports** — what the server listens on and where it is reachable from; see [Open ports](#open-ports).
6. **Security settings** — the SSH, account and sudo audit; see [Security settings](#security-settings).
7. **History** — process start and exit, changes of exe, cmdline or user, risk increases and decreases, new indicators, new listening ports, system findings, security setting changes.
8. **System** — server details, scanning limitations (privileges, container), persistence checks and dangerous open ports.
9. **Process card** — all collected data, the score explanation, facts behind every indicator, recommendations, the ancestor chain, children, sockets, open files and the process history. You can copy the command line and the card as JSON, and link directly to a card (`#p=<key>`).

The dashboard refreshes automatically every 5 to 60 seconds, or not at all. Auto-refresh pauses while a process card is open.

### Open ports

The most common real cause of a VPS break-in is a service that accidentally listens on `0.0.0.0`: Redis without a password, MongoDB, the Docker API, an admin panel. The **Open ports** tab (panel `5` in the terminal UI, `GET /api/exposure`, a table at the end of `serversecuritygo scan`) lists every listening TCP socket and bound UDP socket:

- **reachability**: *public* (any address outside the ranges below, including `0.0.0.0` and `::` — all interfaces, the server's public addresses are listed next to them), *private network* (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`, link-local), *local only* (`127.0.0.0/8`, `::1`) or *inside a container* (a socket in its own network namespace, reachable from outside only through a published port);
- the owning process, user and container; for Docker — the container name, image and port mapping;
- the **recognized service** from the built-in table: Redis, Docker API, MongoDB, Elasticsearch/OpenSearch, etcd, kubelet, Jupyter, memcached, PostgreSQL, MySQL/MariaDB, RabbitMQ, CouchDB, SMB, RDP, VNC, Telnet, FTP, rpcbind, NFS, SNMP, Prometheus exporters. A service is recognized by port and process name (or container image); a match by port number only lowers the level by one step, because another program may use the port;
- the **ufw** state for the port: *open* (an allow rule from any address), *blocked* (ufw is active and does not allow the port for everyone) or *bypasses ufw*.

The level is the danger of the service being reachable, not a sign of compromise: Redis reachable from the internet is CRITICAL, PostgreSQL is HIGH, a Prometheus exporter is LOW. If ufw blocks the port, the level drops to LOW with a note that only the firewall protects the service. Every dangerous public port becomes a system finding with that level (it appears in the System tab, in the history and in the log) and an indicator of the `exposure` category in the card of the process holding the port. That indicator is not "strong": on its own it raises a legitimate process no higher than LOW.

**Docker bypasses ufw.** Docker inserts its iptables rules before ufw's, so `ufw deny 6379` does not close a port published as `-p 6379:6379`. If ufw is active and a container port is published on all interfaces without a ufw rule allowing it, the dashboard reports `fw_docker_bypass` (HIGH) and suggests publishing the port as `127.0.0.1:PORT:PORT` or restricting it in the `DOCKER-USER` chain. Published ports are read from `docker-proxy` arguments and from the containers' `config.v2.json`, so they are visible with `userland-proxy: false` as well. The Docker API is not used: its socket grants root, and an observer does not need it.

To silence a deliberately open port, add an allowlist rule for the process with the indicator ID (for example, `{"exe": "/usr/lib/postgresql/16/bin/postgres", "rules": ["exposed_database"]}`): the process indicator and the system finding are both shown as suppressed and no longer count. Ports published by Docker without a listening process (`userland-proxy: false`) cannot be suppressed this way.

### Security settings

Most VPS break-ins come not from zero-day exploits but from password logins, a stray `NOPASSWD: ALL` or a forgotten user. The **Security settings** tab (panel `6` in the terminal UI, `GET /api/audit`, the `serversecuritygo audit` command) checks the configuration — the causes of a break-in rather than its traces.

The service runs the audit right at startup and then every `SSG_AUDIT_INTERVAL` (1 hour by default). The **Check now** button (`r` on the panel in the terminal UI) runs it immediately, for example after you have fixed something; a new check does not start while one is running. The tab shows when the last check ran and how many checks passed: "N of M passed" counts only checks with a pass, fail or warning result (tips, n/a and unknown are not counted).

Every check has a result (*pass*, *fail*, *warning*, *tip*, *n/a* — for example, sshd is not installed, *unknown* — no permission to read), its severity, facts with a file and line (`/etc/ssh/sshd_config.d/50-cloud-init.conf:1 PasswordAuthentication yes`), a recommendation and often a ready-made fix command. The application never runs the command: you run it yourself. For SSH changes, first check key login in a separate session.

| Group | Checks |
|---|---|
| SSH | `ssh_root_login`, `ssh_password_auth`, `ssh_empty_passwords`, `ssh_kbd_interactive` (password via PAM even with `PasswordAuthentication no`), `ssh_max_auth_tries`, `ssh_x11_forwarding`, `ssh_tcp_forwarding` (`GatewayPorts`), `ssh_weak_crypto` (CBC, 3DES, RC4, MD5, SHA-1, DSA), `ssh_authkeys_file` (non-standard key file or `AuthorizedKeysCommand`), `ssh_host_keys_perms`, `ssh_config_perms`, tips `ssh_allow_users`, `ssh_banner_version`, `ssh_port` |
| Accounts | `acct_uid0_extra`, `acct_empty_password`, `acct_service_shell`, `acct_weak_hash` (MD5, DES), `acct_new`, `acct_priv_groups` (`sudo`, `admin`, `wheel`, `docker`, `lxd`, `disk`, `adm`, `shadow`), `acct_duplicate_ids`, `acct_passwd_perms`, `acct_home_perms`, `acct_root_path` |
| sudo | `sudo_nopasswd_all` (MEDIUM for the default cloud users `ubuntu`, `debian`, `admin`…), `sudo_no_auth`, `sudo_gtfobins` (`vim`, `less`, `find`, `systemctl` and others that drop to a root shell), `sudo_wildcard`, `sudo_writable_cmd`, `sudo_env_keep` (`LD_PRELOAD`, `PYTHONPATH`, `!env_reset`), `sudo_files_perms`, `sudo_changed` |

The sshd configuration is parsed the way sshd reads it: `Include` is expanded in place, the first value of a key wins, `Match` blocks are shown separately ("password login is allowed for user X"), and missing keys take OpenSSH defaults. The parser for sudoers handles `@include`/`@includedir` (skipping files with a dot in the name, like sudo), aliases, line continuation and `Defaults`.

**Changes.** The service remembers user names and UIDs, privileged group members and SHA-256 checksums of sudoers files in `/var/lib/serversecuritygo/audit-baseline.json` (mode 600, no passwords or file contents). A new user, a new member of a privileged group or a sudoers change makes `acct_new`, `acct_priv_groups` or `sudo_changed` fail for 24 hours, so the next run does not quietly clear the alert. If a file cannot be read during a run, its part of the baseline is kept, so nothing is reported as new afterwards. Every change of a result ("was pass, now fail", "fixed") is recorded in the History tab and in the log. A one-off `serversecuritygo audit` has nothing to compare with, so change checks are n/a there.

### fail2ban

The **fail2ban** tab (a panel in the terminal UI, `GET /api/fail2ban`) appears only when fail2ban is installed: there is `/etc/fail2ban` and `fail2ban-server` (or the dpkg package), or the `fail2ban-server` process is running. Without fail2ban there is no tab, no panel and no empty placeholder; the API answers `{"installed": false}`.

What it shows, for the last `SSG_AUTH_LOG_DAYS` days (14 by default):

- status: running or not, version, enabled jails with `maxretry`, `findtime`, `bantime` (and `bantime.increment`) and the file that enabled each jail; the configuration is read like fail2ban does it: `jail.conf`, `jail.d/*.conf`, `jail.local`, `jail.d/*.local`, with `[DEFAULT]` and `%(name)s` substitution;
- current bans: IP, jail, since, until (or permanent), how many times the address has been banned (repeat offenders), and a ready-made `fail2ban-client set <jail> unbanip <IP>` command — the application never runs it;
- password brute-force intensity: attempts (`Found` lines) and bans per day and per hour (charts in the dashboard, block-character sparklines in the terminal), totals for 24 hours and for the period, the peak hour;
- the most active addresses and /24 subnets (/64 for IPv6) with several attacking addresses; addresses from `ignoreip` that keep trying are marked;
- recent events: bans, unbans, restored and extended bans, fail2ban and jail restarts.

Data comes only from files: `/var/log/fail2ban.log` (the path is taken from `logtarget` in `fail2ban.conf`/`fail2ban.local`) and its rotated copies, including `.gz`. `fail2ban-client` is not called. Rotated files are parsed once and the current file is read incrementally; the summary is recalculated only when the log, the configuration or the fail2ban state changes (and at most once a minute otherwise). Counters older than the period are dropped. Current bans are reconstructed from the log (a ban without a later unban, taking `bantime` into account; a fail2ban restart lifts all bans until `Restore Ban`); the exact list is `fail2ban-client status sshd`. IP addresses are personal data: they stay in the service's memory and are not written to `state.json` or the event history. The amount of data read is limited (256 MB per file, 200,000 distinct addresses in total), so the log of a heavily attacked server cannot exhaust the service's memory.

Brute force on a public server never stops, so the statistics are informational and do not affect process scores. System checks:

| ID | Level | When |
|---|---|---|
| `fail2ban_not_running` | MEDIUM | fail2ban is installed but `fail2ban-server` is not running: brute-force protection is off |
| `fail2ban_sshd_disabled` | LOW | SSH is reachable from the internet, but no enabled jail protects it |
| `fail2ban_log_unavailable` | INFO | the log is written to journald/syslog (`logtarget = SYSTEMD-JOURNAL`) or the file cannot be read |

`fail2ban_sshd_disabled` can be suppressed with an allowlist rule for the `sshd` process.

## How risk is scored

Each rule produces an **indicator**: a set of facts saying what was read and where, for example `/proc/3101/exe → /dev/shm/.x/kworkerds`. An indicator by itself makes no claim about maliciousness. It has a weight, a category, and a "strong" flag if it is rarely legitimate on its own.

1. The sum of weights gives the base level: LOW from 1 point, MEDIUM from 15, HIGH from 35, CRITICAL from 60.
2. The level is capped by the **number of independent categories** (location, file integrity, masquerading, launch chain, network, command line, behavior, environment, privileges, persistence):
   - one category and no strong indicator — at most **LOW**. So a name alone, a path alone or high load alone never goes above LOW;
   - one category with a strong indicator — at most **MEDIUM**;
   - two categories with fewer than two strong indicators — at most **HIGH**;
   - **CRITICAL** requires three or more categories, or two strong indicators.
3. Informational indicators (running in a container, listening on a port, insufficient privileges) are shown but do not affect the score.
4. The allowlist suppresses indicators of known legitimate processes. A suppressed indicator is not hidden: it is shown struck through and mentioned in the explanation.
5. Known legitimate cases are handled separately. A binary in `/usr` deleted by `apt upgrade` gets 4 points instead of 20. `runc` via memfd is weakened. A systemd journal Unix socket on a service's stdout is not treated as a reverse shell. `node`, `java` and `python` as parents of a shell produce only a weak indicator.

Example explanation from a process card:

> Total CRITICAL: 102 points, 4 indicators, 2 categories (command line, network), 2 strong. Fired: "Shell or interpreter I/O connected to a network socket" +40 (strong); "Command line contains a reverse shell construct" +35 (strong); … This is an assessment based on indirect indicators, not proof of compromise.

The dashboard and the terminal UI show this text in the selected language.

## Examples of detected anomalies

All examples are included in the demo data (`serversecuritygo demo`) and in the automated tests.

| Scenario | Indicators fired | Level |
|---|---|---|
| Miner in `/dev/shm/.x/`, `argv[0]="[kworker/u8:2]"`, connection to port 3333, sustained CPU load | exe in temp dir, hidden dir, kernel thread masquerade, pool port, root from writable dir, sustained CPU | CRITICAL |
| `nginx` → `sh -c 'bash -i >& /dev/tcp/…/4444 0>&1'` → `bash` with fd 0/1/2 on a TCP socket | network service spawned a shell, reverse shell construct, stdin/stdout on a socket, shell with an external connection | CRITICAL |
| `/tmp/.ICE-unix/dbus-daemon (deleted)` with `LD_PRELOAD`, listening on `0.0.0.0:31337` | temp dir, deleted binary, system service name outside system paths, LD_PRELOAD, suspicious listener | CRITICAL |
| `cron` → `sh -c 'curl … \| sh'` | download and immediate execution, scheduler runs a download | HIGH |
| Process from `memfd:` (fileless execution) | running from memory | MEDIUM |
| Compiler at 95% CPU | sustained load only | LOW |
| `sshd` after a package update (`/usr/sbin/sshd (deleted)`) | system binary replaced | LOW |
| Non-empty `/etc/ld.so.preload` | global library preloading | HIGH (system) |
| Cron job `curl … \| sh` | suspicious autostart command | MEDIUM (system) |
| Recently modified `authorized_keys` | recent SSH key change | LOW (system) |

Full list of rule IDs for the allowlist:
`exe_in_temp`, `exe_hidden_path`, `cwd_in_temp`, `exe_deleted`, `exe_memfd`, `exe_world_writable`, `exe_setuid_nonstd`, `exe_system_nonroot`, `kthread_masquerade`, `system_name_masquerade`, `name_mismatch`, `unusual_name`, `empty_cmdline`, `cmdline_truncated`, `unicode_control`, `web_spawns_shell`, `scheduler_suspicious`, `stdio_socket`, `revshell_pattern`, `download_exec`, `miner_pattern`, `miner_name`, `pool_port`, `shell_network`, `suspicious_listen`, `cpu_sustained`, `mem_sustained`, `ld_preload`, `root_from_writable`, `exposed_database`, `exposed_docker_api`, `exposed_admin_panel`, `exposed_remote_access`, `exposed_file_sharing`, `exposed_info_service`. System checks: `ld_so_preload`, `autostart_suspicious`, `autostart_temp`, `autostart_recent`, `ssh_key_command`, `ssh_keys_recent`, `ssh_keys_not_regular`, `fw_docker_bypass`, the `exposed_*` IDs above for dangerous public ports, `fail2ban_not_running`, `fail2ban_sshd_disabled`, `fail2ban_log_unavailable`.

## Detection limitations

This is a heuristic tool for initial triage, not an antivirus or an EDR.

- **Kernel-level rootkits** can hide processes, files and sockets directly in `/proc`. The scanner sees what the kernel shows. User-space rootkits that use `LD_PRELOAD` and `/etc/ld.so.preload` do not affect the scanner itself (a static Go binary without libc), but they can distort the output of `ps`, `ls` and other tools.
- **Snapshots, not events.** Scans run every `SSG_SCAN_INTERVAL` (30 s by default), so processes that live shorter than the interval may be missed. Complete launch auditing requires auditd or eBPF.
- **No file content analysis:** no signatures, hashes or IP reputation. Command-line patterns (`stratum+tcp`, `/dev/tcp/`) are matched by templates and can be evaded by renaming or obfuscation.
- **Privileges.** Without root, exe, cwd, fd and environ of other users' processes are unreadable. The same happens with `hidepid` on `/proc`, `kernel.yama.ptrace_scope=3` and strict AppArmor or SELinux profiles. The scanner reports this in a banner and in the process card.
- **Containers.** Inside a container the scanner sees only that container's PID namespace, so run it on the host. Exe and cwd paths of containerized processes are relative to the container filesystem, so comparisons with the host's system paths can be wrong.
- **False positives** are possible for developer tools (`go run` from `/tmp`, CI builds), custom services in non-standard directories, legitimate mining and `curl | sh` installers. The allowlist exists for these.
- **CPU%** is computed from the `utime+stime` delta between scans with `CLK_TCK=100`, which is the value on x86_64 and arm64 in Ubuntu and Debian. On first observation the average since process start is shown (marked with `*`).
- **Sockets** without a known owner (TIME_WAIT, kernel sockets, no privileges) are shown as "unknown". If a socket is shared by several processes (systemd socket activation, nginx master and workers), the Network table names the first owner found, while each process card shows the socket in full.
- **Open ports** are judged by the address a socket listens on and by ufw only. A service bound to the server's own private address (for example `172.31.5.10` on AWS or GCP) is shown as *private network*, although with the provider's 1:1 NAT it may be reachable from the internet through the public IP; check the provider's security groups. Rules added with `iptables`/`nftables` directly, firewalld and cloud firewalls are not read.
- Fields missing on older kernels (for example `NSpid` before 4.1) are tolerated: that information is simply not shown.

## Where it has been tested

| Environment | What was verified |
|---|---|
| Ubuntu 24.04.4 LTS, kernel 6.8.0, x86_64, 1 vCPU / 2 GB, Docker (test VPS) | installation with the README command; the service running under systemd restrictions (exe, fd and sockets read for every process, no restrictions); the dashboard over an SSH tunnel; `update.sh`, `rollback.sh` and `logs.sh`; history persisting across restarts; password login; refusal to start on a network address without a password or TLS; detection of harmless simulations (kworker masquerade from `/tmp`, a binary deleted after start, bash with input from a TCP socket); the terminal UI in tmux in both modes, its own scanning and connecting to the service through the socket (panels, tree, filter, details, help) |
| GitHub Actions `ubuntu-latest` | all tests, the real `/proc` test as root, a one-off scan of the runner, shellcheck |
| macOS | tests on a fake `/proc`, demo mode, the web dashboard in Chrome |

The application has not yet been run on Debian. It relies only on standard `/proc` and systemd interfaces, but Debian testing is still pending. Automatic rollback in `update.sh` when a new version fails to start has not been reproduced separately. Manual `rollback.sh` has been verified.

Load on the test server (about 120 processes): a scan takes about 60 ms, and the service uses about 12 MB of memory.

## Configuration

All variables are listed with detailed comments (in Russian) in [`.env.example`](.env.example). The main ones:

| Variable | Default | Purpose |
|---|---|---|
| `SSG_LISTEN_ADDR` | `127.0.0.1:8090` | web dashboard address |
| `SSG_SOCKET_PATH` | `/run/serversecuritygo/api.sock` | terminal UI socket (`off` disables it) |
| `SSG_SCAN_INTERVAL` | `30s` | scan period (minimum `2s`) |
| `SSG_AUTH_PASSWORD_HASH` | — | password hash (`serversecuritygo hash-password`) |
| `SSG_ALLOWED_HOSTS` | — | allowed host names for network access |
| `SSG_TLS_CERT` / `SSG_TLS_KEY` | — | built-in HTTPS |
| `SSG_TRUST_PROXY_TLS` | `false` | HTTPS is terminated by a reverse proxy |
| `SSG_CPU_THRESHOLD` / `SSG_CPU_SUSTAIN_SCANS` | `80` / `10` | high load threshold and duration |
| `SSG_HISTORY_RETENTION` | `168h` | how long to keep data about exited processes |
| `SSG_ALLOWLIST_FILE` | `/opt/serversecuritygo/allowlist.json` | allowlist |
| `SSG_LANG` | — (auto) | default language: `ru` or `en` |
| `SSG_AUDIT_ENABLED` | `true` | security settings audit in the service |
| `SSG_AUDIT_INTERVAL` | `1h` | how often to repeat the audit (minimum `1m`) |
| `SSG_AUTH_LOG_DAYS` | `14` | how many days of the fail2ban log to analyze (1–365) |

After editing `.env`, run `systemctl restart serversecuritygo`.

**Allowlist.** Copy [`allowlist.example.json`](allowlist.example.json) to `/opt/serversecuritygo/allowlist.json`. A rule sets `exe` and `name` (with `*` and `?` wildcards), `user` and a list of `rules` (indicator IDs). A rule with no conditions is ignored, so nothing gets suppressed by accident. A process sets its own name (`comm`), so a rule without `exe` matches only if the name also matches the executable's file name: a miner calling itself `node` is not covered by `{"name": "node"}`. For programs running on an interpreter (for example, `gunicorn` on Python), specify `exe`. The service warns about rules without `exe` in its log at startup.

## Language

Every text the user sees is available in English and Russian: the web dashboard and login page, the terminal UI, indicator titles, evidence, score explanations, recommendations, history events, scan warnings, `scan` and `--help` output, the service log and error messages.

- **Web dashboard.** The **English / Русский** button in the header (and on the login page) switches the language instantly; the choice is stored in the browser. Until the user picks a language, the dashboard uses `SSG_LANG`, or the browser language (`Accept-Language`) if it is not set.
- **Terminal UI.** The `L` key switches the language. The initial language is `SSG_LANG`, or the terminal locale (`LC_ALL`, `LC_MESSAGES`, `LANG`).
- **Command line and service log.** `SSG_LANG`, otherwise the locale. With an empty, `C` or `POSIX` locale (typical for systemd services) the output is in Russian, so set `SSG_LANG=en` in `/opt/serversecuritygo/.env` for an English service log.

The scanner stores texts as messages (a catalog key and arguments) and every client renders them in its own language, so two users can watch the same server in different languages at the same time. Translations live in [`internal/i18n`](internal/i18n): `catalog_*.go` holds Russian and English side by side, and tests check that every key has both translations with the same placeholders.

**JSON API.** Text fields (`title`, `evidence`, `recommendation`, `explanation`, `recommendations`, `warnings`, event `details`) are either a plain string (a fact from the system, such as a path) or a message object `{"key": "…", "args": […]}` (`{"sep": "…", "parts": […]}` for joined text). The catalog for one language is served at `GET /i18n/en.json` or `/i18n/ru.json`. `scan --format json` outputs ready-made text in the process language instead of message objects. Error messages of the API follow the `X-SSG-Lang` request header.

## Remote access

The recommended way is an SSH tunnel (see above): nothing is exposed.

If you need direct access, the service starts only when all of these conditions are met:

1. A password is set:
   ```bash
   /opt/serversecuritygo/bin/serversecuritygo hash-password
   # paste the printed SSG_AUTH_PASSWORD_HASH=... line into .env
   ```
2. The host name used to open the dashboard is set: `SSG_ALLOWED_HOSTS=mon.example.com`.
3. HTTPS is enabled: either `SSG_TLS_CERT` and `SSG_TLS_KEY`, or a reverse proxy with HTTPS plus `SSG_TRUST_PROXY_TLS=true`. In the second case it is better to keep the application on `127.0.0.1`.

Example for nginx: the application stays on `127.0.0.1:8090`, and nginx serves the dashboard over HTTPS. In `.env`, set `SSG_TRUST_PROXY_TLS=true` and a password. With `SSG_TRUST_PROXY_TLS=true` the service refuses to start without a password, because it cannot tell whether the proxy exposes it to the internet.

```nginx
server {
    listen 443 ssl;
    server_name mon.example.com;
    ssl_certificate     /etc/letsencrypt/live/mon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mon.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host 127.0.0.1;
        # Client address for login rate limiting: without it every
        # client looks like 127.0.0.1 and shares one counter.
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

The password is stored only as a PBKDF2-SHA256 hash (600,000 iterations). After five failed attempts, login from that address (for IPv6, from that /64 network) is blocked for 15 minutes. An attempt is counted before the password is checked, so parallel requests cannot bypass the limit, and no more than two passwords are checked at once. Behind a reverse proxy, the client address is taken from `X-Forwarded-For` set by the proxy (see the example above). Sessions live in memory, and cookies are marked `HttpOnly`, `SameSite=Strict` and `Secure`.

You can also restrict access by IP with a firewall, for example `ufw allow from <your IP> to any port 443`.

## Updating, rollback, removal, logs

```bash
/opt/serversecuritygo/scripts/update.sh            # to the latest release
/opt/serversecuritygo/scripts/update.sh v0.2.0     # to a specific version
/opt/serversecuritygo/scripts/rollback.sh          # return to the version before the last update
/opt/serversecuritygo/scripts/logs.sh              # journal (last 100 lines, then follow)
/opt/serversecuritygo/scripts/logs.sh -p warning --since today
/opt/serversecuritygo/scripts/uninstall.sh         # remove the service, keep files and history
/opt/serversecuritygo/scripts/uninstall.sh --purge # also remove /opt/serversecuritygo and history
/opt/serversecuritygo/scripts/uninstall.sh --full  # complete removal (see below)
```

How updates are protected against failures:

- before updating, the history, `.env` and `allowlist.json` are archived to `/var/backups/serversecuritygo`, keeping the last 5 archives;
- the new binary is checked (`version`), and the old one is kept as `bin/serversecuritygo.prev`;
- after restart `/healthz` is checked; if the service does not come up, the previous version is restored automatically.
- once the sources are switched, the update is finished by the script from the new version, so its new steps take effect right away. The exception is updating from v0.1.x: the new script did not run there yet, so create the link `/usr/local/bin/serversecuritygo` manually (`ln -sfn /opt/serversecuritygo/bin/serversecuritygo /usr/local/bin/serversecuritygo`) or run `update.sh` again.

Backups are not deleted, even with `--purge`.

**Updating to v0.3.0 (English language).** Run `update.sh` as usual; no migration is needed, and the existing history is kept. After the update:

- the web dashboard opens in the browser language and has an **English / Русский** switch; in the terminal UI the language is switched with `L`;
- the service log stays in Russian unless you add `SSG_LANG=en` to `/opt/serversecuritygo/.env` and run `systemctl restart serversecuritygo`;
- if your own scripts read the JSON API, note that text fields may now be message objects (see [Language](#language)); `scan --format json` still outputs plain text.

### Complete removal

This removes the application as if it had never been on the server: the service and its traces in systemd, the link `/usr/local/bin/serversecuritygo`, `/opt/serversecuritygo`, the history in `/var/lib/serversecuritygo` and the backups in `/var/backups/serversecuritygo`. This cannot be undone.

```bash
/opt/serversecuritygo/scripts/uninstall.sh --full -y
```

If `/opt/serversecuritygo` has already been deleted or damaged, a single command does the same cleanup without the scripts:

```bash
systemctl disable --now serversecuritygo 2>/dev/null; \
rm -rf /etc/systemd/system/serversecuritygo.service /etc/systemd/system/serversecuritygo.service.d; \
systemctl daemon-reload; systemctl reset-failed serversecuritygo 2>/dev/null; \
[ -L /usr/local/bin/serversecuritygo ] && rm -f /usr/local/bin/serversecuritygo; \
rm -rf /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo /run/serversecuritygo
```

What the command leaves alone, and why:

- **the `git`, `curl` and `ca-certificates` packages.** The installer adds them only if they were missing, but other programs need them too. If you are sure you do not need them: `apt-get remove git curl`;
- **journald entries.** There is no way to delete one service's entries without wiping the whole system journal. They disappear on their own as the journal rotates.

To confirm that nothing is left:

```bash
systemctl status serversecuritygo        # Unit serversecuritygo.service could not be found.
ls -d /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo /usr/local/bin/serversecuritygo   # No such file or directory
```

Service status: `systemctl status serversecuritygo`.

## Console mode and demo

A one-off scan that does not touch the service history:

```bash
/opt/serversecuritygo/bin/serversecuritygo scan --env-file /opt/serversecuritygo/.env
/opt/serversecuritygo/bin/serversecuritygo scan --min-risk MEDIUM --sample 2s      # accurate CPU from two samples
/opt/serversecuritygo/bin/serversecuritygo scan --format json --min-risk INFO > scan.json
```

A one-off check of the security settings (SSH, accounts, sudo); `--all` also shows passed checks:

```bash
/opt/serversecuritygo/bin/serversecuritygo audit
/opt/serversecuritygo/bin/serversecuritygo audit --format json > audit.json
```

**Report formats.** `scan` and `audit` take `--format`:

| Format | For |
|---|---|
| `text` (default) | the terminal |
| `json` | scripts and Ansible: a stable schema with `schema_version`, `verdict`, `incomplete` |
| `html` | the server owner: one self-contained file (built-in CSS, no scripts, light and dark themes) with the verdict, summary, findings and recommendations |
| `md` | documentation or a ticket: Markdown tables, everything taken from the system is escaped |

`--output FILE` writes the report to a file with mode 600 (the report contains command lines and paths) instead of the screen. The file is replaced atomically; a symbolic link is refused, and a device such as `/dev/null` is written to directly:

```bash
serversecuritygo audit --format html --output /root/audit.html
serversecuritygo scan --format md --output /root/scan.md
```

**Exit codes** let you run the checks from cron, CI, Ansible or monitoring:

| Code | Meaning |
|---|---|
| `0` | no findings of the `--fail-on` level or higher |
| `1` | there are findings of the `--fail-on` level or higher (default `HIGH`) |
| `2` | error: `/proc` cannot be read at all, broken configuration, wrong flag |
| `3` | no such findings, but the check is incomplete: some data could not be read (run as root) |

`--fail-on` takes `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` or `none`. Findings take precedence over incompleteness: code 1 is returned even if some data was not read. `--fail-on none` makes the code independent of findings (only 2 and 3 remain). **Note for existing scripts:** `scan` used to always exit with 0; now it exits with 1 when there are HIGH or CRITICAL findings — add `--fail-on none` where the old behavior is needed. For `scan`, the level is the highest risk of a process or system finding (`--min-risk` only filters the output); for `audit`, the highest severity of a "fail" or "warning" check.

```bash
# daily at 6:00: the audit report into a file, a mail from cron if something is wrong
0 6 * * * /opt/serversecuritygo/bin/serversecuritygo audit --fail-on HIGH --format md --output /root/audit.md || echo "security settings need attention: /root/audit.md"
```

Demo mode with fictional data runs on Linux and macOS:

```bash
go run ./cmd/serversecuritygo demo --tui   # in the terminal
go run ./cmd/serversecuritygo demo         # in the browser: http://127.0.0.1:8090
```

## Building and testing

Requires Go 1.24 or newer; there are no external modules.

```bash
make build        # bin/serversecuritygo for the current OS
make build-linux  # dist/serversecuritygo-linux-{amd64,arm64} + SHA256SUMS
make test         # go test -race ./...
make vet          # gofmt + go vet
```

Tests use a fake `/proc` tree (`internal/fakeproc`), so they pass on any OS. On Linux, `TestRealProc` additionally reads the real `/proc`. On every push and pull request, GitHub Actions runs the tests on Ubuntu, the `/proc` test as root, a one-off scan of the runner, shellcheck on the scripts and cross-compilation. A `v*` tag builds a release.

## Project layout

```
cmd/serversecuritygo/     entry point: tui (default), serve, scan, demo, hash-password, version
internal/
  procfs/                 reading /proc: stat, status, cmdline, exe, fd, ns, cgroup, net
  detect/                 rules, risk scoring, explanations, allowlist, system checks
  exposure/               open ports: reachability, dangerous services, ufw, published Docker ports
  audit/                  security settings audit: sshd_config, accounts, sudoers; background runner
  fail2ban/               fail2ban: jail configuration, log parsing (incl. .gz), current bans, brute-force statistics
  report/                 scan and audit reports: text, JSON, HTML, Markdown; exit codes
  safefile/               safe reading of files an attacker may control (no symlinks, FIFOs, size limit)
  redact/                 masking secrets in command lines
  history/                process history and event log (state.json, events.jsonl)
  scanner/                periodic scanning: collect → analyze → history
  web/                    HTTP server, authentication, API; static/ holds the embedded web dashboard
  i18n/                   English and Russian translations, message type, language detection
  tui/                    terminal UI (no external libraries: termios, ANSI, mouse)
  view/                   data views shared by the web dashboard and the terminal UI
  config/                 settings from environment variables
  fakeproc/               fake /proc for tests and demo data
  model/                  shared data structures
deploy/serversecuritygo.service   hardened systemd unit
scripts/                  install.sh, update.sh, rollback.sh, uninstall.sh, logs.sh, lib.sh
.env.example              all settings with comments
allowlist.example.json    allowlist example
.github/workflows/        CI and releases
```

API (JSON, for automation; text fields are described in [Language](#language)): `GET /api/status`, `/api/processes`, `/api/process/{key}`, `/api/tree`, `/api/connections`, `/api/exposure`, `/api/audit`, `/api/fail2ban`, `/api/events?limit=N`, `/api/system`, `POST /api/rescan` and `POST /api/audit/run` (with the `X-CSRF-Token` header from `/api/status`), `GET /healthz`.

## Security

- Read-only: the code contains no kill calls, file deletion or network rule changes.
- The terminal UI gets its data through a Unix socket with mode `600` in a `700` directory. The file permissions are the authorization, so only root can connect. Control characters from process names and command lines are never written to the terminal, so a process name cannot execute an escape sequence in your terminal.
- By default the web dashboard listens only on `127.0.0.1`. A network address will not start without a password, `SSG_ALLOWED_HOSTS` and HTTPS.
- Without a password, the dashboard is available only to users listed in `SSG_LOCAL_UIDS` (root by default): the owner of every loopback connection is looked up in `/proc/net/tcp`, and everyone else gets 403. Otherwise any local user could read what the service collects as root: paths, open files and sockets of other users' processes, and check results.
- A `Host` header check protects against DNS rebinding, a CSRF token protects every POST request, and CSP forbids inline scripts. Process names and command lines are rendered as text only, so an attacker cannot inject HTML through the name of their process.
- Secrets in command lines are masked **before** analysis, storage and output: `--password=…`, mysql `-pPASSWORD`, `user:pass@` in URLs, `*_TOKEN=…`, AWS and GitHub keys, JWTs, bot tokens. Environment variable values never reach the history. Passwords, cookies and command lines are never written to the log.
- The service runs as root, because otherwise other users' processes are invisible, but with reduced capabilities: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The filesystem is read-only for the service except `/var/lib/serversecuritygo`, and it runs with `NoNewPrivileges`, a system call filter, and the limits `MemoryMax=256M` and `CPUQuota=50%`.

## Contributing

Contributions are very welcome! We gratefully accept bug reports, false-positive reports, ideas and pull requests.

- Before you start, please read the [contributing guidelines](CONTRIBUTING.md#english) and the [code of conduct](CODE_OF_CONDUCT.md#english).
- For bugs and suggestions, please [open an issue](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose); templates are provided.
- **Please do not report vulnerabilities in public issues.** See [SECURITY.md](SECURITY.md#english) for how to report them.

## License

MIT, see [LICENSE](LICENSE).
