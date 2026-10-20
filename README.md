# ServerSecurityGo

**English** | [Русский](README.ru.md)

[![CI](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml/badge.svg)](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Zagorsky17/ServerSecurityGo)](https://github.com/Zagorsky17/ServerSecurityGo/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Process monitoring and analysis for Linux servers (Ubuntu, Debian). It looks for suspicious processes, signs of malware and unauthorized access. The scanner reads `/proc` and scores every process on a combination of verifiable indicators. It explains each score, keeps a history of changes and shows everything in a web dashboard. The dashboard UI is currently in Russian.

**The application only observes.** It never kills processes, deletes files or blocks connections. All decisions stay with the administrator.

- A single static binary with no dependencies: only the Go standard library, with the web UI embedded in the binary.
- By default the dashboard is reachable only at `127.0.0.1:8090`.
- Risk levels are `INFO`, `LOW`, `MEDIUM`, `HIGH` and `CRITICAL`. Every level comes with an explanation: which rules fired, with what weight and on which facts.

## Contents

- [Installation from GitHub](#installation-from-github)
- [Opening the dashboard](#opening-the-dashboard)
- [Features](#features)
- [How risk is scored](#how-risk-is-scored)
- [Examples of detected anomalies](#examples-of-detected-anomalies)
- [Detection limitations](#detection-limitations)
- [Where it has been tested](#where-it-has-been-tested)
- [Configuration](#configuration)
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

Manual installation without the script:

```bash
git clone https://github.com/Zagorsky17/ServerSecurityGo /opt/serversecuritygo
cd /opt/serversecuritygo
make build          # or download a release binary into bin/serversecuritygo
install -m 600 .env.example .env
install -m 644 deploy/serversecuritygo.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now serversecuritygo
```

## Opening the dashboard

The dashboard listens only on `127.0.0.1:8090`. To open it from your own computer, use an SSH tunnel:

```bash
ssh -L 8090:127.0.0.1:8090 root@<server-IP>
# then open http://127.0.0.1:8090 in your browser
```

If you connect with a dedicated key, add `-i ~/.ssh/<key> -o IdentitiesOnly=yes`.

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
| Boot time, memory, kernel | `/proc/stat`, `/proc/meminfo`, `/proc/sys/kernel/osrelease` |

System persistence checks cover `/etc/ld.so.preload`, cron (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`), systemd units in `/etc/systemd/system`, `/etc/rc.local`, `/etc/init.d`, `/etc/profile.d`, `.bashrc`, `update-motd.d` and `authorized_keys`.

**Web dashboard** (light and dark themes):

1. **Suspicious** — processes with indicators, sorted by risk. Each row shows the indicators, score, first and last seen time, and a recommendation.
2. **All processes** — search, sorting by any column, filters by PID/PPID, user, name, path and minimum risk level.
3. **Tree** — parent and child relationships, collapsible branches, highlighting of matches.
4. **Network** — sockets with their owning processes, filters by protocol, state and external addresses.
5. **History** — process start and exit, changes of exe, cmdline or user, risk increases and decreases, new indicators, new listening ports, system findings.
6. **System** — server details, scanning limitations (privileges, container) and persistence checks.
7. **Process card** — all collected data, the score explanation, facts behind every indicator, recommendations, the ancestor chain, children, sockets, open files and the process history. You can copy the command line and the card as JSON, and link directly to a card (`#p=<key>`).

The dashboard refreshes automatically every 5 to 60 seconds, or not at all. Auto-refresh pauses while a process card is open.

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

The dashboard shows this text in Russian.

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
`exe_in_temp`, `exe_hidden_path`, `cwd_in_temp`, `exe_deleted`, `exe_memfd`, `exe_world_writable`, `exe_setuid_nonstd`, `exe_system_nonroot`, `kthread_masquerade`, `system_name_masquerade`, `name_mismatch`, `unusual_name`, `empty_cmdline`, `web_spawns_shell`, `scheduler_suspicious`, `stdio_socket`, `revshell_pattern`, `download_exec`, `miner_pattern`, `miner_name`, `pool_port`, `shell_network`, `suspicious_listen`, `cpu_sustained`, `mem_sustained`, `ld_preload`, `root_from_writable`. System checks: `ld_so_preload`, `autostart_suspicious`, `autostart_temp`, `autostart_recent`, `ssh_key_command`, `ssh_keys_recent`.

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
- Fields missing on older kernels (for example `NSpid` before 4.1) are tolerated: that information is simply not shown.

## Where it has been tested

| Environment | What was verified |
|---|---|
| Ubuntu 24.04.4 LTS, kernel 6.8.0, x86_64, 1 vCPU / 2 GB, Docker (test VPS) | installation with the README command; the service running under systemd restrictions (exe, fd and sockets read for every process, no restrictions); the dashboard over an SSH tunnel; `update.sh`, `rollback.sh` and `logs.sh`; history persisting across restarts; password login; refusal to start on a network address without a password or TLS; detection of harmless simulations (kworker masquerade from `/tmp`, a binary deleted after start, bash with input from a TCP socket) |
| GitHub Actions `ubuntu-latest` | all tests, the real `/proc` test as root, a one-off scan of the runner, shellcheck |
| macOS | tests on a fake `/proc`, demo mode, the UI in Chrome |

The application has not yet been run on Debian. It relies only on standard `/proc` and systemd interfaces, but Debian testing is still pending. Automatic rollback in `update.sh` when a new version fails to start has not been reproduced separately. Manual `rollback.sh` has been verified.

Load on the test server (about 120 processes): a scan takes about 60 ms, and the service uses about 12 MB of memory.

## Configuration

All variables are listed with detailed comments (in Russian) in [`.env.example`](.env.example). The main ones:

| Variable | Default | Purpose |
|---|---|---|
| `SSG_LISTEN_ADDR` | `127.0.0.1:8090` | dashboard address |
| `SSG_SCAN_INTERVAL` | `30s` | scan period (minimum `2s`) |
| `SSG_AUTH_PASSWORD_HASH` | — | password hash (`serversecuritygo hash-password`) |
| `SSG_ALLOWED_HOSTS` | — | allowed host names for network access |
| `SSG_TLS_CERT` / `SSG_TLS_KEY` | — | built-in HTTPS |
| `SSG_TRUST_PROXY_TLS` | `false` | HTTPS is terminated by a reverse proxy |
| `SSG_CPU_THRESHOLD` / `SSG_CPU_SUSTAIN_SCANS` | `80` / `10` | high load threshold and duration |
| `SSG_HISTORY_RETENTION` | `168h` | how long to keep data about exited processes |
| `SSG_ALLOWLIST_FILE` | `/opt/serversecuritygo/allowlist.json` | allowlist |

After editing `.env`, run `systemctl restart serversecuritygo`.

**Allowlist.** Copy [`allowlist.example.json`](allowlist.example.json) to `/opt/serversecuritygo/allowlist.json`. A rule sets `exe` and `name` (with `*` and `?` wildcards), `user` and a list of `rules` (indicator IDs). A rule with no conditions is ignored, so nothing gets suppressed by accident.

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
    }
}
```

The password is stored only as a PBKDF2-SHA256 hash (600,000 iterations). After five failed attempts, login from that address is blocked for 15 minutes. Sessions live in memory, and cookies are marked `HttpOnly`, `SameSite=Strict` and `Secure`.

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

Backups are not deleted, even with `--purge`.

### Complete removal

This removes the application as if it had never been on the server: the service and its traces in systemd, `/opt/serversecuritygo`, the history in `/var/lib/serversecuritygo` and the backups in `/var/backups/serversecuritygo`. This cannot be undone.

```bash
/opt/serversecuritygo/scripts/uninstall.sh --full -y
```

If `/opt/serversecuritygo` has already been deleted or damaged, a single command does the same cleanup without the scripts:

```bash
systemctl disable --now serversecuritygo 2>/dev/null; \
rm -rf /etc/systemd/system/serversecuritygo.service /etc/systemd/system/serversecuritygo.service.d; \
systemctl daemon-reload; systemctl reset-failed serversecuritygo 2>/dev/null; \
rm -rf /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo
```

What the command leaves alone, and why:

- **the `git`, `curl` and `ca-certificates` packages.** The installer adds them only if they were missing, but other programs need them too. If you are sure you do not need them: `apt-get remove git curl`;
- **journald entries.** There is no way to delete one service's entries without wiping the whole system journal. They disappear on their own as the journal rotates.

To confirm that nothing is left:

```bash
systemctl status serversecuritygo        # Unit serversecuritygo.service could not be found.
ls -d /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo   # No such file or directory
```

Service status: `systemctl status serversecuritygo`.

## Console mode and demo

A one-off scan that does not touch the service history:

```bash
/opt/serversecuritygo/bin/serversecuritygo scan --env-file /opt/serversecuritygo/.env
/opt/serversecuritygo/bin/serversecuritygo scan --min-risk MEDIUM --sample 2s      # accurate CPU from two samples
/opt/serversecuritygo/bin/serversecuritygo scan --format json --min-risk INFO > scan.json
```

Demo mode with fictional data runs on any OS, including macOS:

```bash
go run ./cmd/serversecuritygo demo      # http://127.0.0.1:8090
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
cmd/serversecuritygo/     entry point: serve, scan, demo, hash-password, version
internal/
  procfs/                 reading /proc: stat, status, cmdline, exe, fd, ns, cgroup, net
  detect/                 rules, risk scoring, explanations, allowlist, system checks
  redact/                 masking secrets in command lines
  history/                process history and event log (state.json, events.jsonl)
  scanner/                periodic scanning: collect → analyze → history
  web/                    HTTP server, authentication, API; static/ holds the embedded UI
  config/                 settings from environment variables
  fakeproc/               fake /proc for tests and demo data
  model/                  shared data structures
deploy/serversecuritygo.service   hardened systemd unit
scripts/                  install.sh, update.sh, rollback.sh, uninstall.sh, logs.sh, lib.sh
.env.example              all settings with comments
allowlist.example.json    allowlist example
.github/workflows/        CI and releases
```

API (JSON, for automation): `GET /api/status`, `/api/processes`, `/api/process/{key}`, `/api/tree`, `/api/connections`, `/api/events?limit=N`, `/api/system`, `POST /api/rescan` (with the `X-CSRF-Token` header from `/api/status`), `GET /healthz`.

## Security

- Read-only: the code contains no kill calls, file deletion or network rule changes.
- By default the dashboard listens only on `127.0.0.1`. A network address will not start without a password, `SSG_ALLOWED_HOSTS` and HTTPS.
- A `Host` header check protects against DNS rebinding, a CSRF token protects every POST request, and CSP forbids inline scripts. Process names and command lines are rendered as text only, so an attacker cannot inject HTML through the name of their process.
- Secrets in command lines are masked **before** analysis, storage and output: `--password=…`, mysql `-pPASSWORD`, `user:pass@` in URLs, `*_TOKEN=…`, AWS and GitHub keys, JWTs, Telegram tokens. Environment variable values never reach the history. Passwords, cookies and command lines are never written to the log.
- The service runs as root, because otherwise other users' processes are invisible, but with reduced capabilities: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The filesystem is read-only for the service except `/var/lib/serversecuritygo`, and it runs with `NoNewPrivileges`, a system call filter, and the limits `MemoryMax=256M` and `CPUQuota=50%`.

## Contributing

Contributions are very welcome! We gratefully accept bug reports, false-positive reports, ideas and pull requests.

- Before you start, please read the [contributing guidelines](CONTRIBUTING.md#english) and the [code of conduct](CODE_OF_CONDUCT.md#english).
- For bugs and suggestions, please [open an issue](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose); templates are provided.
- **Please do not report vulnerabilities in public issues.** See [SECURITY.md](SECURITY.md#english) for how to report them.

## License

MIT, see [LICENSE](LICENSE).
