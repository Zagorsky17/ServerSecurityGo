# ServerSecurityGo

[English](README.md) | [Русский](README.ru.md) | **简体中文**

[![Release](https://img.shields.io/github/v/release/Zagorsky17/ServerSecurityGo)](https://github.com/Zagorsky17/ServerSecurityGo/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

面向 Linux 服务器（Ubuntu、Debian）的进程监控与分析工具。它查找可疑进程、恶意软件迹象和未经授权的访问。扫描器读取 `/proc`，根据一组可验证的指标为每个进程评分，解释每一项评分，记录变更历史，并在 Web 面板和终端界面中展示全部信息。界面提供英文和俄文两种语言（见[语言](#语言)），暂无中文界面。

**本程序只做观察。** 它从不终止进程、删除文件或阻断连接，所有决定都由管理员做出。

- 类似 lazygit 的终端界面：在服务器上只需输入 `serversecuritygo`。通过 SSH 隧道访问的 Web 面板是可选的。
- 单个静态二进制文件，没有任何依赖：只使用 Go 标准库，两种界面都内嵌在二进制文件中。
- 默认情况下，面板只能通过 `127.0.0.1:8090` 访问。
- 风险等级为 `INFO`、`LOW`、`MEDIUM`、`HIGH` 和 `CRITICAL`。每个等级都附带解释：触发了哪些规则、权重多少、依据哪些事实。

## 目录

- [从 GitHub 安装](#从-github-安装)
- [终端界面](#终端界面)
- [可选的 Web 面板](#可选的-web-面板)
- [功能](#功能)
  - [开放端口](#开放端口)
  - [审计结果](#审计结果)
  - [fail2ban](#fail2ban)
  - [服务器指标](#服务器指标)
  - [网络负载与 DDoS 迹象](#网络负载与-ddos-迹象)
- [扫描器自检](#扫描器自检)
- [风险评分方式](#风险评分方式)
- [可检测的异常示例](#可检测的异常示例)
- [检测局限](#检测局限)
- [测试环境](#测试环境)
- [配置](#配置)
- [语言](#语言)
- [远程访问](#远程访问)
- [更新与卸载](#更新与卸载)
- [控制台模式与演示](#控制台模式与演示)
- [构建与测试](#构建与测试)
- [项目结构](#项目结构)
- [安全](#安全)
- [参与贡献](#参与贡献)

## 从 GitHub 安装

在服务器上以 root 身份执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | bash
```

安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Zagorsky17/ServerSecurityGo/main/scripts/install.sh | SSG_VERSION=v0.1.1 bash
```

安装脚本会执行以下操作：

1. 将仓库克隆到 `/opt/serversecuritygo`。仓库是公开的，不需要 deploy key。
2. 如果已安装 Go 1.27.4 或更高版本，则从源码构建二进制文件；否则从 [GitHub Releases](https://github.com/Zagorsky17/ServerSecurityGo/releases) 下载预编译的二进制文件并校验其 SHA256。服务器上不需要安装 Go。
3. 根据 `.env.example` 创建 `/opt/serversecuritygo/.env`，权限为 `600`。
4. 安装 `serversecuritygo.service`，设置开机启动并启动服务，然后检查 `/healthz`。
5. 创建链接 `/usr/local/bin/serversecuritygo`，这样一条命令即可打开界面。

如果缺少 `git` 或 `curl`，安装脚本会用 `apt-get` 安装它们。除此之外，它不会对系统做任何修改，也不会触碰 `/opt` 中的其他目录。

文件位置：

| 内容 | 位置 |
|---|---|
| 代码和二进制文件 | `/opt/serversecuritygo`、`/opt/serversecuritygo/bin/serversecuritygo` |
| 设置 | `/opt/serversecuritygo/.env`（权限 600，不提交到 git） |
| 白名单（可选） | `/opt/serversecuritygo/allowlist.json` |
| 历史与指标 | `/var/lib/serversecuritygo`（权限 700）：`state.json`、`events.jsonl`、`audit-baseline.json`、`metrics.json` |
| 备份 | `/var/backups/serversecuritygo`（权限 700） |
| 日志 | journald：`journalctl -u serversecuritygo` |
| systemd 单元 | `/etc/systemd/system/serversecuritygo.service` |
| 启动命令 | `/usr/local/bin/serversecuritygo`（指向二进制文件的链接） |
| 终端界面套接字 | `/run/serversecuritygo/api.sock`（权限 600，仅 root 可用；服务启动时创建） |

不使用脚本手动安装：

```bash
git clone https://github.com/Zagorsky17/ServerSecurityGo /opt/serversecuritygo
cd /opt/serversecuritygo
make build          # 或者把发布版二进制文件下载到 bin/serversecuritygo
install -m 600 .env.example .env
install -m 644 deploy/serversecuritygo.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now serversecuritygo
```

## 终端界面

这是主要的使用方式。通过 SSH 连接到服务器后输入：

```bash
serversecuritygo
```

```
╭ [1] Summary ─────────────────────────────╮╭ PID 3202 · bash ─────────────────────────────────────╮
│ web-01 · Ubuntu 24.04 LTS · 6.8.0-147    ││  CRITICAL   102 pts · www-data · bash                │
│ Scan 21:37:58 (56 ms) · every 30s · …    ││                                                      │
│ CRIT 4  HIGH 1  MED 1  LOW 3             ││ Risk assessment                                      │
╰──────────────────────────────────────────╯│   Result CRITICAL: 102 point(s), indicators: 4, …    │
╭ [2] Suspicious (9) ──────────────────────╮│ Indicators                                           │
│CRITICAL  3202 www-data bash     /usr/bin…││   ● Shell or interpreter I/O is connected to a netw… │
│CRITICAL  3101 root     kworkerds /dev/sh…││       · /proc/3202/fd/0 → socket:[2002] tcp … 4444   │
╰──────────────────────────────────────────╯│   ● Command line contains a reverse shell construct  │
╭ [3] Processes (47) · risk ───────────────╮│ Command line  (y — copy, secrets are masked)         │
╭ [4] Network (17) ────────────────────────╮│   bash -i                                            │
╭ [5] Ports (9) ───────────────────────────╮│                                                      │
╭ [6] Settings (32) ───────────────────────╮│                                                      │
╭ [7] History (25) ────────────────────────╮│ Launch chain                                         │
╭ [8] System (2) ──────────────────────────╮│   systemd(1) → nginx(720) → nginx(721) → sh(3201) →… │
↑↓ select  1-8/Tab panels  Enter details  / filter  r scan  y copy  L русский  ? help  q quit
```

左侧有十个面板：概要、可疑进程、所有进程（列表或树形）、网络连接、开放端口、审计结果、历史、系统检查、服务器指标和网络负载。如果安装了 fail2ban，会在历史之前再出现一个面板 fail2ban，其后面板的编号随之顺延；若关闭了指标采集，则没有指标和网络负载面板。编号超过十的面板用 `Tab` 切换。右侧显示所选条目的详细信息：风险评分及其解释、带事实依据的指标、建议、命令行、启动链、套接字、打开的文件以及进程历史。按 `L` 可在英文和俄文之间切换界面语言。

| 按键 | 作用 |
|---|---|
| `1`…`9`、`0`（第十个面板）、`Tab` / `Shift+Tab` | 切换面板 |
| `↑` `↓` / `j` `k`、`PgUp` `PgDn`、`g` `G` | 选择行；在详情中滚动 |
| `Enter` / `→`、`Esc` / `←` | 进入详情并返回 |
| `/` | 按名称、PID、路径、用户、指标或风险等级过滤面板 |
| `s`、`t`、`K` | 排序进程（风险、CPU、内存、PID、名称）、树形视图、内核线程 |
| `r`、`p` | 立即扫描（在“审计结果”面板上为立即运行审计）、暂停自动刷新 |
| `y` | 把所选条目的主要值复制到你电脑的剪贴板（OSC 52，可通过 SSH 使用）：进程的命令行、审计检查的修复命令、fail2ban 封禁的 IP、开放端口的地址:端口、连接的远程 IP |
| `c` | 复制菜单：详情中的所有内容——IP、命令、路径、事实、建议；按 `Enter` 或 `1`…`9` 复制某一项 |
| `Y` | 以 JSON 形式复制所选条目 |
| `v` | 纯文本模式：以不带边框、颜色和换行的纯文本显示详情，便于用鼠标选取；按任意键返回界面 |
| `m` | 关闭和开启鼠标；关闭时可以使用终端自身的文本选取 |
| `+` / `z` | 将当前一侧放大到全屏（再按一次返回） |
| `w` | “指标”面板的图表窗口：1 小时 → 24 小时 → 30 天 |
| `L` | 界面语言：英文 / 俄文 |
| `?`、`q` | 帮助、退出 |

也可以使用鼠标：单击选择面板和行，滚轮滚动。界面占用鼠标时，终端无法同时选取文本：按 `m` 把鼠标交还给终端（或在 iTerm2 中按住 `Option`，在大多数 Linux 终端和 Windows Terminal 中按住 `Shift`），也可以用 `v` 打开纯文本模式。

**数据来源。** 如果服务正在运行，界面会通过 Unix 套接字 `/run/serversecuritygo/api.sock` 连接到服务。只有 root 能访问该套接字，因此不需要密码或隧道，并且可以看到已收集的完整历史。如果服务没有运行，或者安装的是没有套接字的旧版本，界面会自己扫描进程，此时历史只在本次会话中保留。数据来源显示在“概要”面板中。

```bash
serversecuritygo tui --local            # 始终自行扫描
serversecuritygo tui --refresh 2s       # 更频繁地刷新屏幕
```

要查看所有用户的进程，请以 root 身份运行界面。在服务模式下，数据已由服务收集。

如果 `y` 或 `c` 复制不起作用：iTerm2、kitty、WezTerm、Alacritty、Windows Terminal 和较新的 xterm 支持 OSC 52。在 tmux 中需要设置 `set -g set-clipboard on`。macOS 的 Terminal.app 不支持 OSC 52：请按 `v`（纯文本模式）并用鼠标选取文本——长命令会由终端自动折行，并作为一行复制。

## 可选的 Web 面板

Web 面板在浏览器中展示相同的数据。它只监听 `127.0.0.1:8090`。要从自己的电脑打开，请使用 SSH 隧道：

```bash
ssh -L 8090:127.0.0.1:8090 root@<服务器 IP>
# 然后在浏览器中打开 http://127.0.0.1:8090
```

如果使用专用密钥连接，请加上 `-i ~/.ssh/<密钥> -o IdentitiesOnly=yes`。

面板不必一直运行：在 `.env` 中设置 `SSG_LISTEN_ADDR=off` 并执行 `systemctl restart serversecuritygo`，即可完全关闭面板——不再打开 HTTP 端口，而扫描、历史、审计和指标继续工作，可在终端界面中查看。需要恢复面板时，把地址写回去并重启服务。

在未设置密码时，服务只允许 root 进入面板：对每个到 `127.0.0.1` 的连接，它都会在 `/proc/net/tcp` 中查找套接字的所有者。以 root 身份打开的隧道可以使用，而服务器上的其他用户（例如被入侵的 `www-data`）会收到 403 错误。如果你以自己的用户身份通过 SSH 登录，请把该用户的 UID 加入 `SSG_LOCAL_UIDS`（例如 `0,1000`），或者设置密码。

## 功能

### 诊断摘要

审计默认显示失败、警告、不可用检查和变更检查。选择 **All results（所有结果）** 可查看通过项和建议。系统摘要保留不完整检查及带有关联历史的发现；其他 INFO 项可通过 **Show all results, including INFO（显示所有结果，包括 INFO）** 查看。在 TUI 的审计和系统面板中，`i` 切换完整列表，搜索也包含详情。UFW 设置和读取限制显示在配置文件内容之前。

失败登录记录按 IP、日志来源和认证方法分组，使用固定的 15 分钟 UTC 时间区间。计数表示日志记录数，而非唯一尝试次数：不同日志可能描述同一次尝试。成功登录以及缺少来源、IP 或时间的记录分别显示。展开 Web 分组或在 TUI 中选择分组即可查看全部事件；`Y` 将分组复制为 JSON 数组（单个事件仍为对象）。Web 分组详情默认显示最多 400 条记录，点击 **Show all（显示全部）** 可查看其余记录。API 和历史中的原始事件与发现均保留。

**数据收集**读取 `/proc` 及相关来源：

| 数据 | 来源 |
|---|---|
| PID、PPID、名称、状态、线程、启动时间、CPU（utime+stime） | `/proc/PID/stat` |
| UID/EUID/GID、RSS、命名空间内的 PID | `/proc/PID/status` |
| 命令行（密钥会被遮蔽） | `/proc/PID/cmdline` |
| 可执行文件、删除标记、权限、所有者 | `/proc/PID/exe`（readlink + stat） |
| 工作目录 | `/proc/PID/cwd` |
| 打开的文件和套接字 | `/proc/PID/fd/*` |
| 每个网络命名空间的 TCP/UDP/Unix 套接字 | `/proc/PID/net/{tcp,tcp6,udp,udp6,unix}` |
| 命名空间和容器（docker、containerd、kubernetes、podman、lxc） | `/proc/PID/ns/*`、`/proc/PID/cgroup` |
| 是否存在 `LD_PRELOAD`/`LD_AUDIT`（只记录名称，从不保存值） | `/proc/PID/environ` |
| 用户 | `/etc/passwd` |
| 服务器地址（用于区分公网端口和内网端口） | `/proc/net/fib_trie`、`/proc/net/if_inet6` |
| ufw 状态和规则 | `/etc/ufw/ufw.conf`、`/etc/default/ufw`、`/etc/ufw/user.rules`、`/etc/ufw/user6.rules` |
| SSH 设置 | `/etc/ssh/sshd_config`（含 `Include` 和 `Match`）、`/etc/ssh/ssh_host_*_key` 的权限 |
| 账户（从不显示或保存密码哈希，只记录算法类型） | `/etc/passwd`、`/etc/shadow`、`/etc/group`、`/etc/login.defs`、`/etc/environment`、root 的 `.profile` 和 `.bashrc` |
| sudo 规则 | `/etc/sudoers`（含 `@include`/`@includedir`、别名和 `Defaults`） |
| Docker 发布的端口、容器名称和镜像 | `docker-proxy` 的参数、`<data-root>/containers/*/config.v2.json`（环境变量不会读入内存结构，也从不显示） |
| 启动时间、内存、内核 | `/proc/stat`、`/proc/meminfo`、`/proc/sys/kernel/osrelease` |
| 服务器指标 | `/proc/stat`、`/proc/loadavg`、`/proc/meminfo`、`/proc/pressure/*`、`/proc/diskstats`、`/proc/net/dev`、`/proc/uptime`、`/proc/vmstat`、`/proc/self/mounts` + `statfs` |

系统持久化检查覆盖 `/etc/ld.so.preload`、cron（`/etc/crontab`、`/etc/cron.*`、`/var/spool/cron`）、`/etc/systemd/system` 中的 systemd 单元、`/etc/rc.local`、`/etc/init.d`、`/etc/profile.d`、`.bashrc`、`update-motd.d` 和 `authorized_keys`。

**终端界面**见[上文](#终端界面)。**Web 面板**（浅色和深色主题）：

1. **可疑进程** —— 带有指标的进程，按风险排序。每一行显示指标、分数、首次和最近一次观察时间以及一条建议。
2. **所有进程** —— 搜索、按任意列排序，可按 PID/PPID、用户、名称、路径和最低风险等级过滤。
3. **进程树** —— 父子关系，可折叠分支，高亮匹配项。
4. **网络** —— 套接字及其所属进程，可按协议、状态和外部地址过滤。
5. **开放端口** —— 服务器监听了什么，以及从哪里可以访问；见[开放端口](#开放端口)。
6. **审计结果** —— SSH、账户、sudo 和内核参数的审计；见[审计结果](#审计结果)。
7. **历史** —— 进程启动和退出，exe、cmdline 或用户的变化，风险升高和降低，新指标，新的监听端口，系统发现，安全设置的变化。
8. **系统** —— 服务器信息、扫描限制（权限、容器）、持久化检查和危险的开放端口。
9. **指标** —— CPU 与 steal、负载、PSI、内存、磁盘和网络，附 1 小时、24 小时和 30 天的图表；见[服务器指标](#服务器指标)。
10. **网络负载** —— 按端口的半开连接、连接来源、内核计数器和攻击发现；见[网络负载与 DDoS 迹象](#网络负载与-ddos-迹象)。
11. **进程卡片** —— 收集到的所有数据、评分解释、每个指标背后的事实、建议、祖先链、子进程、套接字、打开的文件和进程历史。可以复制命令行和 JSON 格式的卡片，也可以直接链接到某张卡片（`#p=<key>`）。

面板每 5 到 60 秒自动刷新一次，也可以关闭自动刷新。打开进程卡片时自动刷新会暂停。

### 开放端口

VPS 被入侵最常见的真实原因，是某个服务意外监听在 `0.0.0.0` 上：没有密码的 Redis、MongoDB、Docker API、管理面板。**开放端口**标签页（终端界面中的面板 `5`、`GET /api/exposure`、`serversecuritygo scan` 输出末尾的表格）列出每个监听的 TCP 套接字和已绑定的 UDP 套接字：

- **可达范围**：*公网*（下列范围以外的任何地址，包括 `0.0.0.0` 和 `::`，即所有接口，旁边会列出服务器的公网地址）、*内网*（`10/8`、`172.16/12`、`192.168/16`、`100.64/10`、`fc00::/7`、链路本地地址）、*仅本机*（`127.0.0.0/8`、`::1`）或*容器内*（套接字位于自己的网络命名空间中，外部只能通过已发布的端口访问）；
- 所属进程、用户和容器；对于 Docker，还有容器名称、镜像和端口映射；
- 从内置表中**识别出的服务**：Redis、Docker API、MongoDB、Elasticsearch/OpenSearch、etcd、kubelet、Jupyter、memcached、PostgreSQL、MySQL/MariaDB、RabbitMQ、CouchDB、SMB、RDP、VNC、Telnet、FTP、rpcbind、NFS、SNMP、Prometheus exporter，以及被用于 DDoS 放大攻击的公网 UDP 服务（DNS、NTP、SSDP/UPnP、chargen、CLDAP、WS-Discovery）。服务根据端口和进程名（或容器镜像）识别；仅凭端口号匹配时等级降低一级，因为该端口上可能是别的程序；
- 该端口的 **ufw** 状态：*开放*（有允许任意地址的规则）、*已阻止*（ufw 已启用，且未对所有人开放该端口）或*绕过 ufw*。

等级表示服务可被访问的危险程度，而不是被入侵的迹象：可从互联网访问的 Redis 为 CRITICAL，PostgreSQL 为 HIGH，Prometheus exporter 为 LOW。如果 ufw 阻止了该端口，等级降为 LOW，并注明只有防火墙在保护该服务。每个危险的公网端口都会成为带有该等级的系统发现（显示在“系统”标签页、历史和日志中），并在占用该端口的进程卡片中成为 `exposure` 类别的指标。该指标不是“强”指标：单独出现时，合法进程的等级最高为 LOW。

**Docker 绕过 ufw。** Docker 会把自己的 iptables 规则插在 ufw 规则之前，所以 `ufw deny 6379` 无法关闭以 `-p 6379:6379` 发布的端口。如果 ufw 已启用，而某个容器端口在所有接口上发布、且没有允许它的 ufw 规则，面板会报告 `fw_docker_bypass`（HIGH），并建议以 `127.0.0.1:端口:端口` 的形式发布，或在 `DOCKER-USER` 链中加以限制。已发布的端口从 `docker-proxy` 的参数和容器的 `config.v2.json` 中读取，因此在 `userland-proxy: false` 时也能看到。不使用 Docker API：它的套接字等同于 root 权限，而观察者不需要它。

如果某个端口是有意开放的，可以为该进程添加带指标 ID 的白名单规则（例如 `{"exe": "/usr/lib/postgresql/16/bin/postgres", "rules": ["exposed_database"]}`）：进程指标和系统发现都会显示为已抑制，不再计入。没有监听进程、由 Docker 发布的端口（`userland-proxy: false`）无法用这种方式抑制。

### 审计结果

大多数 VPS 入侵并不是通过零日漏洞，而是通过密码登录、多余的 `NOPASSWD: ALL` 或被遗忘的用户。**审计结果**标签页（终端界面中的面板 `6`、`GET /api/audit`、`serversecuritygo audit` 命令）检查的是配置——入侵的原因，而不是入侵的痕迹。

服务在启动时立即执行审计，之后每隔 `SSG_AUDIT_INTERVAL`（默认 1 小时）执行一次。**立即检查**按钮（终端界面中在该面板上按 `r`）会马上运行审计，例如在你修复问题之后；检查进行中时不会启动新的检查。标签页显示上次检查的时间和通过数量：“通过 N / M”只统计结果为通过、危险或警告的检查（建议、不适用和未知不计入）。

每项检查都有结果（*通过*、*危险*、*警告*、*建议*、*不适用*——例如未安装 sshd、*未知*——没有读取权限）、严重程度、带文件和行号的事实（`/etc/ssh/sshd_config.d/50-cloud-init.conf:1 PasswordAuthentication yes`）、建议，通常还有现成的修复命令。应用程序从不执行命令：由你自己运行。修改 SSH 之前，请先在另一个会话中确认密钥登录可用。

| 分组 | 检查 |
|---|---|
| SSH | `ssh_root_login`、`ssh_password_auth`、`ssh_empty_passwords`、`ssh_kbd_interactive`（即使 `PasswordAuthentication no`，也可通过 PAM 输入密码）、`ssh_max_auth_tries`、`ssh_x11_forwarding`、`ssh_tcp_forwarding`（`GatewayPorts`）、`ssh_weak_crypto`（CBC、3DES、RC4、MD5、SHA-1、DSA）、`ssh_authkeys_file`（非标准密钥文件或 `AuthorizedKeysCommand`）、`ssh_host_keys_perms`、`ssh_config_perms`，以及建议项 `ssh_allow_users`、`ssh_banner_version`、`ssh_port` |
| 账户 | `acct_uid0_extra`、`acct_empty_password`、`acct_service_shell`、`acct_weak_hash`（MD5、DES）、`acct_new`、`acct_priv_groups`（`sudo`、`admin`、`wheel`、`docker`、`lxd`、`disk`、`adm`、`shadow`）、`acct_duplicate_ids`、`acct_passwd_perms`、`acct_home_perms`、`acct_root_path` |
| sudo | `sudo_nopasswd_all`（对云镜像默认用户 `ubuntu`、`debian`、`admin` 等为 MEDIUM）、`sudo_no_auth`、`sudo_gtfobins`（`vim`、`less`、`find`、`systemctl` 等可轻易获得 root shell 的程序）、`sudo_wildcard`、`sudo_writable_cmd`、`sudo_env_keep`（`LD_PRELOAD`、`PYTHONPATH`、`!env_reset`）、`sudo_files_perms`、`sudo_changed` |
| 内核 | 网络攻击准备情况：`net_syncookies`、`net_conntrack_max`（连接跟踪表被填满后内核会丢弃新连接）、`net_icmp_broadcast`（smurf 放大），以及建议项 `net_syn_backlog`、`net_somaxconn`、`net_synack_retries`、`fw_ssh_ratelimit`（SSH 端口的 `ufw limit` 规则或 fail2ban jail）。取值来自 `/proc/sys`；修复命令会把参数追加到 `/etc/sysctl.d/90-hardening.conf`。若未加载 conntrack 模块，则该检查为不适用 |

sshd 配置的解析方式与 sshd 本身一致：`Include` 就地展开，每个键以第一个值为准，`Match` 块单独显示（“用户 X 允许密码登录”），缺失的键采用 OpenSSH 默认值。sudoers 解析支持 `@include`/`@includedir`（与 sudo 一样跳过文件名含点的文件）、别名、续行和 `Defaults`。

**变化。** 服务把用户名和 UID、特权组成员以及 sudoers 文件的 SHA-256 记录在 `/var/lib/serversecuritygo/audit-baseline.json` 中（权限 600，不含密码和文件内容）。出现新用户、特权组新成员或 sudoers 被修改时，`acct_new`、`acct_priv_groups` 或 `sudo_changed` 会在 24 小时内保持危险，下一次检查不会悄悄清除告警。如果某次运行时文件读取失败，会保留该文件对应的基线部分，之后不会把所有内容都误报为新的。每次结果变化（“原为通过，现为危险”、“已修复”）都会记录到“历史”标签页和日志中。一次性的 `serversecuritygo audit` 没有可比较的对象，因此其中的变化类检查为不适用。

### fail2ban

**fail2ban** 标签页（终端界面中的一个面板、`GET /api/fail2ban`）仅在安装了 fail2ban 时出现：存在 `/etc/fail2ban` 和 `fail2ban-server`（或 dpkg 软件包），或者 `fail2ban-server` 进程正在运行。没有 fail2ban 时既没有标签页，也没有面板或空白占位；API 返回 `{"installed": false}`。

显示最近 `SSG_AUTH_LOG_DAYS` 天（默认 14 天）的以下内容：

- 状态：是否运行、版本、已启用的 jail 及其 `maxretry`、`findtime`、`bantime`（以及 `bantime.increment`）和启用该 jail 的文件；配置按 fail2ban 自己的方式读取：`jail.conf`、`jail.d/*.conf`、`jail.local`、`jail.d/*.local`，支持 `[DEFAULT]` 和 `%(名称)s` 替换；
- 当前封禁：IP、jail、开始时间、截止时间（或永久）、该地址已被封禁的次数（惯犯），以及现成的 `fail2ban-client set <jail> unbanip <IP>` 命令——应用本身从不执行它；
- 密码暴力破解强度：按天和按小时统计的尝试次数（`Found` 行）和封禁次数（面板中为图表，终端中为块字符迷你图）、24 小时和整个周期的合计、峰值小时；
- 最活跃的地址，以及包含多个攻击地址的 /24 子网（IPv6 为 /64）；仍在尝试的 `ignoreip` 地址会被标记；
- 最近事件：封禁、解封、恢复和延长的封禁、fail2ban 与 jail 的重启。

数据只来自文件：`/var/log/fail2ban.log`（路径取自 `fail2ban.conf`/`fail2ban.local` 中的 `logtarget`）及其轮转副本，包括 `.gz`。不调用 `fail2ban-client`。轮转文件只解析一次，当前文件从上次停下的位置继续读取；只有当日志、配置或 fail2ban 状态发生变化时才重新计算汇总（否则至多每分钟一次）。超出统计周期的计数会被丢弃。当前封禁根据日志重建（有封禁而之后没有解封，并考虑 `bantime`；fail2ban 重启会解除所有封禁，直到出现 `Restore Ban` 行）；精确列表请用 `fail2ban-client status sshd`。IP 地址属于个人数据：只保存在服务内存中，不会写入 `state.json` 或事件历史。解析量有上限（每个文件 256 MB，所有文件合计 200,000 个不同地址），因此遭受大量暴力破解的服务器日志也不会耗尽服务内存。

公网服务器上的暴力破解从不停止，因此这些统计仅供参考，不影响进程评分。系统检查：

| ID | 级别 | 触发条件 |
|---|---|---|
| `fail2ban_not_running` | MEDIUM | 已安装 fail2ban，但 `fail2ban-server` 未运行：防暴力破解保护已关闭 |
| `fail2ban_sshd_disabled` | LOW | SSH 可从互联网访问，但没有已启用的 jail 保护它 |
| `fail2ban_log_unavailable` | INFO | 日志写入 journald/syslog（`logtarget = SYSTEMD-JOURNAL`）或文件无法读取 |

可以用针对 `sshd` 进程的 allowlist 规则屏蔽 `fail2ban_sshd_disabled`。

### 服务器指标

**指标**标签页（终端界面中的面板 `10`、`GET /api/metrics?range=1h|24h|30d`）回答“服务器为什么慢”这个问题：是你的进程、内存不足，还是主机商的原因。只有在服务开启指标采集（`SSG_METRICS_ENABLED=true`）时才会出现该板块。

一个独立的轻量 goroutine 每 `SSG_METRICS_INTERVAL`（默认 5 秒）采集一次，比进程扫描更频繁，否则半分钟的尖峰就看不到了：

- **处理器**按构成划分（用户、系统、I/O 等待、**steal**），包含总体和每个核心；steal 是你的虚拟机等待 CPU 时、宿主机把时间交给其他虚拟机的那部分：steal 持续偏高说明服务器慢不是你的进程导致的。在物理机上 steal 始终为 0，面板会直接说明这不是虚拟机；
- **平均负载** 1/5/15（相对核心数）与 **PSI 压力**（`/proc/pressure/*`，任务等待 CPU、内存或磁盘的时间占比）；在 4.20 之前的内核或 `psi=0` 时该部分不存在；
- **内存与 swap**、**分区占用**（含 inode）、**磁盘 I/O**（MB/s 与设备繁忙度）、**网卡流量**（MB/s、包/秒、丢包）、**uptime**；
- 全部来自 `/proc` 和 `statfs`：不执行任何外部命令，也没有任何外发连接。网络文件系统（NFS、CIFS、sshfs）不做测量：对不可达的服务器调用 `statfs` 会卡住，连指标 goroutine 一起卡死。

数据序列保存在内存中并逐级降采样：**1 小时**为每次采集、**24 小时**为每分钟、**30 天**（`SSG_METRICS_RETENTION`）为每 15 分钟。每个点同时保存平均值和最大值，因此短暂尖峰在聚合后不会消失（图上表现为线条上方的浅色填充）。聚合值每五分钟以及停止时写入 `/var/lib/serversecuritygo/metrics.json`，所以 24 小时和 30 天的图表能在服务重启后保留；原始采集值不会落盘。文件损坏不会影响启动：它会被移到 `.corrupt`，序列重新开始。

在容器内，`/proc/stat` 和 `/proc/meminfo` 显示的是宿主机而不是容器限制——界面中有相应提示。

指标**不影响**进程风险评分：服务器过载是 VPS 质量问题，不是入侵迹象。但由指标得出的发现会进入“系统”板块、事件历史和 `scan` 报告：

| ID | 等级 | 条件 |
|---|---|---|
| `steal_high` | LOW | steal 高于 `SSG_STEAL_THRESHOLD`（10 %）并持续超过 10 分钟：主机商超售资源 |
| `disk_almost_full` | MEDIUM | 分区或其 inode 占用超过 `SSG_DISK_FULL_THRESHOLD`（90 %）：磁盘写满后日志停止写入，排查入侵将无据可依 |
| `load_high` | INFO | 平均负载超过每核 2 并持续超过 15 分钟 |
| `memory_pressure` | INFO | 内存 PSI 高于 10 %，或 swap 在 10 分钟内增长超过 64 MB |
| `oom_recent` | LOW | `/proc/vmstat` 中的 `oom_kill` 计数增加：内核内存不足并杀掉了进程 |

发现只在条件持续（10–15 分钟）后出现，一旦条件消失立即撤销：单个尖峰不算告警。因此一次性的 `serversecuritygo scan` 只能看到其中的 `disk_almost_full`：其余发现需要持续采集指标的常驻服务。

### 网络负载与 DDoS 迹象

**网络负载**标签页（终端界面中的面板 `11`、`GET /api/netload`）回答“服务器没有响应——是攻击还是应用本身？”这个问题。该板块与指标一同出现（`SSG_METRICS_ENABLED=true`）：内核计数器由同一个 goroutine 采集。

**边界。** 应用只做观察：不封禁地址、不修改防火墙规则、也不制造负载。它不含压力测试功能：发送请求洪流就等于做出攻击工具。更重要的是——**占满服务器上行链路的流量型攻击在服务器内部完全看不到**：服务器只能看到已经到达的部分。这类攻击只能由主机商或 CDN 拦截，应用会直接说明这一点，而不是承诺“防护”。

可以看到：

- **端口**：半开连接（`SYN_RECV`、`NEW_SYN_RECV`，即已开始但未完成的握手）、已建立连接、accept 队列及其上限（来自监听套接字 `tx_queue:rx_queue` 的 `backlog`）、不同地址的数量以及所属进程；
- **来源**：单个地址和子网（IPv4 为 /24，IPv6 为 /64），含连接数、半开数和地址数；受信网络与私有网络会被标注；
- **内核计数器**（每秒）：SYN cookies、监听套接字丢弃、接收丢弃、UDP 错误、重传、数据包、已建立连接、无主套接字以及 conntrack 表占用率。同样的计数器会进入指标序列（`net_syn_rate`、`net_listen_drops`、`net_conntrack`、`net_rx_drops`、`net_udp_errors`、`net_estab`、`net_orphan`、`net_retrans`），可在 1 小时、24 小时和 30 天的图表中查看。

数据仅来自 `/proc`：`net/netstat`、`net/snmp`、`net/sockstat`、`net/softnet_stat`、`net/stat/nf_conntrack`、`net/dev`、`sys/net/*` 以及 `net/tcp`、`net/tcp6` 表。没有也不会有外部 IP 信誉库（自治原则）。

| ID | 等级 | 条件 |
|---|---|---|
| `net_syn_flood` | MEDIUM；半开数 ≥ backlog 的 90 % 或 SYN 被丢弃时为 HIGH | SYN cookies > 50/秒且持续超过 30 秒，**或**某端口半开数 ≥ 256 且 ≥ backlog 的 50 %（连续两次扫描） |
| `net_listen_overflow` | MEDIUM | `ListenOverflows`/`ListenDrops` > 10/秒且持续超过一分钟，**或** accept 队列 ≥ backlog 的 90 %：应用来不及接受连接——可能是攻击，也可能是工作进程不足 |
| `net_conn_flood_ip` | LOW；超过阈值 5 倍时为 MEDIUM | 单个地址的连接数超过 `SSG_NET_CONN_PER_IP`（200），连续两次扫描 |
| `net_conn_flood_subnet` | MEDIUM | 单个子网的连接数超过阈值的 4 倍，且来自 ≥ 20 个不同地址 |
| `net_conn_surge` | LOW | 入站连接 ≥ 1000 且 ≥ `SSG_NET_SURGE_FACTOR` × 常态（需要六小时基线） |
| `net_conntrack_full` | MEDIUM；≥ 95 % 或出现丢失时为 HIGH | conntrack 表占用 ≥ 80 % 且持续超过一分钟：内核开始丢弃新连接 |
| `net_orphans_high` | LOW | 无主套接字 ≥ `tcp_max_orphans` 的 50 %，或 `TCPAbortOnMemory` 在增长 |
| `net_udp_flood` | MEDIUM / LOW | `RcvbufErrors` > 100/秒（应用来不及读取 UDP）或 `NoPorts` > 1000/秒（流量打向关闭的端口） |
| `net_rx_drops` | MEDIUM | 接收丢弃 > 1000/秒：内核或网卡处理不过来 |
| `net_pps_surge` | LOW | 入站数据包 ≥ 50 000/秒且 ≥ `SSG_NET_SURGE_FACTOR` × 常态 |
| `net_ddos_suspected` | HIGH | 至少**两组**发现同时触发（SYN、连接、内核、UDP）——单一症状在真实访客激增时也会出现 |
| `net_table_truncated` | INFO | 连接数超过 `SSG_NET_MAX_SOCKETS`：本板块中的数字被低估 |

**持续与回差。** 发现只在条件持续 30–120 秒（基于连接的发现为连续两次扫描）后出现，并在不再超限五分钟后撤销。单个尖峰不算告警；攻击期间发现不会反复闪烁，也不会把历史刷满事件。

**误报。** 对于 CDN 后面的站点，所有访客都来自 CDN 的地址——把这些网段写入 `SSG_NET_TRUSTED_NETS`，它们就不再被视为洪流来源（表格中标为受信）。私有网络和子网的阈值会自动提高到四倍。服务器的出站连接不会计入来源，与自身的连接同样不计。在指标不足六小时之前，相对阈值（“常态的 N 倍”）不生效。任何发现都可以用其 ID 通过白名单规则抑制。

**保护扫描器自身。** 攻击期间 `/proc/net/tcp` 会增长到数十万行，因此每个网络命名空间的套接字数量受 `SSG_NET_MAX_SOCKETS` 限制（100 000，每个套接字约 200 字节）；超出部分会被跳过，并出现 `net_table_truncated`。按地址聚合的数据同样有大小上限。

### UFW 与 PID 扫描耗时

在 TUI 中，UFW 的第一项是 **Ports and rules summary（端口与规则汇总）**：显示保存的状态、主要策略、监听及发布端口的地址和进程，以及按文件顺序列出的 IPv4/IPv6 用户规则声明。汇总不受“端口”筛选条件影响；UFW 筛选仅作用于源文件列表。Enter 切换到详情滚动，`Y` 将 UFW 和端口数据复制为 JSON。汇总最多显示 100 个端口和 100 条声明，超出时明确提示。before/after 规则及无 tuple 的手写规则仍可在源文件中查看；监听端口本身不代表外部网络可达。

**UFW** 位于 fail2ban 后面（未安装 fail2ban 时位于审计后面）。显示已保存的入站、出站和转发策略、IPv6、日志、应用程序配置、conntrack 模块及 sysctl 文件。可以查看 `ufw.conf`、`/etc/default/ufw`、`before/user/after.rules` 及其 IPv6 版本、`before/after.init`、`sysctl.conf`、`IPT_SYSCTL` 指定的文件和 `applications.d` 配置的完整内容。TUI 中选择文件后按 Enter 滚动详情；`/` 按路径和内容过滤，`y` 复制路径，`Y` 复制 JSON。网页中展开文件即可。API 为 `GET /api/ufw`，采用与其他接口相同的授权机制。

这里展示磁盘上的配置，文件修改可能尚未生效；不验证内核当前规则或 Docker 的第三方规则。读取时不执行命令，每个文件限制 1 MiB，总计 4 MiB，应用配置最多 1000 个；读取错误、超限和必需文件缺失会明确显示。缺失设置不会被假定的默认值代替。[UFW 处理顺序](https://manpages.ubuntu.com/manpages/noble/man8/ufw-framework.8.html) 为 before → user → after，IPv4 和 IPv6 分别处理。

完整 PID 扫描期间，警告显示已用时间、预计剩余时间和已扫描范围百分比。时间格式为 `HH:MM:SS`；预估按本次扫描的平均速度计算，随负载变化。尚无初始测量时显示正在计算。取消或失败后耗时停止增长，新一轮扫描重新计时。显示随扫描器快照（`SSG_SCAN_INTERVAL`）更新，成功完成后显示总耗时。

### 隐藏进程、内核模块与软件包完整性

结果显示在**系统**、历史记录和 `scan` 报告中。服务将 `/proc` 列表与线程 TGID、父进程 PID 对照，并根据 PID 和启动时间，两次确认缺失的进程组组长，两次间隔 50 毫秒。普通线程、已退出进程和复用的 PID 被排除。独立工作线程每批探测 1024 个 PID，批次之间暂停 100 毫秒，完成后按 `SSG_ROOTKIT_INTERVAL`（默认 `10m`）重新运行。较大的 PID 范围需要数分钟，短命进程可能被漏掉。`loadavg` 的任务总数不作为隐藏进程的证据，因为命名空间和并发创建任务会使这种推断不可靠。

模块检查两次对照 `/proc/modules` 与 `/sys/module` 中处于 live 状态的可加载模块，排除内置模块及加载、卸载过程中的状态。`rootkit-modules.json` 保存本次系统启动的初始模块集合。`kmod_hidden` 和 `hidden_process` 为 CRITICAL；`kmod_new` 和 `kmod_unsigned` 为 MEDIUM。已知外部驱动名称将 `kmod_unsigned` 降为 LOW，但名称并不证明可信。`kernel_tainted` 仅提供信息：[内核 taint 标志](https://docs.kernel.org/admin-guide/tainted-kernels.html)也包括警告、硬件故障和外部驱动。`kmod_unindexed` 和 `kmod_origin_unavailable` 表示 `modules.dep` 缺少条目或索引不可用，都不能证明模块实际从哪个路径加载。

服务在启动时以及每隔 `SSG_INTEGRITY_INTERVAL`（默认 `24h`）验证所选软件包文件，读取速率最高为 16 MiB/s。范围包括 `/usr/bin`、`/usr/sbin`、`/bin`、`/sbin`、systemd 二进制文件、PAM 模块、OpenSSH 辅助程序、libc、libpam、libkeyutils 和 libaudit，同时支持 usrmerge 与不同架构的库目录。服务直接读取 dpkg status、`.list`、`.md5sums`、conffiles 和 diversions；alternatives 符号链接不会被当作无软件包归属的普通可执行文件。dpkg 忙碌或元数据正在变化时，结果标为不完整。没有软件包校验和的文件会明确标为未验证。

`bin_modified` 对 SSH、提权与登录工具、常见诊断工具、PAM 和 libc 使用 CRITICAL，其他不一致使用 HIGH。安装后服务首次成功验证时，`integrity.json` 保存 SHA-256。软件包版本与校验和一致更新时会刷新基线；同一版本内哈希或元数据发生变化时，会保留旧基线并报告发现。`bin_unpackaged` 为 INFO。独立确认手动安装的文件后，可用精确规则 `{"exe":"/usr/bin/my-tool","rules":["bin_unpackaged"]}` 在重启服务后的下次成功检查中接受其 SHA-256。通配符以及未明确指定 `bin_unpackaged` 的规则不会接受文件。后续哈希变化仍会触发 `bin_modified`。

```bash
serversecuritygo scan --full --min-risk INFO --format json --output /root/full-scan.json
```

`--full` 等待 PID 扫描及文件验证，支持取消。单次扫描和本地 TUI 读取服务基线，但不覆盖它们。快速 `scan` 会将这些检查保留为待执行状态，并返回代码 **3**，使用 `--fail-on none` 时也是如此；达到阈值的发现仍优先返回代码 1。`rootkit_unavailable`、`rootkit_sweep_pending`、`integrity_pending`、`integrity_unavailable` 和 `integrity_unverified` 也会使报告不完整，并在警告中显示，不受风险过滤器影响。完成的检查含时间戳（`rootkit_sweep_complete`、`integrity_complete`）。演示模式不会通过这些检查探测真实主机。

基线是首次观察时建立的本地信任，并非独立真实性验证。root 可以修改 MD5、[本地 dpkg 数据库](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html)和 SHA-256 基线。被入侵的内核也可以欺骗 procfs 与 sysfs。与独立可信 `.deb` 归档对照属于后续阶段。读取限制为：100,000 个 `/proc` 条目、16,384 个模块条目、每次 64 MiB 的 dpkg 元数据、每个待哈希文件 1 GiB。超限会报告检查不完整，而不会给出无异常结论。

## 扫描器自检

服务独立于扫描循环检查安装文件的完整性和扫描数据的新鲜度。结果显示在系统页面、概览警告、历史记录及 `scan` 报告中。自检不会修改服务器配置，也不会自动应用例外规则的变更。

| 检测项 | 含义 |
|---|---|
| `self_binary_changed` — CRITICAL | 启动时正在运行的二进制文件 SHA256 与安装基线不一致。Linux 读取 `/proc/self/exe`，即使文件路径已被替换，仍检查正在运行的文件。 |
| `self_unit_changed` — HIGH | `/etc`、`/run`、`/usr/local/lib`、`/usr/lib` 或 `/lib/systemd/system` 下的 `serversecuritygo.service`、`serversecuritygo.service.d/*.conf` 或通用 `service.d/*.conf` 发生修改、新增或删除。证据列出受影响路径。 |
| `self_baseline_changed` — HIGH | 启动后基线被修改；服务继续使用原始基线进行比较。 |
| `self_allowlist_changed` — MEDIUM | 例外文件被修改、新增或删除。仅保存路径和 SHA256，不将内容写入历史记录。已加载的规则持续生效至重启。 |
| `self_scan_stalled` — HIGH | 超过三个扫描间隔没有成功完成扫描，包括第一次扫描。失败的扫描不会更新成功时间。 |
| `self_clock_back` — MEDIUM | 两次检查之间，系统时间相对单调时钟后退超过一秒。警告保留至重启；扫描超时不受系统时间调整影响。 |
| `self_check_unavailable` — MEDIUM | 基线缺失或损坏、文件无法读取、类型不受支持或超出大小限制。这表示检查不完整，并不代表完整性已确认。 |

安装和更新在启动服务前原子写入 `/var/lib/serversecuritygo/self.sha256`，权限为 `600`。此固定路径不受 `SSG_DATA_DIR` 影响。回滚同时恢复原二进制文件和旧基线。服务本身不会创建或更新此基线。手动安装时，确认二进制文件及单元文件可信后，在项目目录中以 root 执行：

```bash
source scripts/lib.sh
write_self_baseline
systemctl restart serversecuritygo
```

此命令将当前文件接受为基线；应先查明变更原因，不能仅为消除警告而运行。校验和不能替代可信的发行签名，具有 root 权限的攻击者能够同时替换程序与基线。单元检查覆盖磁盘文件，包括被其他文件覆盖的配置，并不能证明 systemd 已加载这些配置。管理员的合法变更也需要核实。

观察器正常运行时，至少每五秒检查一次文件。例外文件必须是普通文件，不得使用符号链接，且不超过 1 MiB；规则加载也执行相同限制。观察状态保存在 `SSG_DATA_DIR/self-allowlist.json`，权限为 `600`，以检测重启之间的变更。单次 `scan` 和本地 TUI 仅使用内存，不修改服务状态；演示模式不检查实际安装。

`GET /api/status` 包含 `stale` 字段；首次扫描成功之前及数据过期时，`/healthz` 返回 `503`。完整性警告本身不会导致存活检查失败，应查看报告。自检不可用时，`scan` 返回不完整状态（退出码 `3`，除非风险结果优先触发退出码 `1`）；`--fail-on none` 也不会隐藏不完整状态。

单元启用 `WatchdogSec=30s` 和 `NotifyAccess=main`。扫描仍有效时发送本地 `WATCHDOG=1` 通知；通知停止后，systemd 只重启 ServerSecurityGo，不更改其他进程或网络。默认扫描间隔为 30 秒，超过 90 秒无成功结果后数据过期，再等待 watchdog 超时。协议参考：[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) 和 [sd_notify](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)。

## 风险评分方式

每条规则产生一个**指标**：一组说明读取了什么、从哪里读取的事实，例如 `/proc/3101/exe → /dev/shm/.x/kworkerds`。单个指标本身并不断定是否恶意。它有权重、类别，如果它单独出现时很少是合法的，还会带有“强”标记。

1. 权重之和决定基础等级：1 分起为 LOW，15 分起为 MEDIUM，35 分起为 HIGH，60 分起为 CRITICAL。
2. 等级受**独立类别数量**的限制（位置、文件完整性、伪装、启动链、网络、命令行、行为、环境、权限、持久化）：
   - 只有一个类别且没有强指标 —— 最高 **LOW**。因此仅凭名称、仅凭路径或仅凭高负载都不会超过 LOW；
   - 一个类别且有强指标 —— 最高 **MEDIUM**；
   - 两个类别且强指标少于两个 —— 最高 **HIGH**；
   - **CRITICAL** 需要三个或更多类别，或者两个强指标。
3. 信息类指标（运行在容器中、监听端口、权限不足）会显示，但不影响评分。
4. 白名单用于抑制已知合法进程的指标。被抑制的指标不会被隐藏：它以删除线显示，并在解释中注明。
5. 已知的合法情况会单独处理。被 `apt upgrade` 删除的 `/usr` 中的二进制文件只得 4 分而不是 20 分；通过 memfd 运行的 `runc` 权重降低；服务 stdout 上的 systemd journal Unix 套接字不会被视为反弹 shell；`node`、`java` 和 `python` 作为 shell 的父进程只产生弱指标。

进程卡片中的解释示例：

> Result CRITICAL: 102 point(s), indicators: 4, categories: 2 (command line, network), strong: 2. Triggered: “Shell or interpreter I/O is connected to a network socket” +40 (strong); “Command line contains a reverse shell construct” +35 (strong); … This is an assessment based on indirect indicators, not proof of compromise.

Web 面板和终端界面会以所选语言显示这段文字。

## 可检测的异常示例

所有示例都包含在演示数据（`serversecuritygo demo`）和自动化测试中。

| 场景 | 触发的指标 | 等级 |
|---|---|---|
| 位于 `/dev/shm/.x/` 的挖矿程序，`argv[0]="[kworker/u8:2]"`，连接到 3333 端口，CPU 持续高负载 | exe 位于临时目录、隐藏目录、伪装成内核线程、矿池端口、root 从可写目录运行、CPU 持续高负载 | CRITICAL |
| `nginx` → `sh -c 'bash -i >& /dev/tcp/…/4444 0>&1'` → fd 0/1/2 连接到 TCP 套接字的 `bash` | 网络服务启动了 shell、反弹 shell 结构、stdin/stdout 连接到套接字、shell 持有外部连接 | CRITICAL |
| 带 `LD_PRELOAD` 的 `/tmp/.ICE-unix/dbus-daemon (deleted)`，监听 `0.0.0.0:31337` | 临时目录、已删除的二进制文件、系统服务名但不在系统路径中、LD_PRELOAD、可疑监听 | CRITICAL |
| `cron` → `sh -c 'curl … \| sh'` | 下载后立即执行、计划任务运行下载内容 | HIGH |
| 从 `memfd:` 运行的进程（无文件执行） | 从内存运行 | MEDIUM |
| CPU 占用 95% 的编译器 | 只有持续高负载 | LOW |
| 软件包更新后的 `sshd`（`/usr/sbin/sshd (deleted)`） | 系统二进制文件已被替换 | LOW |
| 非空的 `/etc/ld.so.preload` | 全局预加载库 | HIGH（系统） |
| cron 任务 `curl … \| sh` | 可疑的自启动命令 | MEDIUM（系统） |
| 最近修改过的 `authorized_keys` | SSH 密钥最近被修改 | LOW（系统） |

可用于白名单的完整规则 ID 列表：
`exe_in_temp`、`exe_hidden_path`、`cwd_in_temp`、`exe_deleted`、`exe_memfd`、`exe_world_writable`、`exe_setuid_nonstd`、`exe_system_nonroot`、`kthread_masquerade`、`system_name_masquerade`、`name_mismatch`、`unusual_name`、`empty_cmdline`、`cmdline_truncated`、`unicode_control`、`web_spawns_shell`、`scheduler_suspicious`、`stdio_socket`、`revshell_pattern`、`download_exec`、`miner_pattern`、`miner_name`、`pool_port`、`shell_network`、`suspicious_listen`、`cpu_sustained`、`mem_sustained`、`ld_preload`、`root_from_writable`、`exposed_database`、`exposed_docker_api`、`exposed_admin_panel`、`exposed_remote_access`、`exposed_file_sharing`、`exposed_info_service`、`exposed_amplifier`。系统检查：`ld_so_preload`、`autostart_suspicious`、`autostart_temp`、`autostart_recent`、`ssh_key_command`、`ssh_keys_recent`、`ssh_keys_not_regular`、`fw_docker_bypass`、上面针对危险公网端口的 `exposed_*` ID，以及 `fail2ban_not_running`、`fail2ban_sshd_disabled`、`fail2ban_log_unavailable`、`steal_high`、`disk_almost_full`、`load_high`、`memory_pressure`、`oom_recent`、`net_syn_flood`、`net_listen_overflow`、`net_conn_flood_ip`、`net_conn_flood_subnet`、`net_conn_surge`、`net_conntrack_full`、`net_orphans_high`、`net_udp_flood`、`net_rx_drops`、`net_pps_surge`、`net_ddos_suspected`、`net_table_truncated`。

### 持久化、进程内存与 Docker 安全

持久化检查覆盖 `/etc/passwd` 中具有登录 shell 的用户，包括 `/home` 之外的主目录：shell 配置、cron/at/incron、systemd 服务/定时器/用户单元/drop-in/生成器、PAM、motd、udev、Xsession/autostart、SysV init、网络/apt/logrotate 钩子、SSH rc/config，以及 `/opt/*` 和 `/var/www/*` 下的 Git hooks。临时目录中的 PAM 命令评为 CRITICAL；不属于软件包的本地 systemd/SysV 文件属于清单信息。只有完整的本地 dpkg 索引才能支持“无软件包归属”的判断。标准目录中找不到的 PAM 模块引用为 INFO：可选模块可能未安装；实际存在但无软件包归属的模块仍为 HIGH。hosts 中的软件仓库域名覆盖需要核查；DNS 地址和空 shell 历史本身不能证明篡改。系统符号链接在被检查主机根目录内解析，并限制跳转次数。用户符号链接、读取失败或超限会使检查不完整。限制为每文件 1 MiB 和 4,096 行、每轮 32 MiB、每目录 4,096 项、20,000 个候选路径及 64 个 PAM 模块目录。

进程详情显示 TracerPid、具名的 CapEff/CapPrm/CapBnd/CapAmb、NoNewPrivs 和 Seccomp。可执行内存映射用于检查临时/已删除库和匿名可执行内存。已知 JIT 运行时降低权重；只有进程根目录中存在替代文件且主机软件包索引适用时，已删除库才降低权重。不同挂载命名空间不会继承主机的软件包归属。跟踪器关联要求 PID 与启动时间同时匹配。maps 限制为每进程 1 MiB、256 个不同可执行映射，每轮 32 MiB。environ 流式读取限制为每进程 8 MiB、每轮 32 MiB，每项仅分析前 4,096 字节。超限和拒绝访问均明确显示。仅保留环境信号，不保留变量值；`/proc/environ` 可能不反映 shell 启动后的变量更改。

Docker 检查读取 `config.v2.json` 与 `hostconfig.json`，支持自定义 `data-root`：每文件 2 MiB，总计 32 MiB，最多 4,096 个容器。检查 privileged、Docker socket、敏感主机挂载、额外 capabilities、主机命名空间、显式关闭 seccomp/AppArmor、配置的 root 用户、设备及疑似秘密的环境变量**名称**。支持 bind 字符串和结构化挂载。停止的容器标记为保存的配置。已知 Docker 管理镜像名称将 socket 信号降为 HIGH，但不证明可信。还检查 socket 权限及 docker 组成员；仅允许 root 的严格权限可接受。进程信号包含容器名称及镜像。这些是配置观察，不能验证实时隔离。应用从不调用 Docker API；containerd/Podman 安全元数据留待后续实现。

新增进程规则 ID：`ptrace_attached`, `lib_from_temp`, `lib_deleted`, `anon_exec_memory`, `history_disabled`, `prompt_command_net`, `ld_library_path_temp`, `proc_dangerous_caps`, `proc_ambient_caps`。
新增系统规则 ID：`systemd_unit_no_package`, `pam_exec`, `pam_module_unusual`, `library_search_path`, `sysv_no_package`, `shell_history_disabled`, `hosts_override`, `dns_configuration`, `persistence_unavailable`, `package_ownership_unavailable`, `ctr_privileged`, `ctr_docker_sock`, `ctr_host_root_mount`, `ctr_dangerous_caps`, `ctr_host_namespaces`, `ctr_no_seccomp`, `ctr_no_apparmor`, `ctr_runs_as_root`, `ctr_devices`, `ctr_secrets_in_env`, `ctr_sock_perms`, `container_unavailable`。系统信号显示在现有“系统”视图及报告中。新增进程规则支持 allowlist；`systemd_unit_no_package` 可用精确单元路径作为 `exe`。其他新增系统和 Docker 提示保持可见。

来源语义：[Linux proc 文档](https://docs.kernel.org/filesystems/proc.html)、[Docker 安全](https://docs.docker.com/engine/security/)及 [Docker seccomp](https://docs.docker.com/engine/security/seccomp/)。

## 检测局限

这是一个用于初步排查的启发式工具，不是杀毒软件，也不是 EDR。

- **内核级 rootkit** 可以直接在 `/proc` 中隐藏进程、文件和套接字。扫描器只能看到内核展示的内容。使用 `LD_PRELOAD` 和 `/etc/ld.so.preload` 的用户态 rootkit 不会影响扫描器本身（它是不依赖 libc 的静态 Go 二进制文件），但可能篡改 `ps`、`ls` 等工具的输出。
- **是快照，而不是事件。** 扫描每隔 `SSG_SCAN_INTERVAL`（默认 30 秒）运行一次，因此存活时间短于该间隔的进程可能被漏掉。要完整审计进程启动，需要 auditd 或 eBPF。
- **有限的文件分析。** 完整性检查覆盖选定的软件包文件；ELF 分析和可选的 Webshell 检查采用有资源限制的启发式方法。它们不会检查所有文件，也不提供通用恶意软件特征库。不使用外部 IP 信誉服务。命令行模式（`stratum+tcp`、`/dev/tcp/`）可以通过改名或混淆绕过。
- **权限。** 没有 root 权限时，无法读取其他用户进程的 exe、cwd、fd 和 environ。在 `/proc` 使用 `hidepid`、设置 `kernel.yama.ptrace_scope=3` 或使用严格的 AppArmor、SELinux 策略时也是如此。扫描器会在横幅和进程卡片中提示这一点。
- **容器。** 在容器内部，扫描器只能看到该容器的 PID 命名空间，因此请在宿主机上运行。容器内进程的 exe 和 cwd 路径是相对于容器文件系统的，因此与宿主机系统路径的比较可能不准确。
- **误报**可能出现在开发工具（从 `/tmp` 执行 `go run`、CI 构建）、位于非标准目录的自定义服务、合法挖矿以及 `curl | sh` 安装脚本上。白名单就是为这些情况准备的。
- **CPU%** 根据两次扫描之间 `utime+stime` 的差值计算，`CLK_TCK=100`，这是 Ubuntu 和 Debian 在 x86_64 和 arm64 上的取值。首次观察时显示的是自进程启动以来的平均值（以 `*` 标记）。
- 所有者未知的**套接字**（TIME_WAIT、内核套接字、权限不足）显示为“unknown”。如果一个套接字被多个进程共享（systemd 套接字激活、nginx 主进程和工作进程），“网络”表只显示找到的第一个所有者，而每张进程卡片会完整显示该套接字。
- **开放端口**仅根据套接字监听的地址和 ufw 判断。绑定在服务器自身内网地址上的服务（例如 AWS 或 GCP 上的 `172.31.5.10`）显示为*内网*，但在云服务商的 1:1 NAT 下，它可能仍可通过公网 IP 从互联网访问；请检查云服务商的安全组。直接通过 `iptables`/`nftables` 添加的规则、firewalld 和云防火墙都不会被读取。
- 旧内核缺少的字段（例如 4.1 之前没有 `NSpid`）不会导致错误，只是不显示相应信息。

## 测试环境

| 环境 | 验证内容 |
|---|---|
| Ubuntu 24.04.4 LTS，内核 6.8.0，x86_64，1 vCPU / 2 GB，Docker（测试 VPS） | 使用 README 中的命令安装；服务在 systemd 限制下运行（读取了所有进程的 exe、fd 和套接字，没有限制）；通过 SSH 隧道使用面板；`update.sh`、`rollback.sh` 和 `logs.sh`；重启后历史保留；密码登录；在没有密码或 TLS 的网络地址上拒绝启动；检测无害的模拟场景（从 `/tmp` 伪装成 kworker、启动后被删除的二进制文件、输入来自 TCP 套接字的 bash）；在 tmux 中以两种模式运行终端界面：自行扫描以及通过套接字连接服务（面板、进程树、过滤、详情、帮助） |
| GitHub Actions `ubuntu-latest` | 全部测试、以 root 运行的真实 `/proc` 测试、对运行器的一次性扫描、shellcheck |
| macOS | 基于伪造 `/proc` 的测试、演示模式、Chrome 中的 Web 面板 |

本程序尚未在 Debian 上运行过。它只依赖标准的 `/proc` 和 systemd 接口，但 Debian 上的测试尚待进行。新版本启动失败时 `update.sh` 的自动回滚尚未单独复现过。手动 `rollback.sh` 已经验证。

测试服务器上的负载（约 120 个进程）：一次扫描约 60 毫秒，服务占用约 12 MB 内存。

## 配置

所有变量及其详细注释（俄文）都列在 [`.env.example`](.env.example) 中。主要变量：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `SSG_LISTEN_ADDR` | `127.0.0.1:8090` | Web 面板地址（`off` 表示关闭面板，扫描继续运行）|
| `SSG_SOCKET_PATH` | `/run/serversecuritygo/api.sock` | 终端界面套接字（`off` 表示关闭） |
| `SSG_SCAN_INTERVAL` | `30s` | 扫描周期（最小 `2s`） |
| `SSG_ROOTKIT_INTERVAL` | `10m` | 完整 PID 扫描后的暂停时间（最少 `1m`） |
| `SSG_INTEGRITY_INTERVAL` | `24h` | 软件包完整性验证后的暂停时间（最少 `1m`） |
| `SSG_AUTH_PASSWORD_HASH` | — | 密码哈希（`serversecuritygo hash-password`） |
| `SSG_ALLOWED_HOSTS` | — | 网络访问时允许的主机名 |
| `SSG_TLS_CERT` / `SSG_TLS_KEY` | — | 内置 HTTPS |
| `SSG_TRUST_PROXY_TLS` | `false` | HTTPS 由反向代理终止 |
| `SSG_CPU_THRESHOLD` / `SSG_CPU_SUSTAIN_SCANS` | `80` / `10` | 高负载阈值和持续时间 |
| `SSG_HISTORY_RETENTION` | `168h` | 已退出进程数据的保留时间 |
| `SSG_ALLOWLIST_FILE` | `/opt/serversecuritygo/allowlist.json` | 白名单 |
| `SSG_LANG` | —（自动） | 默认语言：`ru` 或 `en` |
| `SSG_AUDIT_ENABLED` | `true` | 在服务中执行安全设置审计 |
| `SSG_AUDIT_INTERVAL` | `1h` | 审计的重复周期（最少 `1m`） |
| `SSG_AUTH_LOG_DAYS` | `14` | 分析多少天的 fail2ban 日志（1–365） |
| `SSG_METRICS_ENABLED` | `true` | 服务器指标采集（CPU、steal、内存、磁盘、网络） |
| `SSG_METRICS_INTERVAL` | `5s` | 指标采集周期（最小 `1s`） |
| `SSG_METRICS_RETENTION` | `720h` | 15 分钟聚合指标的保留时长 |
| `SSG_STEAL_THRESHOLD` | `10` | `steal_high` 发现的 steal 阈值（%） |
| `SSG_DISK_FULL_THRESHOLD` | `90` | `disk_almost_full` 的分区占用阈值（%） |
| `SSG_NET_CONN_PER_IP` | `200` | `net_conn_flood_ip` 的单地址连接数 |
| `SSG_NET_SURGE_FACTOR` | `5` | 超过常态多少倍算作激增 |
| `SSG_NET_TRUSTED_NETS` | — | 受信网络（CDN、代理）：不计为洪流来源 |
| `SSG_NET_MAX_SOCKETS` | `100000` | 每个网络命名空间的套接字上限 |

已退出进程的历史记录最多保留 4096 条，预算为 8 MiB（字符串及估算开销）。达到任一限制时删除最旧的已退出记录，并生成 `history_trimmed` 事件；活动进程仍会保留。Retention 是最长保留时间，不保证完整的历史深度。`state.json` 上限为 16 MiB：文件过大或不安全时启动将报错，原文件保持不变。移走该文件前请先备份。新命令行中的带引号赋值会被脱敏；已有数据和归档不会自动清理。

修改 `.env` 后，执行 `systemctl restart serversecuritygo`。

**白名单。** 将 [`allowlist.example.json`](allowlist.example.json) 复制到 `/opt/serversecuritygo/allowlist.json`。一条规则可以设置 `exe` 和 `name`（支持 `*` 和 `?` 通配符）、`user` 以及 `rules` 列表（指标 ID）。没有任何条件的规则会被忽略，以免意外抑制所有指标。进程可以自行设置名称（`comm`），因此没有 `exe` 的规则只有在名称同时与可执行文件名匹配时才生效：自称 `node` 的挖矿程序不会被 `{"name": "node"}` 覆盖。对于运行在解释器上的程序（例如运行在 Python 上的 `gunicorn`），请指定 `exe`。服务启动时会在日志中对没有 `exe` 的规则发出警告。

## 语言

用户看到的所有文字都提供英文和俄文版本：Web 面板和登录页、终端界面、指标标题、事实依据、评分解释、建议、历史事件、扫描警告、`scan` 和 `--help` 的输出、服务日志以及错误信息。目前没有中文界面。

- **Web 面板。** 页眉（以及登录页）中的 **English / Русский** 按钮可立即切换语言，选择会保存在浏览器中。在用户选择语言之前，面板使用 `SSG_LANG`；如果未设置，则使用浏览器语言（`Accept-Language`）。中文浏览器默认显示英文界面。
- **终端界面。** 按 `L` 键切换语言。初始语言为 `SSG_LANG`，否则取终端的 locale（`LC_ALL`、`LC_MESSAGES`、`LANG`）。中文 locale 默认使用英文。
- **命令行和服务日志。** 使用 `SSG_LANG`，否则使用 locale。locale 为空、`C` 或 `POSIX` 时（systemd 服务通常如此）输出为俄文，因此要得到英文服务日志，请在 `/opt/serversecuritygo/.env` 中设置 `SSG_LANG=en`。

扫描器把文字保存为消息（目录键和参数），由每个客户端用自己的语言渲染，因此两个用户可以同时用不同语言查看同一台服务器。翻译位于 [`internal/i18n`](internal/i18n)：`catalog_*.go` 中俄文和英文并排存放，测试会检查每个键都有两种翻译并且占位符一致。

**JSON API。** 文本字段（`title`、`evidence`、`recommendation`、`explanation`、`recommendations`、`warnings`、事件的 `details`）要么是普通字符串（来自系统的事实，例如路径），要么是消息对象 `{"key": "…", "args": […]}`（拼接文本为 `{"sep": "…", "parts": […]}`）。单一语言的目录可通过 `GET /i18n/en.json` 或 `/i18n/ru.json` 获取。`scan --format json` 输出的是以进程语言渲染好的文本，而不是消息对象。API 的错误信息语言取决于请求头 `X-SSG-Lang`。

## 远程访问

推荐使用 SSH 隧道（见上文）：不对外暴露任何端口。

如果需要直接访问，只有满足以下所有条件时服务才会启动：

1. 已设置密码：
   ```bash
   /opt/serversecuritygo/bin/serversecuritygo hash-password
   # 把输出的 SSG_AUTH_PASSWORD_HASH=... 这一行粘贴到 .env 中
   ```
2. 已设置用于打开面板的主机名：`SSG_ALLOWED_HOSTS=mon.example.com`。
3. 已启用 HTTPS：要么设置 `SSG_TLS_CERT` 和 `SSG_TLS_KEY`，要么使用带 HTTPS 的反向代理并设置 `SSG_TRUST_PROXY_TLS=true`。未启用程序自身的 TLS 时，必须监听 loopback（`127.0.0.1` 或 `[::1]`），即使设置了 `SSG_TRUST_PROXY_TLS=true` 也是如此。使用网络地址的后端需要在代理与程序之间启用 TLS。

nginx 示例：程序保持在 `127.0.0.1:8090`，由 nginx 通过 HTTPS 提供面板。在 `.env` 中设置 `SSG_TRUST_PROXY_TLS=true` 和密码。设置 `SSG_TRUST_PROXY_TLS=true` 时，没有密码服务将拒绝启动，因为它无法判断代理是否把它暴露到了互联网。

```nginx
server {
    listen 443 ssl;
    server_name mon.example.com;
    ssl_certificate     /etc/letsencrypt/live/mon.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mon.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host 127.0.0.1;
        # 用于登录限速的客户端地址：没有它，所有客户端
        # 看起来都是 127.0.0.1，共用一个计数器。
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

密码只以 PBKDF2-SHA256 哈希（600,000 次迭代）形式保存。连续五次登录失败后，来自该地址（IPv6 为该 /64 网段）的登录会被封锁 15 分钟。尝试次数在校验密码之前计数，因此并行请求无法绕过限制，并且同一时间最多校验两个密码。在反向代理之后，客户端地址取自代理设置的 `X-Forwarded-For`（见上面的示例）。会话保存在内存中，cookie 带有 `HttpOnly`、`SameSite=Strict` 和 `Secure` 标记。

你还可以用防火墙按 IP 限制访问，例如 `ufw allow from <你的 IP> to any port 443`。

## 更新与卸载

```bash
/opt/serversecuritygo/scripts/update.sh            # 更新到最新发布版
/opt/serversecuritygo/scripts/update.sh v0.2.0     # 更新到指定版本
/opt/serversecuritygo/scripts/rollback.sh          # 回到上次更新之前的版本
/opt/serversecuritygo/scripts/logs.sh              # 日志（最后 100 行，然后持续跟踪）
/opt/serversecuritygo/scripts/logs.sh -p warning --since today
/opt/serversecuritygo/scripts/uninstall.sh         # 删除服务，保留文件和历史
/opt/serversecuritygo/scripts/uninstall.sh --purge # 同时删除 /opt/serversecuritygo 和历史
/opt/serversecuritygo/scripts/uninstall.sh --full  # 完全卸载（见下文）
```

更新如何防止失败：

- 更新前，历史、`.env` 和 `allowlist.json` 会被归档到 `/var/backups/serversecuritygo`，保留最近 5 个归档；
- 新的二进制文件会先经过检查（`version`），旧的会保存为 `bin/serversecuritygo.prev`；
- 重启后会检查 `/healthz`；如果服务没有启动，会自动恢复之前的版本；
- 源码切换后，更新由新版本的脚本完成，因此新版本新增的步骤会立即生效。例外是从 v0.1.x 更新：那时新脚本还没有运行，因此需要手动创建链接 `/usr/local/bin/serversecuritygo`（`ln -sfn /opt/serversecuritygo/bin/serversecuritygo /usr/local/bin/serversecuritygo`），或者再执行一次 `update.sh`。

即使使用 `--purge`，备份也不会被删除。

**更新到 v0.3.0（英文界面）。** 照常运行 `update.sh` 即可；无需迁移，已有的历史会保留。更新之后：

- Web 面板以浏览器语言打开，页眉中有 **English / Русский** 切换按钮；在终端界面中按 `L` 切换语言；
- 服务日志仍为俄文，除非你在 `/opt/serversecuritygo/.env` 中添加 `SSG_LANG=en` 并执行 `systemctl restart serversecuritygo`；
- 如果你自己的脚本读取 JSON API，请注意文本字段现在可能是消息对象（见[语言](#语言)）；`scan --format json` 仍然输出普通文本。

### 完全卸载

这会把程序彻底移除，就像它从未安装在服务器上一样：服务及其在 systemd 中的痕迹、链接 `/usr/local/bin/serversecuritygo`、`/opt/serversecuritygo`、`/var/lib/serversecuritygo` 中的历史以及 `/var/backups/serversecuritygo` 中的备份。此操作无法撤销。

```bash
/opt/serversecuritygo/scripts/uninstall.sh --full -y
```

如果 `/opt/serversecuritygo` 已被删除或损坏，可以用一条命令在不依赖脚本的情况下完成同样的清理：

```bash
systemctl disable --now serversecuritygo 2>/dev/null; \
rm -rf /etc/systemd/system/serversecuritygo.service /etc/systemd/system/serversecuritygo.service.d; \
systemctl daemon-reload; systemctl reset-failed serversecuritygo 2>/dev/null; \
[ -L /usr/local/bin/serversecuritygo ] && rm -f /usr/local/bin/serversecuritygo; \
rm -rf /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo /run/serversecuritygo
```

该命令不会处理以下内容，原因如下：

- **`git`、`curl` 和 `ca-certificates` 软件包。** 安装脚本只在缺少时才会添加它们，但其他程序也需要它们。如果确定不再需要：`apt-get remove git curl`；
- **journald 记录。** 无法只删除某个服务的记录而不清空整个系统日志。它们会随着日志轮转自行消失。

确认没有残留：

```bash
systemctl status serversecuritygo        # Unit serversecuritygo.service could not be found.
ls -d /opt/serversecuritygo /var/lib/serversecuritygo /var/backups/serversecuritygo /usr/local/bin/serversecuritygo   # No such file or directory
```

服务状态：`systemctl status serversecuritygo`。

## 控制台模式与演示

一次性扫描，不影响服务的历史：

```bash
/opt/serversecuritygo/bin/serversecuritygo scan --env-file /opt/serversecuritygo/.env
/opt/serversecuritygo/bin/serversecuritygo scan --min-risk MEDIUM --sample 2s      # 两次采样得到准确的 CPU
/opt/serversecuritygo/bin/serversecuritygo scan --format json --min-risk INFO > scan.json
```

一次性检查安全设置（SSH、账户、sudo）；`--all` 同时显示已通过的检查：

```bash
/opt/serversecuritygo/bin/serversecuritygo audit
/opt/serversecuritygo/bin/serversecuritygo audit --format json > audit.json
```

**报告格式。** `scan` 和 `audit` 接受 `--format`：

| 格式 | 用途 |
|---|---|
| `text`（默认） | 终端 |
| `json` | 脚本和 Ansible：带 `schema_version`、`verdict`、`incomplete` 的稳定结构 |
| `html` | 服务器所有者：单个自包含文件（内置 CSS、无脚本、亮色和暗色主题），包含结论、概要、发现和建议 |
| `md` | 文档或工单：Markdown 表格，所有来自系统的内容都已转义 |

`--output 文件` 把报告写入权限为 600 的文件（报告中包含命令行和路径），而不是输出到屏幕。文件以原子方式替换；拒绝写入符号链接，而对 `/dev/null` 这类设备则直接写入：

```bash
serversecuritygo audit --format html --output /root/audit.html
serversecuritygo scan --format md --output /root/scan.md
```

**退出码**便于从 cron、CI、Ansible 或监控系统运行检查：

| 退出码 | 含义 |
|---|---|
| `0` | 没有 `--fail-on` 级别及以上的发现 |
| `1` | 有 `--fail-on` 级别及以上的发现（默认 `HIGH`） |
| `2` | 错误：完全无法读取 `/proc`、配置损坏、参数错误 |
| `3` | 没有这样的发现，但检查不完整：部分数据无法读取（请以 root 运行） |

`--fail-on` 接受 `LOW`、`MEDIUM`、`HIGH`、`CRITICAL` 或 `none`。发现优先于不完整：即使部分数据没有读取，也返回退出码 1。`--fail-on none` 使退出码与发现无关（只剩 2 和 3）。**对现有脚本的提示：** 以前 `scan` 总是以 0 退出；现在有 HIGH 或 CRITICAL 发现时以 1 退出——需要旧行为时请加上 `--fail-on none`。对 `scan` 来说，级别是进程或系统发现的最高风险（`--min-risk` 只过滤输出）；对 `audit` 来说，是状态为“危险”或“警告”的检查的最高严重程度。

```bash
# 每天 6:00：把审计报告写入文件，有问题时由 cron 发邮件
0 6 * * * /opt/serversecuritygo/bin/serversecuritygo audit --fail-on HIGH --format md --output /root/audit.md || echo "安全设置需要注意：/root/audit.md"
```

使用虚构数据的演示模式可在 Linux 和 macOS 上运行：

```bash
go run ./cmd/serversecuritygo demo --tui   # 在终端中
go run ./cmd/serversecuritygo demo         # 在浏览器中：http://127.0.0.1:8090
```

## 构建与测试

下列命令在模拟 `/proc` 数据和临时磁盘历史上执行有时限的重复测试，检查事件数量稳定性及历史重新加载。它不评估真实环境中的检测准确率，也不能代替对运行服务的长期观察。测试目录自动清理。普通测试套件执行 30 次迭代，不等待。

```bash
SSG_TEST_SOAK_DURATION=20m go test ./internal/scanner -run '^TestDiagnosticStability$' -count=1 -timeout 25m -v
```

需要 Go 1.27.4 或更高版本；没有外部模块。

```bash
make build        # 为当前系统构建 bin/serversecuritygo
make build-linux  # dist/serversecuritygo-linux-{amd64,arm64} + SHA256SUMS
make test         # go test -race ./...
make vet          # gofmt + go vet
```

测试使用伪造的 `/proc` 树（`internal/fakeproc`），因此可在任何操作系统上通过。在 Linux 上，`TestRealProc` 还会读取真实的 `/proc`。每次 push 和 pull request 时，GitHub Actions 会在 Ubuntu 上运行测试、以 root 运行 `/proc` 测试、对运行器做一次性扫描、对脚本运行 shellcheck 并进行交叉编译。推送 `v*` 标签会构建发布版。

## 项目结构

```
cmd/serversecuritygo/     入口：tui（默认）、serve、scan、demo、hash-password、version
internal/
  procfs/                 读取 /proc：stat、status、cmdline、exe、fd、ns、cgroup、net
  detect/                 规则、风险评分、解释、白名单、系统检查
  exposure/               开放端口：可达范围、危险服务、ufw、Docker 发布的端口
  audit/                  安全设置审计：sshd_config、账户、sudoers；后台运行
  netload/                网络负载：按端口的半开连接、来源、/proc/net 计数器、带持续判定的攻击发现
  metrics/                服务器指标：CPU 与 steal、负载、PSI、内存、分区、磁盘、网络；环形缓冲与 metrics.json
  fail2ban/               fail2ban：jail 配置、日志解析（含 .gz）、当前封禁、暴力破解统计
  report/                 scan 和 audit 报告：文本、JSON、HTML、Markdown；退出码
  safefile/               安全读取攻击者可能控制的文件（不跟随符号链接、拒绝 FIFO、限制大小）
  redact/                 遮蔽命令行中的密钥
  history/                进程历史和事件日志（state.json、events.jsonl）
  scanner/                周期性扫描：收集 → 分析 → 历史
  web/                    HTTP 服务器、认证、API；static/ 中是内嵌的 Web 面板
  i18n/                   英文和俄文翻译、消息类型、语言检测
  tui/                    终端界面（无外部库：termios、ANSI、鼠标）
  view/                   Web 面板和终端界面共用的数据视图
  config/                 来自环境变量的设置
  fakeproc/               用于测试和演示数据的伪造 /proc
  model/                  共享的数据结构
deploy/serversecuritygo.service   加固的 systemd 单元
scripts/                  install.sh、update.sh、rollback.sh、uninstall.sh、logs.sh、lib.sh
.env.example              带注释的全部设置
allowlist.example.json    白名单示例
.github/workflows/        CI 和发布
```

API（JSON，用于自动化；文本字段的格式见[语言](#语言)）：`GET /api/status`、`/api/processes`、`/api/process/{key}`、`/api/tree`、`/api/connections`、`/api/exposure`、`/api/audit`、`/api/fail2ban`、`/api/metrics?range=1h|24h|30d`、`/api/netload`、`/api/events?limit=N`、`/api/system`、`POST /api/rescan` 和 `POST /api/audit/run`（需带上来自 `/api/status` 的 `X-CSRF-Token` 请求头）、`GET /healthz`。

## 安全

- 只读：代码中没有终止进程、删除文件或修改网络规则的调用。
- 终端界面通过权限为 `600`、位于 `700` 目录中的 Unix 套接字获取数据。文件权限本身就是授权，因此只有 root 能连接。进程名和命令行中的控制字符永远不会写入终端，因此进程名无法在你的终端中执行转义序列。
- 默认情况下，Web 面板只监听 `127.0.0.1`。没有密码、`SSG_ALLOWED_HOSTS` 和 HTTPS 时，网络地址不会启动。
- 未设置密码时，面板只对 `SSG_LOCAL_UIDS` 中列出的用户开放（默认是 root）：每个回环连接的所有者都会在 `/proc/net/tcp` 中查找，其他人一律收到 403。否则任何本地用户都能读取服务以 root 身份收集的内容：其他用户进程的路径、打开的文件和套接字，以及检查结果。
- `Host` 请求头检查防御 DNS rebinding，CSRF 令牌保护每个 POST 请求，CSP 禁止内联脚本。进程名和命令行只以纯文本渲染，因此攻击者无法通过自己进程的名称注入 HTML。
- 命令行中的密钥会在分析、存储和输出**之前**被遮蔽：`--password=…`、mysql 的 `-pPASSWORD`、URL 中的 `user:pass@`、`*_TOKEN=…`、AWS 和 GitHub 密钥、JWT、机器人令牌。环境变量的值永远不会进入历史。密码、cookie 和命令行永远不会写入日志。
- 服务以 root 身份运行（否则看不到其他用户的进程），但权限受到削减：只有 `CAP_SYS_PTRACE` 和 `CAP_DAC_READ_SEARCH`。除 `/var/lib/serversecuritygo` 外，文件系统对服务是只读的；服务以 `NoNewPrivileges` 和系统调用过滤器运行，并受 `MemoryMax=256M` 和 `CPUQuota=50%` 限制。

## 参与贡献

非常欢迎参与贡献！我们感谢任何错误报告、误报报告、想法和 pull request。

- 开始之前，请阅读[贡献指南](CONTRIBUTING.md#english)和[行为准则](CODE_OF_CONDUCT.md#english)（英文）。
- 报告错误和提出建议，请[创建 issue](https://github.com/Zagorsky17/ServerSecurityGo/issues/new/choose)；我们提供了模板。issue 可以用英文或俄文撰写。
- **请不要在公开 issue 中报告漏洞。** 报告方式见 [SECURITY.md](SECURITY.md#english)。

## 许可证

MIT，见 [LICENSE](LICENSE)。

### 登录记录与事件调查

**登录**面板读取本地 SSH、sudo/su、账户变更事件、wtmp/btmp/utmp 和稀疏 lastlog 文件。SSH SHA256 指纹与用户的 `authorized_keys` 匹配；失败尝试按 IP、用户和小时汇总。服务将已见 IP 保存到 `auth-state.json`，首次导入建立基线，不把所有地址都标为新地址。保留期限取 `SSG_AUTH_LOG_DAYS` 与 `SSG_HISTORY_RETENTION` 中较短者。`SSG_AUTH_LOG_ENABLED=false` 关闭此采集器。

**时间线**面板和 `/api/timeline?since=48h` 合并进程历史、登录事件和最近文件元数据。`/api/logins` 使用与其他 API 相同的身份验证。ctime 是 inode 变更时间，不是创建时间；chmod/chown 和软件包维护也会改变它。旧 mtime 与新 ctime 的差异仅供调查，不证明时间被伪造。软件包更新窗口是近似关联，不会抑制发现。

文件元数据由独立的每小时工作任务收集，不会阻塞进程扫描或 watchdog 心跳。首次扫描完成前，时间线会明确显示等待状态。

```sh
serversecuritygo triage --format html --output /root/triage.html
serversecuritygo triage --full --format json --output /root/triage.json
serversecuritygo timeline --since 48h --format md --output /root/timeline.md
serversecuritygo recent --days 3 --format json --output /root/recent.json
serversecuritygo collect --output /var/backups/serversecuritygo/evidence.tar.gz
```

`triage` 包含进程扫描、配置审计、认证记录、最近文件和十项优先检查，附带经过 shell 引用处理的验证命令。`--full` 等待 PID 遍历、选定 dpkg 文件校验及有界 SUID/capabilities 清单。验证命令只展示，不执行。报告支持 text/JSON/HTML/Markdown 及现有 `--fail-on` 退出码。`SSG_HOST_ROOT` 指向磁盘镜像且使用默认 `/proc` 时，调查命令排除分析机器的实时进程，并明确说明无法进行的实时检查。单次命令不写入服务历史或登录基线。

`collect` 创建新归档，拒绝覆盖，要求私有目标目录（700），归档及其文件权限为 600。内容包括进程、网络、审计数据，受限的持久化配置与日志副本，maps、**所有值均被省略的环境变量名称**，可执行文件 SHA256，以及可访问的已删除/memfd 可执行文件副本。`/proc/PID/exe` 是唯一有意允许的文件符号链接例外；程序会复查 PID 身份与文件元数据。`MANIFEST.sha256` 包含已保存文件的哈希，`collection.json` 记录遗漏，CLI 同时输出归档 SHA256。不要执行采集的二进制文件。采集仅通过 CLI 提供，网页不启用采集或归档下载接口。

默认总预算为 500 MiB（`SSG_COLLECT_MAX_MB`），每个可执行文件 50 MiB（`SSG_COLLECT_MAX_BINARY_MB`），限时三分钟。总预算限制压缩输出、未压缩成员和可执行文件读取；单个配置或日志文件限制为 2 MiB。私钥、shadow/gshadow 和 `.env` 被排除，文本中识别出的秘密被遮盖。归档仍包含个人数据和可能敏感的命令，必须私密保存。清单只能核验已捕获字节的一致性，不能证明主机可信，也不是文件系统的原子快照。

认证读取受字节和记录数量限制：最多 5,000 个事件和密钥，固定 auth.log 轮换文件（`.1`、`.2.gz`）。不可用或超限的数据源会明确报告不完整。支持 glibc 小端 amd64 与 arm64 记账格式；不会猜测未知镜像架构。二进制 journald 解析留待后续，因此没有 auth.log 的主机认证可见性有限。无法可靠推断密钥选项、自定义 `AuthorizedKeysFile`、journal 清理意图和所有轮换方案。journal 大幅缩小或 shell 历史被禁用需要人工核查；空日志本身不证明删除。最近文件遍历限制为 100,000 个路径、10,000 个结果或十秒，不遍历符号链接。服务每小时刷新元数据；时间线只包含可用且仍被保留的观察记录。

新增发现 ID：`login_new_ip`、`login_password_root`、`login_after_bruteforce`、`login_unusual_time`、`login_service_account`、`log_wtmp_truncated`、`log_wtmp_gap`、`log_authlog_truncated`、`log_history_null`、`log_journal_vacuum`、`log_utmp_missing`。服务账户认证在未确认终端时为 LOW，匹配到会话 TTY 时为 HIGH。同一 IP 十分钟内至少十次失败后成功登录会被标记；共享 NAT 和管理员活动也可能解释该现象。内核遭入侵后，本地检查不能恢复信任，应保留磁盘镜像并在独立环境分析。

记账格式于 2026-11-16 对照 [glibc utmp 定义](https://github.com/bminor/glibc/blob/master/bits/utmp.h)及 [aarch64 ABI 定义](https://github.com/bminor/glibc/blob/master/sysdeps/aarch64/bits/wordsize.h)核对。Linux CI 将 C 生成的记账记录与 Go 解析器进行比较，并从独立测试进程采集已删除的可执行文件。

### 发现详情、加固审计与基线比较

进程、系统和审计详情包含原因、正常场景、验证命令、建议、MITRE ATT&CK 上下文，以及最近 2,000 条记录中最多八条相关事件。进程按 PID 与启动时间关联，文件按路径关联。ATT&CK 和软件包归属不能证明入侵或完整性；程序不会执行显示的命令。

审计新增内核加固、临时目录挂载与敏感权限、SUID/SGID 和文件 capabilities、重启标记、同类型较新内核、APT 数据时间、unattended-upgrades、发行版支持期限及保存的防火墙配置。`audit --full` 等待文件清单；快速审计明确报告清单缺失。未知状态也包括不支持的语法和无法读取的数据源。运行中的内核规则及云提供商防火墙未经验证；待安装安全更新计数和 netlink 规则读取仍留待后续阶段。

独立文件扫描默认每六小时执行一次，每秒 2,000 个路径。配置项为 `SSG_FS_SCAN_INTERVAL`、`SSG_FS_SCAN_RATE`，以及逗号分隔的 `SSG_FS_SCAN_EXCLUDE` 和额外挂载根目录 `SSG_FS_SCAN_MOUNTS`。默认覆盖根文件系统与 `/dev/shm`，不跨越其他文件系统、不跟随符号链接；排除 `/proc`、`/sys`、`/dev`（`/dev/shm` 除外）、`/run`、Docker/容器存储以及网络/FUSE 挂载。限制为 200 万路径、10,000 个特权文件/发现、128 层和 30 分钟。超限、取消或读取失败均明确标记不完整。首个完整清单保存在 `baseline.json`，新增权限生成 `fs_privilege_new`。软件包归属不是可信签名。新增 ID：`fs_suid_inventory`、`fs_capabilities`、`fs_world_writable_system`、`fs_unowned`、`fs_privilege_new`、`fs_inventory_pending`、`fs_inventory_unavailable`、`new_public_listener`、`ports_baseline_unavailable`。

每次文件扫描完成后，服务自动刷新四项相关检查：`fs_world_writable_system`、`fs_unowned`、`fs_suid_inventory` 和 `fs_capabilities`。本地 TUI 同样适用。刷新复用已收集的清单，不重新扫描文件，也不重读其他配置。定时及手动完整审计保持可用。执行串行化，通知合并，同一报告不会重复处理。清单不完整且没有已确认的危险发现时保持 `unknown`；已发现的 HIGH/CRITICAL 问题仍为 `fail`。

Web 和 TUI 分别显示完整审计时间、所用文件清单的采集开始时间及其在配置范围内的完整性，以便判断数据年龄；完整审计时间不代表文件数据同样新。在服务 API 中，`inventorySource` 包含 `ready`、`time` 和 `incomplete`；审计及摘要中的 `updatedAt` 在部分刷新后也会改变，触发 TUI 更新缓存。不含这些字段的旧服务仍然兼容，但无法单独显示数据源时间。此机制不新增外部请求或配置项。

```sh
serversecuritygo audit --full --format json --output /root/audit.json
serversecuritygo baseline save --name before-upgrade
serversecuritygo baseline list
serversecuritygo diff --from before-upgrade --to now --format json --output /root/diff.json
serversecuritygo baseline accept --ports
```

快照保存在 `SSG_DATA_DIR/baselines`，目录权限 700、文件权限 600，命名快照禁止覆盖。保存及与 `now` 比较会等待有界文件扫描。内容包括本地用户/组、公网监听端口及其进程文件、保存的 systemd 单元/服务、SUID/SGID、capabilities、默认 authorized_keys 指纹、模块名称、选定关键程序的哈希及审计状态。不保存密码哈希、密钥材料、密钥注释或单元内容。比较要求相同 machine-id，且仅比较完整、范围一致的部分；不可读数据不会产生虚假的删除结论。这是分时采集的观察结果，不是原子快照或独立的主机可信证明。

安装创建 `installation`；升级后的服务在首次获得清单且该快照不存在时创建它。每周自动保存快照，保留最近 12 个，手动命名快照不删除。Web/TUI 的“Changes”和 `/api/changes` 每小时更新，使用最新文件清单（通常可滞后六小时）。七天视图使用截止点之前最近的快照，并显示实际比较时间；历史不足时显示缺失信息。

完整的初始公网端口清单确定预期的协议、地址、端口和进程文件组合。新组合触发 HIGH `new_public_listener` 与 `listen` 事件。审核后执行 `baseline accept --ports` 仅更新预期清单，服务一分钟内加载；必须拥有完整套接字表和已知进程文件。无法确定所有者的 Docker 发布端口等情况会阻止接受。此操作不修改防火墙，也不抑制其他发现。

离线支持表于 2026-11-18 根据 [Ubuntu](https://ubuntu.com/project/docs/release-team/list-of-releases/) 和 [Debian](https://www.debian.org/releases/) 核对，区分 Ubuntu 标准支持、Debian LTS 与需管理员确认的 Pro/ESM/ELTS。文件 capabilities 遵循 [Linux 格式](https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h)，支持版本 1–3。

### 变化优先级与判断依据

系统列表先显示 CRITICAL，再显示未被抑制的 `new_public_listener`、`fs_privilege_new` 和 `ssh_keys_recent`，其余发现按风险排列。**Change — review first** 只决定审核顺序，不提高风险等级，也不证明攻击。快照比较优先显示端口、SSH 密钥、SUID/SGID 和 capabilities 的变化；不完整或范围不兼容的部分不会生成这些差异。

Web 和 TUI 卡片分别显示观察事实、风险与后果、可信依据与限制、验证命令。`fs_privilege_new` 显示变化前后的权限；基线特权文件列表中没有记录，不代表文件本身以前不存在。软件包归属不会消除警告。`ssh_keys_recent` 仅依据 mtime，不能确认密钥变化：应将指纹与批准的密钥和完整且兼容的快照核对。新的公网监听也不能证明外部可达。

可信说明描述依据与限制，不给出攻击概率百分比。命令仅展示，路径经过 shell 引号转义。`explain` 也输出这些说明。JSON 在发现上下文中增加 `reviewFirst` 和 `confidence`，在快照变化中增加 `reviewFirst`。旧服务的数据不包含新增说明和标记。

### 允许列表审核、学习模式和新增检测

进程发现卡片中的 **This is legitimate** 提供限定可执行文件、用户和规则 ID 的 JSON 片段。`"exact": true` 防止文件名中的 `*`、`?`、`[` 被解释为通配符。请审核后自行将规则合并到现有允许列表；复制不会更改任何配置。CRITICAL 进程、强信号、信息性发现和已抑制发现不会生成建议。系统发现与审计没有自动允许列表操作。

`SSG_LEARNING_HOURS=0` 默认关闭学习；1–168 小时用于收集待审核候选。候选要求至少三次观察、跨度至少五分钟、进程风险不高于 LOW，且发现权重不超过 10。当前扫描仍须满足条件；升至 HIGH/CRITICAL 或出现强信号会移除候选。首次学习窗口和计数保存在 `learning.json`，重启后继续；修改设置不会重新开始窗口。学习不会降低评分、接受基线或编辑允许列表。 审核候选后，面板还提供只读的 `baseline save` 命令文本，用于保存当前整个系统的命名快照；它不会接受端口或抑制检测。**Learning** 面板、`/api/learning` 和 TUI 显示候选及范围过宽规则的警告。30 个日历日没有匹配到观察结果的规则会提示审核；停机时间也计入，因此不能据此认定规则过时。状态最多包含 1000 个候选和 1000 条规则使用记录；损坏状态会保留并提示错误。

新增 ID：`bpf_unexpected`、`raw_packet_socket`、`iface_promisc`、`exe_packed`、`exe_static_in_temp` 和可选的 `webshell_pattern`。eBPF 仅从可见进程描述符及 `fdinfo` 读取，不能枚举所有内核程序或确认挂载状态。AF_PACKET 表按 inode 关联可见描述符所有者；本程序不捕获数据包。已知软件包工具、root 所有且组和其他用户不可写的可执行文件会降低相关评分，但软件包归属不能证明完整性。混杂模式也用于网桥和虚拟化。现有独立类别评分继续生效；单个强类别不能独自使进程达到 HIGH。

ELF 检查在启动时和每小时独立运行：最多 256 个不同可执行文件，每文件 32 MiB、总计 64 MiB、一分钟工作预算。缓存要求相同进程代次、路径、设备/inode、ctime、大小和 mtime，且不超过两小时。尚未检查的新进程或已变化进程会明确标记为覆盖不完整。UPX 检测要求 ELF 架构、加载器/程序头和文件末尾附近带校验和的打包头相互一致（`upx-header`）。仅有 `UPX!` 字符串或 `UPX` 节名称不会提高风险。支持打包头版本 11–14，末尾最多允许 8 KiB 零填充；修改过或不支持的布局可能漏检。匹配后仍需核实文件来源；仅高熵属于 INFO。文件不会被执行或解包。eBPF 每进程最多读取 128 个描述符、每扫描 2048 个；AF_PACKET 每扫描最多 128 个命名空间和 10000 行。缺失覆盖使用 `advanced_pending`、`advanced_process_pending`、`advanced_unavailable`、`packet_inventory_unavailable`、`promisc_unavailable` 表示。

网页木马检查默认关闭：`SSG_WEBSHELL_ENABLED=false`。开启后，仅在观察到 nginx、Apache/httpd 或 PHP-FPM 时运行。读取本地配置中的静态 `root`/`DocumentRoot` 路径及 `/var/www`，检查 `SSG_WEBSHELL_DAYS` 天内修改的 `.php`、`.jsp`、`.aspx`；默认 7 天，范围 1–365。限制为 32 个根路径、100000 个路径、每内容文件 1 MiB、内容总量 16 MiB、1000 条发现；配置查找最多 256 个文件，每个 256 KiB。不跟随符号链接；变量路径不受支持并会报告不完整；容器内部路径可能不可见。发现仅包含模式 ID，不包含源代码或提取的秘密。INFO/MEDIUM 匹配需要人工审核，合法管理代码也可能匹配。与 `web_spawns_shell` 的关联只提供上下文，不证明该文件触发执行。

### SARIF 与安装诊断

```sh
serversecuritygo scan --full --format sarif --output /root/scan.sarif --min-risk INFO
serversecuritygo audit --full --format sarif --output /root/audit.sarif
serversecuritygo triage --full --format sarif --output /root/triage.sarif
serversecuritygo explain exe_memfd
serversecuritygo explain kern_aslr --format json
serversecuritygo doctor --format json --output /root/doctor.json
```

SARIF 2.1.0 是 `scan`、`audit`、`triage` 的本地导出，包含规则 ID、级别、转义文件 URI、`properties.attack` 中的 ATT&CK ID、明确的允许列表抑制和运行不完整状态。审计通过、信息性、未知和不适用结果分别表示。原有退出码和风险过滤仍然有效。程序不会上传报告或连接外部集成；报告文件权限为 600。

`explain` 只读取内置规则和检查目录，不扫描主机；参考文本中的 `{N}` 由具体发现提供数值。`doctor` 只读取安装路径及权限、systemd 主单元文件、最多 32 个其他进程的样本、auth.log 可用性、内核版本和 dpkg 元数据，不执行命令或修改权限。它不能证明服务就绪、已加载单元及 drop-in 正确、可访问全部 PID 或已修复 CVE；建议文本说明后续核查。通过 `SSG_HOST_ROOT` 检查磁盘映像时，不会默默使用工作站默认的 `/proc`。网页和 TUI 进程搜索包含规则 ID、用户、容器及本地/远程端口。

### 文件发现分组

“System”部分按目录和 UID/GID 将重复的 `fs_unowned` 发现分组。此标识表示 UID 或 GID 未出现在本地 `/etc/passwd` 和 `/etc/group` 中，不表示文件没有软件包归属，也不能单独证明系统已被入侵。分组目录最多取父路径的前三层，例如 `/usr/local/include/node/a.h` 归入 `/usr/local/include`。不同风险级别和抑制状态分别显示；单条记录、无法识别的证据格式及其他发现类型仍保留独立行。

在网页中点击组标题查看原始发现，通过表格上方的按钮返回分组。在 TUI 中按 Enter 打开文件列表，再按 Enter 查看所选文件详情；在文件列表按左箭头或 Esc 返回分组。`/` 搜索所有原始路径、发现 ID、风险级别和证据，包括 UID/GID。`y` 复制分组目录或所选文件路径，`Y` 复制该组或单条发现的 JSON；可复制的数据量受终端剪贴板容量限制。数据刷新时，只要该组仍存在，就保留当前打开的组。

分组仅改变显示方式，原始发现、历史、风险评级和 CLI 报告均保留。`GET /api/system` 的 `findings` 数组仍包含全部发现；新增 `groups` 数组包含 `key`（不透明标识）、`directory`、`owner` 和 `indices`，其中索引从零开始，指向同一响应中的 `findings`。TUI 连接旧服务时也能生成分组；网页在缺少 `groups` 时显示原有列表。

### 大型报告刷新

系统发现、审计、UFW 和快照比较支持带 `ETag` / `If-None-Match` 的条件 GET。未变化的报告返回无正文的 `304`，Web 与 TUI 复用已解析数据。缓存仅驻留内存，HTTP 响应仍为 `Cache-Control: no-store`。服务端只保留五种表示各自的最新版本（完整/简要系统报告、审计、UFW、变化），每种 JSON 上限 8 MiB；更大的响应不保存在服务端缓存中。不可变源结构也保留到缓存替换时。事实、警告、审计状态或数据完整性变化时，即使完整审计时间不变，响应也会更新。

Web 使用 `/api/system?summary=1` 获取风险、标题、ID 和路径。点击 **Details** 后，通过 `/api/system/detail?index=N&revision=REVISION` 获取事实、建议和命令；参数来自列表响应。如果报告已变化，服务端返回 `409` 并提示刷新列表。完整 `/api/system` 继续供 TUI 和其他客户端使用。TUI 首次获取完整报告，之后使用条件请求；进程卡片仍在选择进程时加载。不支持 ETag 或简要表示的旧服务继续传输完整数据。

每次刷新仍获取 `/api/status`。`304` 仅表示报告未变化，不代表扫描数据仍然新鲜；过期数据、不完整来源和连接错误会明确显示。Web 自动刷新时不重建未变化的表格，但更新摘要；筛选、排序和语言切换仍会重绘。动态进程、事件和指标不使用此缓存。
