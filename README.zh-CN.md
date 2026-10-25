# ServerSecurityGo

[English](README.md) | [Русский](README.ru.md) | **简体中文**

[![CI](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml/badge.svg)](https://github.com/Zagorsky17/ServerSecurityGo/actions/workflows/ci.yml)
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
  - [安全设置](#安全设置)
  - [fail2ban](#fail2ban)
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
2. 如果已安装 Go 1.24 或更高版本，则从源码构建二进制文件；否则从 [GitHub Releases](https://github.com/Zagorsky17/ServerSecurityGo/releases) 下载预编译的二进制文件并校验其 SHA256。服务器上不需要安装 Go。
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
| 历史 | `/var/lib/serversecuritygo`（权限 700）：`state.json`、`events.jsonl` |
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

左侧有八个面板：概要、可疑进程、所有进程（列表或树形）、网络连接、开放端口、安全设置、历史和系统检查。如果安装了 fail2ban，会在历史之前出现第九个面板 fail2ban，其后面板的编号随之顺延。右侧显示所选条目的详细信息：风险评分及其解释、带事实依据的指标、建议、命令行、启动链、套接字、打开的文件以及进程历史。按 `L` 可在英文和俄文之间切换界面语言。

| 按键 | 作用 |
|---|---|
| `1`…`8`（有 fail2ban 时为 `9`）、`Tab` / `Shift+Tab` | 切换面板 |
| `↑` `↓` / `j` `k`、`PgUp` `PgDn`、`g` `G` | 选择行；在详情中滚动 |
| `Enter` / `→`、`Esc` / `←` | 进入详情并返回 |
| `/` | 按名称、PID、路径、用户、指标或风险等级过滤面板 |
| `s`、`t`、`K` | 排序进程（风险、CPU、内存、PID、名称）、树形视图、内核线程 |
| `r`、`p` | 立即扫描（在“设置”面板上为立即检查设置）、暂停自动刷新 |
| `y`、`Y` | 把命令行（在“设置”面板上为修复命令，在 fail2ban 面板上为解封命令）或 JSON 复制到你电脑的剪贴板（OSC 52，可通过 SSH 使用） |
| `+` | 将当前一侧放大到全屏 |
| `L` | 界面语言：英文 / 俄文 |
| `?`、`q` | 帮助、退出 |

也可以使用鼠标：单击选择面板和行，滚轮滚动。

**数据来源。** 如果服务正在运行，界面会通过 Unix 套接字 `/run/serversecuritygo/api.sock` 连接到服务。只有 root 能访问该套接字，因此不需要密码或隧道，并且可以看到已收集的完整历史。如果服务没有运行，或者安装的是没有套接字的旧版本，界面会自己扫描进程，此时历史只在本次会话中保留。数据来源显示在“概要”面板中。

```bash
serversecuritygo tui --local            # 始终自行扫描
serversecuritygo tui --refresh 2s       # 更频繁地刷新屏幕
```

要查看所有用户的进程，请以 root 身份运行界面。在服务模式下，数据已由服务收集。

如果 `y` 复制不起作用：iTerm2、kitty、WezTerm、Alacritty、Windows Terminal 和较新的 xterm 支持 OSC 52。在 tmux 中需要设置 `set -g set-clipboard on`。

## 可选的 Web 面板

Web 面板在浏览器中展示相同的数据。它只监听 `127.0.0.1:8090`。要从自己的电脑打开，请使用 SSH 隧道：

```bash
ssh -L 8090:127.0.0.1:8090 root@<服务器 IP>
# 然后在浏览器中打开 http://127.0.0.1:8090
```

如果使用专用密钥连接，请加上 `-i ~/.ssh/<密钥> -o IdentitiesOnly=yes`。

在未设置密码时，服务只允许 root 进入面板：对每个到 `127.0.0.1` 的连接，它都会在 `/proc/net/tcp` 中查找套接字的所有者。以 root 身份打开的隧道可以使用，而服务器上的其他用户（例如被入侵的 `www-data`）会收到 403 错误。如果你以自己的用户身份通过 SSH 登录，请把该用户的 UID 加入 `SSG_LOCAL_UIDS`（例如 `0,1000`），或者设置密码。

## 功能

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

系统持久化检查覆盖 `/etc/ld.so.preload`、cron（`/etc/crontab`、`/etc/cron.*`、`/var/spool/cron`）、`/etc/systemd/system` 中的 systemd 单元、`/etc/rc.local`、`/etc/init.d`、`/etc/profile.d`、`.bashrc`、`update-motd.d` 和 `authorized_keys`。

**终端界面**见[上文](#终端界面)。**Web 面板**（浅色和深色主题）：

1. **可疑进程** —— 带有指标的进程，按风险排序。每一行显示指标、分数、首次和最近一次观察时间以及一条建议。
2. **所有进程** —— 搜索、按任意列排序，可按 PID/PPID、用户、名称、路径和最低风险等级过滤。
3. **进程树** —— 父子关系，可折叠分支，高亮匹配项。
4. **网络** —— 套接字及其所属进程，可按协议、状态和外部地址过滤。
5. **开放端口** —— 服务器监听了什么，以及从哪里可以访问；见[开放端口](#开放端口)。
6. **安全设置** —— SSH、账户和 sudo 的审计；见[安全设置](#安全设置)。
7. **历史** —— 进程启动和退出，exe、cmdline 或用户的变化，风险升高和降低，新指标，新的监听端口，系统发现，安全设置的变化。
8. **系统** —— 服务器信息、扫描限制（权限、容器）、持久化检查和危险的开放端口。
9. **进程卡片** —— 收集到的所有数据、评分解释、每个指标背后的事实、建议、祖先链、子进程、套接字、打开的文件和进程历史。可以复制命令行和 JSON 格式的卡片，也可以直接链接到某张卡片（`#p=<key>`）。

面板每 5 到 60 秒自动刷新一次，也可以关闭自动刷新。打开进程卡片时自动刷新会暂停。

### 开放端口

VPS 被入侵最常见的真实原因，是某个服务意外监听在 `0.0.0.0` 上：没有密码的 Redis、MongoDB、Docker API、管理面板。**开放端口**标签页（终端界面中的面板 `5`、`GET /api/exposure`、`serversecuritygo scan` 输出末尾的表格）列出每个监听的 TCP 套接字和已绑定的 UDP 套接字：

- **可达范围**：*公网*（下列范围以外的任何地址，包括 `0.0.0.0` 和 `::`，即所有接口，旁边会列出服务器的公网地址）、*内网*（`10/8`、`172.16/12`、`192.168/16`、`100.64/10`、`fc00::/7`、链路本地地址）、*仅本机*（`127.0.0.0/8`、`::1`）或*容器内*（套接字位于自己的网络命名空间中，外部只能通过已发布的端口访问）；
- 所属进程、用户和容器；对于 Docker，还有容器名称、镜像和端口映射；
- 从内置表中**识别出的服务**：Redis、Docker API、MongoDB、Elasticsearch/OpenSearch、etcd、kubelet、Jupyter、memcached、PostgreSQL、MySQL/MariaDB、RabbitMQ、CouchDB、SMB、RDP、VNC、Telnet、FTP、rpcbind、NFS、SNMP、Prometheus exporter。服务根据端口和进程名（或容器镜像）识别；仅凭端口号匹配时等级降低一级，因为该端口上可能是别的程序；
- 该端口的 **ufw** 状态：*开放*（有允许任意地址的规则）、*已阻止*（ufw 已启用，且未对所有人开放该端口）或*绕过 ufw*。

等级表示服务可被访问的危险程度，而不是被入侵的迹象：可从互联网访问的 Redis 为 CRITICAL，PostgreSQL 为 HIGH，Prometheus exporter 为 LOW。如果 ufw 阻止了该端口，等级降为 LOW，并注明只有防火墙在保护该服务。每个危险的公网端口都会成为带有该等级的系统发现（显示在“系统”标签页、历史和日志中），并在占用该端口的进程卡片中成为 `exposure` 类别的指标。该指标不是“强”指标：单独出现时，合法进程的等级最高为 LOW。

**Docker 绕过 ufw。** Docker 会把自己的 iptables 规则插在 ufw 规则之前，所以 `ufw deny 6379` 无法关闭以 `-p 6379:6379` 发布的端口。如果 ufw 已启用，而某个容器端口在所有接口上发布、且没有允许它的 ufw 规则，面板会报告 `fw_docker_bypass`（HIGH），并建议以 `127.0.0.1:端口:端口` 的形式发布，或在 `DOCKER-USER` 链中加以限制。已发布的端口从 `docker-proxy` 的参数和容器的 `config.v2.json` 中读取，因此在 `userland-proxy: false` 时也能看到。不使用 Docker API：它的套接字等同于 root 权限，而观察者不需要它。

如果某个端口是有意开放的，可以为该进程添加带指标 ID 的白名单规则（例如 `{"exe": "/usr/lib/postgresql/16/bin/postgres", "rules": ["exposed_database"]}`）：进程指标和系统发现都会显示为已抑制，不再计入。没有监听进程、由 Docker 发布的端口（`userland-proxy: false`）无法用这种方式抑制。

### 安全设置

大多数 VPS 入侵并不是通过零日漏洞，而是通过密码登录、多余的 `NOPASSWD: ALL` 或被遗忘的用户。**安全设置**标签页（终端界面中的面板 `6`、`GET /api/audit`、`serversecuritygo audit` 命令）检查的是配置——入侵的原因，而不是入侵的痕迹。

服务在启动时立即执行审计，之后每隔 `SSG_AUDIT_INTERVAL`（默认 1 小时）执行一次。**立即检查**按钮（终端界面中在该面板上按 `r`）会马上运行审计，例如在你修复问题之后；检查进行中时不会启动新的检查。标签页显示上次检查的时间和通过数量：“通过 N / M”只统计结果为通过、危险或警告的检查（建议、不适用和未知不计入）。

每项检查都有结果（*通过*、*危险*、*警告*、*建议*、*不适用*——例如未安装 sshd、*未知*——没有读取权限）、严重程度、带文件和行号的事实（`/etc/ssh/sshd_config.d/50-cloud-init.conf:1 PasswordAuthentication yes`）、建议，通常还有现成的修复命令。应用程序从不执行命令：由你自己运行。修改 SSH 之前，请先在另一个会话中确认密钥登录可用。

| 分组 | 检查 |
|---|---|
| SSH | `ssh_root_login`、`ssh_password_auth`、`ssh_empty_passwords`、`ssh_kbd_interactive`（即使 `PasswordAuthentication no`，也可通过 PAM 输入密码）、`ssh_max_auth_tries`、`ssh_x11_forwarding`、`ssh_tcp_forwarding`（`GatewayPorts`）、`ssh_weak_crypto`（CBC、3DES、RC4、MD5、SHA-1、DSA）、`ssh_authkeys_file`（非标准密钥文件或 `AuthorizedKeysCommand`）、`ssh_host_keys_perms`、`ssh_config_perms`，以及建议项 `ssh_allow_users`、`ssh_banner_version`、`ssh_port` |
| 账户 | `acct_uid0_extra`、`acct_empty_password`、`acct_service_shell`、`acct_weak_hash`（MD5、DES）、`acct_new`、`acct_priv_groups`（`sudo`、`admin`、`wheel`、`docker`、`lxd`、`disk`、`adm`、`shadow`）、`acct_duplicate_ids`、`acct_passwd_perms`、`acct_home_perms`、`acct_root_path` |
| sudo | `sudo_nopasswd_all`（对云镜像默认用户 `ubuntu`、`debian`、`admin` 等为 MEDIUM）、`sudo_no_auth`、`sudo_gtfobins`（`vim`、`less`、`find`、`systemctl` 等可轻易获得 root shell 的程序）、`sudo_wildcard`、`sudo_writable_cmd`、`sudo_env_keep`（`LD_PRELOAD`、`PYTHONPATH`、`!env_reset`）、`sudo_files_perms`、`sudo_changed` |

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
`exe_in_temp`、`exe_hidden_path`、`cwd_in_temp`、`exe_deleted`、`exe_memfd`、`exe_world_writable`、`exe_setuid_nonstd`、`exe_system_nonroot`、`kthread_masquerade`、`system_name_masquerade`、`name_mismatch`、`unusual_name`、`empty_cmdline`、`cmdline_truncated`、`unicode_control`、`web_spawns_shell`、`scheduler_suspicious`、`stdio_socket`、`revshell_pattern`、`download_exec`、`miner_pattern`、`miner_name`、`pool_port`、`shell_network`、`suspicious_listen`、`cpu_sustained`、`mem_sustained`、`ld_preload`、`root_from_writable`、`exposed_database`、`exposed_docker_api`、`exposed_admin_panel`、`exposed_remote_access`、`exposed_file_sharing`、`exposed_info_service`。系统检查：`ld_so_preload`、`autostart_suspicious`、`autostart_temp`、`autostart_recent`、`ssh_key_command`、`ssh_keys_recent`、`ssh_keys_not_regular`、`fw_docker_bypass`、上面针对危险公网端口的 `exposed_*` ID，以及 `fail2ban_not_running`、`fail2ban_sshd_disabled`、`fail2ban_log_unavailable`。

## 检测局限

这是一个用于初步排查的启发式工具，不是杀毒软件，也不是 EDR。

- **内核级 rootkit** 可以直接在 `/proc` 中隐藏进程、文件和套接字。扫描器只能看到内核展示的内容。使用 `LD_PRELOAD` 和 `/etc/ld.so.preload` 的用户态 rootkit 不会影响扫描器本身（它是不依赖 libc 的静态 Go 二进制文件），但可能篡改 `ps`、`ls` 等工具的输出。
- **是快照，而不是事件。** 扫描每隔 `SSG_SCAN_INTERVAL`（默认 30 秒）运行一次，因此存活时间短于该间隔的进程可能被漏掉。要完整审计进程启动，需要 auditd 或 eBPF。
- **不分析文件内容：** 没有特征码、哈希或 IP 信誉库。命令行模式（`stratum+tcp`、`/dev/tcp/`）通过模板匹配，可以通过改名或混淆绕过。
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
| `SSG_LISTEN_ADDR` | `127.0.0.1:8090` | Web 面板地址 |
| `SSG_SOCKET_PATH` | `/run/serversecuritygo/api.sock` | 终端界面套接字（`off` 表示关闭） |
| `SSG_SCAN_INTERVAL` | `30s` | 扫描周期（最小 `2s`） |
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
3. 已启用 HTTPS：要么设置 `SSG_TLS_CERT` 和 `SSG_TLS_KEY`，要么使用带 HTTPS 的反向代理并设置 `SSG_TRUST_PROXY_TLS=true`。第二种情况下最好让程序保持在 `127.0.0.1` 上。

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

需要 Go 1.24 或更高版本；没有外部模块。

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

API（JSON，用于自动化；文本字段的格式见[语言](#语言)）：`GET /api/status`、`/api/processes`、`/api/process/{key}`、`/api/tree`、`/api/connections`、`/api/exposure`、`/api/audit`、`/api/fail2ban`、`/api/events?limit=N`、`/api/system`、`POST /api/rescan` 和 `POST /api/audit/run`（需带上来自 `/api/status` 的 `X-CSRF-Token` 请求头）、`GET /healthz`。

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
