package exposure

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// Значения Env отбрасываются при декодировании и никогда не попадают в отчёт.
type envNames []string

func (e *envNames) UnmarshalJSON(b []byte) error {
	var entries []string
	if err := json.Unmarshal(b, &entries); err != nil {
		return err
	}
	for _, entry := range entries {
		name, _, ok := strings.Cut(entry, "=")
		if ok && envName.MatchString(name) && len(name) <= 128 {
			*e = append(*e, strings.Clone(name))
		}
	}
	clear(entries)
	return nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var secretName = regexp.MustCompile(`(?i)PASSWORD|SECRET|TOKEN|KEY`)
var blockDevice = regexp.MustCompile(`^/dev/(sd[a-z]+[0-9]*|vd[a-z]+[0-9]*|xvd[a-z]+[0-9]*|nvme[0-9]+n[0-9]+(p[0-9]+)?|mmcblk[0-9]+(p[0-9]+)?|mem|kmem)$`)

type mountConfig struct {
	Type, Source, Destination string
	RW                        bool
}
type hostConfig struct {
	Privileged                                bool
	CapAdd, CapDrop                           []string
	NetworkMode, PidMode, IpcMode, UsernsMode string
	SecurityOpt, Binds                        []string
	Mounts                                    []struct {
		Type, Source, Target string
		ReadOnly             bool
	}
	Devices        []struct{ PathOnHost, PathInContainer, CgroupPermissions string }
	ReadonlyRootfs bool
}

var containerMessages = map[string][2]string{
	"ctr_privileged":        {"rule.ctr_privileged.title", "rule.ctr_privileged.rec"},
	"ctr_docker_sock":       {"rule.ctr_docker_sock.title", "rule.ctr_docker_sock.rec"},
	"ctr_host_root_mount":   {"rule.ctr_host_root_mount.title", "rule.ctr_host_root_mount.rec"},
	"ctr_dangerous_caps":    {"rule.ctr_dangerous_caps.title", "rule.ctr_dangerous_caps.rec"},
	"ctr_host_namespaces":   {"rule.ctr_host_namespaces.title", "rule.ctr_host_namespaces.rec"},
	"ctr_no_seccomp":        {"rule.ctr_no_seccomp.title", "rule.ctr_no_seccomp.rec"},
	"ctr_no_apparmor":       {"rule.ctr_no_apparmor.title", "rule.ctr_no_apparmor.rec"},
	"ctr_runs_as_root":      {"rule.ctr_runs_as_root.title", "rule.ctr_runs_as_root.rec"},
	"ctr_devices":           {"rule.ctr_devices.title", "rule.ctr_devices.rec"},
	"ctr_secrets_in_env":    {"rule.ctr_secrets_in_env.title", "rule.ctr_secrets_in_env.rec"},
	"ctr_sock_perms":        {"rule.ctr_sock_perms.title", "rule.ctr_sock_perms.rec"},
	"container_unavailable": {"rule.container_unavailable.title", "rule.container_unavailable.rec"},
}

func containerFinding(id, path string, risk model.Risk, facts ...string) model.SystemFinding {
	keys := containerMessages[id]
	return model.SystemFinding{Path: path, Risk: risk, Finding: model.Finding{ID: id, Title: i18n.T(keys[0]), Category: model.CatExposure, Weight: Weight(risk), Evidence: i18n.Ls(facts), Recommendation: i18n.T(keys[1])}}
}

func containerChecks(c containerConfig, h hostConfig) []model.SystemFinding {
	path := "docker:" + c.ID
	findings := map[string]model.SystemFinding{}
	add := func(id string, risk model.Risk, facts ...string) {
		f, ok := findings[id]
		if !ok {
			f = containerFinding(id, path, risk, strings.TrimPrefix(c.Name, "/")+" ("+c.Config.Image+")")
			if !c.State.Running {
				f.Evidence = append(f.Evidence, i18n.T("ev.container_stopped"))
			}
		}
		f.Risk = max(f.Risk, risk)
		f.Weight = Weight(f.Risk)
		for _, s := range facts {
			if len(f.Evidence) < 12 {
				f.Evidence = append(f.Evidence, i18n.L(s))
			}
		}
		findings[id] = f
	}
	if h.Privileged {
		add("ctr_privileged", model.RiskCritical)
	}
	user, _, _ := strings.Cut(c.Config.User, ":")
	uid, uidErr := strconv.ParseUint(user, 10, 32)
	if user == "" || user == "root" || (uidErr == nil && uid == 0) {
		add("ctr_runs_as_root", model.RiskLow)
	}
	for _, name := range c.Config.Env {
		if secretName.MatchString(name) {
			add("ctr_secrets_in_env", model.RiskInfo, name)
		}
	}
	mount := func(source string, ro bool) {
		if !filepath.IsAbs(source) {
			return
		}
		source = filepath.Clean(source)
		if source == "/var/run/docker.sock" || source == "/run/docker.sock" {
			risk := model.RiskCritical
			switch ImageBase(c.Config.Image) {
			case "traefik", "portainer", "portainer-ce", "watchtower":
				risk = model.RiskHigh
			}
			add("ctr_docker_sock", risk, source)
		}
		for _, sensitive := range []string{"/", "/etc", "/root", "/var/lib/docker", "/proc", "/sys", "/dev", "/boot"} {
			if source == sensitive || (sensitive != "/" && strings.HasPrefix(source, sensitive+"/")) {
				risk := model.RiskCritical
				mode := "rw"
				if ro {
					risk = model.RiskHigh
					mode = "ro"
				}
				add("ctr_host_root_mount", risk, source+" ("+mode+")")
				break
			}
		}
	}
	for _, bind := range h.Binds {
		fields := strings.Split(bind, ":")
		if len(fields) < 2 {
			continue
		}
		ro := false
		if len(fields) > 2 {
			ro = slices.Contains(strings.Split(fields[2], ","), "ro")
		}
		mount(fields[0], ro)
	}
	for _, m := range h.Mounts {
		if m.Type == "bind" {
			mount(m.Source, m.ReadOnly)
		}
	}
	for _, m := range c.MountPoints {
		if m.Type == "bind" {
			mount(m.Source, !m.RW)
		}
	}
	for _, cap := range h.CapAdd {
		cap = strings.TrimPrefix(strings.ToUpper(cap), "CAP_")
		if slices.Contains([]string{"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN", "SYS_RAWIO"}, cap) {
			add("ctr_dangerous_caps", model.RiskHigh, cap)
		}
	}
	for _, ns := range []struct {
		name, value string
		risk        model.Risk
	}{{"network", h.NetworkMode, model.RiskMedium}, {"pid", h.PidMode, model.RiskHigh}, {"ipc", h.IpcMode, model.RiskMedium}, {"user", h.UsernsMode, model.RiskMedium}} {
		if ns.value == "host" {
			add("ctr_host_namespaces", ns.risk, ns.name+"=host")
		}
	}
	for _, opt := range h.SecurityOpt {
		opt = strings.Replace(opt, ":", "=", 1)
		if opt == "seccomp=unconfined" {
			add("ctr_no_seccomp", model.RiskHigh)
		}
		if opt == "apparmor=unconfined" {
			add("ctr_no_apparmor", model.RiskHigh)
		}
	}
	for _, d := range h.Devices {
		if blockDevice.MatchString(filepath.Clean(d.PathOnHost)) {
			add("ctr_devices", model.RiskCritical, d.PathOnHost)
		}
	}
	out := make([]model.SystemFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b model.SystemFinding) int { return strings.Compare(a.ID, b.ID) })
	return out
}

type dockerData struct {
	bindings   []model.PortBinding
	findings   []model.SystemFinding
	containers []containerConfig
	warnings   []i18n.Msg
}

func readDockerData(hostRoot string, security bool) dockerData {
	var out dockerData
	if hostRoot == "" {
		hostRoot = "/"
	}
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		out.warnings = append(out.warnings, i18n.T("warn.docker_unreadable", err.Error()))
		return out
	}
	defer root.Close()
	issue := func(path string) {
		if len(out.warnings) < 12 {
			out.warnings = append(out.warnings, i18n.T("warn.container_metadata", path))
		}
		if len(out.findings) == 0 || out.findings[len(out.findings)-1].ID != "container_unavailable" {
			out.findings = append(out.findings, containerFinding("container_unavailable", path, model.RiskInfo))
		}
	}
	dataRoot, rootErr := dockerRootPath(root)
	if rootErr != nil {
		issue("/etc/docker/daemon.json")
	}
	dir, err := filepath.Rel(hostRoot, filepath.Join(hostRoot, dataRoot, "containers"))
	if err != nil {
		issue("docker:data-root")
		return out
	}
	entries, err := safefile.ReadDirRooted(root, dir, maxContainers)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		resolved, e := safefile.ResolveRooted(root, dir)
		if e != nil {
			err = e
		} else {
			dir = resolved
			entries, err = safefile.ReadDirRooted(root, dir, maxContainers)
		}
	}
	if err != nil {
		if errors.Is(err, safefile.ErrTooLarge) {
			out.warnings = append(out.warnings, i18n.T("warn.docker_too_many", maxContainers))
		}
		if !errors.Is(err, os.ErrNotExist) {
			issue(dir)
		}
		if security {
			out.findings = append(out.findings, dockerSocketChecks(root)...)
		}
		return out
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	budget := int64(32 << 20)
	for _, entry := range entries {
		if !isContainerID(entry.Name()) {
			continue
		}
		name := filepath.Join(dir, entry.Name(), "config.v2.json")
		data, _, err := safefile.ReadRooted(root, name, min(budget, maxContainerConfig))
		budget -= int64(len(data))
		if err != nil {
			issue(name)
			continue
		}
		var c containerConfig
		err = json.Unmarshal(data, &c)
		if err != nil || c.ID != entry.Name() {
			clear(data)
			issue(name)
			continue
		}
		out.bindings = append(out.bindings, ParseContainerConfig(data)...)
		clear(data)
		if !security {
			continue
		}
		out.containers = append(out.containers, c)
		hostName := filepath.Join(dir, entry.Name(), "hostconfig.json")
		data, _, err = safefile.ReadRooted(root, hostName, min(budget, maxContainerConfig))
		budget -= int64(len(data))
		if err != nil {
			issue(hostName)
			continue
		}
		var h hostConfig
		err = json.Unmarshal(data, &h)
		clear(data)
		if err != nil {
			issue(hostName)
			continue
		}
		out.findings = append(out.findings, containerChecks(c, h)...)
	}
	if security {
		out.findings = append(out.findings, dockerSocketChecks(root)...)
	}
	slices.SortFunc(out.bindings, func(a, b model.PortBinding) int {
		if a.HostPort != b.HostPort {
			return a.HostPort - b.HostPort
		}
		if a.Proto != b.Proto {
			return strings.Compare(a.Proto, b.Proto)
		}
		if a.HostIP != b.HostIP {
			return strings.Compare(a.HostIP, b.HostIP)
		}
		return strings.Compare(a.ContainerID, b.ContainerID)
	})
	return out
}

func dockerSocketChecks(root *os.Root) []model.SystemFinding {
	var out []model.SystemFinding
	gid := -1
	data, _, _ := safefile.ReadRooted(root, "etc/group", 1<<20)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && f[0] == "docker" {
			gid, _ = strconv.Atoi(f[2])
			if f[3] != "" {
				out = append(out, containerFinding("ctr_sock_perms", "/etc/group:docker", model.RiskMedium, "docker: "+f[3]))
			}
		}
	}
	for _, path := range []string{"run/docker.sock", "var/run/docker.sock"} {
		fi, err := root.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			out = append(out, containerFinding("container_unavailable", "/"+path, model.RiskInfo))
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		mode := fi.Mode().Perm()
		if fi.Mode()&os.ModeSocket == 0 || st.Uid != 0 || mode&0007 != 0 || (mode&0070 != 0 && int(st.Gid) != gid) || mode&0111 != 0 {
			out = append(out, containerFinding("ctr_sock_perms", "/"+path, model.RiskMedium, fmt.Sprintf("%04o uid=%d gid=%d", mode, st.Uid, st.Gid)))
		}
		break
	}
	return out
}
