package baseline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

func section(scope string) model.BaselineSection {
	return model.BaselineSection{Scope: scope, Complete: true, Items: map[string]string{}}
}
func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func Capture(ctx context.Context, hostRoot, procRoot string, snap *model.Snapshot, audit *model.AuditReport) *model.BaselineSnapshot {
	b := &model.BaselineSnapshot{Version: 1, Time: time.Now(), Sections: map[string]model.BaselineSection{}}
	root, e := os.OpenRoot(hostRoot)
	if e != nil {
		return b
	}
	defer root.Close()
	read := func(p string, limit int64) ([]byte, error) {
		n, e := safefile.ResolveRooted(root, strings.TrimPrefix(p, "/"))
		if e != nil {
			return nil, e
		}
		v, _, e := safefile.ReadRooted(root, n, limit)
		return v, e
	}
	if id, e := read("/etc/machine-id", 4096); e == nil && len(strings.TrimSpace(string(id))) == 32 {
		b.Host = hash([]byte(strings.TrimSpace(string(id))))
	}
	for _, name := range []string{"users", "groups"} {
		s := section("local-files-v1")
		p := "/etc/passwd"
		fields := 7
		if name == "groups" {
			p = "/etc/group"
			fields = 4
		}
		data, e := read(p, 1<<20)
		if e != nil {
			s.Complete = false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			v := strings.Split(line, ":")
			if len(v) != fields || v[0] == "" {
				s.Complete = false
				continue
			}
			if _, e := strconv.ParseUint(v[2], 10, 32); e != nil {
				s.Complete = false
				continue
			}
			if _, dup := s.Items[v[0]]; dup {
				s.Complete = false
			}
			s.Items[v[0]] = strings.Join(v[2:], ":")
		}
		b.Sections[name] = s
	}
	units := section("saved-systemd-units-v1")
	services := section("saved-systemd-services-v1")
	count := 0
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system"} {
		n, e := safefile.ResolveRooted(root, strings.TrimPrefix(dir, "/"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			units.Complete = false
			continue
		}
		e = fs.WalkDir(root.FS(), strings.TrimPrefix(n, "/"), func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			count++
			if count > 20000 {
				return fs.SkipAll
			}
			if err != nil {
				units.Complete = false
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Type() != 0 && d.Type()&os.ModeSymlink == 0 {
				return nil
			}
			key := "/" + p
			data, e := read(key, 1<<20)
			if e != nil {
				units.Complete = false
				return nil
			}
			units.Items[key] = hash(data)
			if strings.HasSuffix(p, ".service") {
				services.Items[key] = units.Items[key]
			}
			return nil
		})
		if e != nil || count > 20000 {
			units.Complete = false
		}
	}
	services.Complete = units.Complete
	b.Sections["units"] = units
	b.Sections["services"] = services
	binaries := section("critical-binaries-v1")
	for _, p := range []string{"/bin/bash", "/bin/sh", "/bin/ls", "/bin/ps", "/bin/systemctl", "/usr/bin/sudo", "/usr/sbin/sshd", "/usr/bin/ss", "/usr/bin/top", "/usr/bin/lsof"} {
		if ctx.Err() != nil {
			binaries.Complete = false
			break
		}
		data, e := read(p, 64<<20)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			binaries.Complete = false
			continue
		}
		binaries.Items[p] = hash(data)
	}
	b.Sections["binaries"] = binaries
	modules := section("proc-modules-names-v1")
	data, _, e := safefile.ReadRegular(filepath.Join(procRoot, "modules"), 4<<20, true)
	if e != nil {
		modules.Complete = false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 6 {
			modules.Complete = false
			continue
		}
		modules.Items[f[0]] = "loaded"
	}
	b.Sections["modules"] = modules
	keys := section("default-authorized-keys-v1")
	keys.Complete = snap != nil && snap.Auth != nil && !snap.Auth.Incomplete
	if snap != nil && snap.Auth != nil {
		for _, k := range snap.Auth.Keys {
			keys.Items[k.Path+"|"+k.Fingerprint] = k.User
		}
	}
	b.Sections["ssh_keys"] = keys
	for _, name := range []string{"suid", "capabilities"} {
		s := section("filesystem-unavailable")
		s.Complete = false
		if snap != nil && snap.Inventory != nil {
			s.Scope = snap.Inventory.Scope
			s.Complete = !snap.Inventory.Incomplete
			for _, f := range snap.Inventory.Files {
				if name == "suid" && (f.SUID || f.SGID) {
					s.Items[f.Path] = fmt.Sprintf("uid=%d gid=%d suid=%t sgid=%t", f.UID, f.GID, f.SUID, f.SGID)
				}
				if name == "capabilities" && (f.Permitted|f.Inheritable != 0) {
					s.Items[f.Path] = fmt.Sprintf("permitted=%x inheritable=%x effective=%t rootid=%d", f.Permitted, f.Inheritable, f.Effective, f.RootID)
				}
			}
		}
		b.Sections[name] = s
	}
	b.Sections["ports"] = Ports(procRoot, snap)
	checks := section("audit-status-v1")
	checks.Complete = audit != nil
	if audit != nil {
		for _, c := range audit.Checks {
			checks.Items[c.ID] = c.Status + ":" + c.Severity.String()
			if c.Status == model.AuditUnknown {
				checks.Complete = false
			}
		}
	}
	b.Sections["audit"] = checks
	return b
}
func Ports(procRoot string, snap *model.Snapshot) model.BaselineSection {
	s := section("public-listeners-address-protocol-binary-v1")
	if snap == nil || snap.Exposure == nil {
		s.Complete = false
		return s
	}
	s.Complete = snap.Stats.Restricted == 0 && len(snap.Exposure.Warnings) == 0
	if !procfs.NetTablesComplete(procRoot) || snap.Exposure.Incomplete {
		s.Complete = false
	}

	// Multiple owners of one endpoint are retained, independently of PID reuse.
	values := map[string][]string{}
	for _, p := range snap.Exposure.Entries {
		if p.Scope != model.ScopePublic {
			continue
		}
		if p.Exe == "" {
			s.Complete = false
			continue
		}
		key := PortKey(p)
		values[key] = append(values[key], p.Exe)
	}
	for k, v := range values {
		sort.Strings(v)
		var unique []string
		for _, x := range v {
			if len(unique) == 0 || unique[len(unique)-1] != x {
				unique = append(unique, x)
			}
		}
		data, _ := json.Marshal(unique)
		s.Items[k] = string(data)
	}
	return s
}
func PortKey(p model.Exposure) string { return fmt.Sprintf("%s %s:%d", p.Proto, p.Addr, p.Port) }
