// Пакет collect создаёт ограниченный архив улик и никогда не запускает собранные файлы.
package collect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/procfs"
	"github.com/Zagorsky17/ServerSecurityGo/internal/redact"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

type Options struct {
	HostRoot, ProcRoot, Output, Version string
	MaxBytes, MaxBinaryBytes            int64
	Now                                 time.Time
}
type Result struct {
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	Incomplete bool     `json:"incomplete"`
	Warnings   []string `json:"warnings"`
}
type entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func cleanText(b []byte) []byte { return []byte(redact.Text(string(b))) }
func excluded(p string) bool {
	for _, part := range strings.Split(p, "/") {
		s := strings.ToLower(part)
		if s == "shadow" || s == "gshadow" || s == ".env" || strings.HasPrefix(s, ".env.") || strings.HasPrefix(s, "id_") && !strings.HasSuffix(s, ".pub") || strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") || strings.Contains(s, "history") && !strings.HasPrefix(p, "var/log/apt/") {
			return true
		}
	}
	return false
}
func Create(ctx context.Context, opt Options, snap *model.Snapshot, audit *model.AuditReport) (res Result, err error) {
	if snap == nil {
		return res, os.ErrInvalid
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.MaxBytes <= 0 || opt.MaxBinaryBytes <= 0 || opt.MaxBytes > 4<<30 || opt.MaxBinaryBytes > 1<<30 {
		return res, i18n.Errorf("err.collect_limit")
	}
	if opt.HostRoot == "" {
		opt.HostRoot = "/"
	}
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	if opt.Output == "" {
		opt.Output = filepath.Join("/var/backups/serversecuritygo", "triage-"+safeName(snap.Host.Hostname)+"-"+opt.Now.UTC().Format("20060102T150405.000000000Z")+".tar.gz")
	}
	dir := filepath.Dir(opt.Output)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return res, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return res, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return res, i18n.Errorf("err.collect_dir", dir)
	}
	outRoot, err := os.OpenRoot(dir)
	if err != nil {
		return res, err
	}
	defer outRoot.Close()
	base := filepath.Base(opt.Output)
	f, err := outRoot.OpenFile(base, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return res, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	done := false
	defer func() {
		f.Close()
		if !done {
			outRoot.Remove(base)
		}
	}()
	root, err := os.OpenRoot(opt.HostRoot)
	if err != nil {
		return res, err
	}
	defer root.Close()
	digest := sha256.New()
	limited := &limitWriter{w: io.MultiWriter(f, digest), left: opt.MaxBytes}
	gz := gzip.NewWriter(limited)
	tw := tar.NewWriter(gz)
	res.Path = opt.Output
	manifest := []entry{}
	used := int64(0)
	manifestBytes := int64(256)
	finalizing := false
	warn := func(s string) {
		res.Incomplete = true
		if len(res.Warnings) < 100 {
			if len(s) > 512 {
				s = s[:512]
			}
			res.Warnings = append(res.Warnings, i18n.S("warn.collect_item", s))
		}
	}
	add := func(name string, b []byte) error {
		if strings.ContainsAny(name, "\\\n\r\t") {
			warn("unsafe archive filename")
			return nil
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		reserve := int64(128 << 10)
		if finalizing {
			reserve = 0
		}
		if int64(len(b))+used+manifestBytes+int64(len(name)+68) > opt.MaxBytes-reserve {
			if finalizing {
				return safefile.ErrTooLarge
			}
			warn(name + ": size limit")
			return nil
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(b)), ModTime: opt.Now}); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
		used += int64(len(b))
		manifestBytes += int64(len(name) + 68)
		sum := sha256.Sum256(b)
		manifest = append(manifest, entry{name, hex.EncodeToString(sum[:]), len(b)})
		return nil
	}
	addJSON := func(name string, v any) error {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		return add(name, b)
	}
	if snap == nil {
		return res, os.ErrInvalid
	}
	if err = addJSON("processes.json", snap.Processes); err != nil {
		return res, err
	}
	if err = addJSON("network.json", struct {
		Sockets  []model.Socket        `json:"sockets"`
		Exposure *model.ExposureReport `json:"exposure"`
	}{snap.Sockets, snap.Exposure}); err != nil {
		return res, err
	}
	if err = addJSON("system.json", struct {
		Host     model.HostInfo        `json:"host"`
		Findings []model.SystemFinding `json:"findings"`
		Audit    *model.AuditReport    `json:"audit"`
	}{snap.Host, snap.System, audit}); err != nil {
		return res, err
	}
	if err = addJSON("logins.json", snap.Auth); err != nil {
		return res, err
	}
	read := func(r *os.Root, p string, max int64) ([]byte, error) {
		in, fi, e := safefile.OpenRooted(r, p)
		if e != nil {
			return nil, e
		}
		defer in.Close()
		if fi.Size() > max {
			return nil, safefile.ErrTooLarge
		}
		b, e := io.ReadAll(io.LimitReader(in, max+1))
		if int64(len(b)) > max {
			return nil, safefile.ErrTooLarge
		}
		return b, e
	}
	paths := []string{"etc/rc.local", "etc/profile", "etc/bash.bashrc", "etc/ld.so.conf", "etc/environment", "etc/crontab", "etc/ld.so.preload", "etc/sudoers", "var/log/wtmp", "var/log/wtmp.1", "var/log/btmp", "var/log/btmp.1", "var/log/lastlog", "var/log/auth.log", "var/log/auth.log.1", "var/log/auth.log.2.gz", "var/log/dpkg.log", "var/log/dpkg.log.1", "var/log/apt/history.log", "etc/os-release"}
	roots := []string{"etc/cron.d", "etc/cron.daily", "etc/cron.hourly", "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron", "etc/systemd/system", "etc/systemd/user", "usr/lib/systemd/system", "lib/systemd/system", "etc/pam.d", "etc/sudoers.d", "etc/profile.d", "etc/ld.so.conf.d", "etc/init.d", "etc/update-motd.d", "etc/udev/rules.d", "etc/apt/apt.conf.d", "etc/logrotate.d"}
	homes := map[string]bool{"root": true}
	if b, e := read(root, "etc/passwd", 1<<20); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) != 7 {
				continue
			}
			home := filepath.Clean(fields[5])
			if filepath.IsAbs(home) && home != "/" && len(homes) < 4096 {
				homes[strings.TrimPrefix(home, "/")] = true
			}
		}
	} else if !os.IsNotExist(e) {
		warn("etc/passwd: " + e.Error())
	}
	for home := range homes {
		for _, name := range []string{".ssh/authorized_keys", ".ssh/rc", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".config/fish/config.fish"} {
			paths = append(paths, home+"/"+name)
		}
		roots = append(roots, home+"/.config/systemd/user", home+"/.config/autostart")
	}
	complete := investigate.Walk(ctx, root, roots, 20000, func(p string, fi os.FileInfo) {
		if !excluded(p) {
			paths = append(paths, p)
		}
	})
	if !complete {
		warn("persistence: traversal incomplete")
	}
	sort.Strings(paths)
	for _, p := range paths {
		if used+manifestBytes >= opt.MaxBytes-(128<<10) {
			warn("persistence: total size limit")
			break
		}
		if excluded(p) {
			continue
		}
		b, e := read(root, p, 2<<20)
		if e != nil {
			if !os.IsNotExist(e) {
				warn(p + ": " + e.Error())
			}
			continue
		}
		if strings.HasSuffix(p, ".gz") {
			z, e := gzip.NewReader(bytes.NewReader(b))
			if e != nil {
				warn(p + ": gzip")
				continue
			}
			b, e = io.ReadAll(io.LimitReader(z, 2<<20+1))
			z.Close()
			if e != nil || len(b) > 2<<20 {
				warn(p + ": gzip limit")
				continue
			}
			p = strings.TrimSuffix(p, ".gz") + ".decoded"
		}
		if !strings.Contains(p, "/wtmp") && !strings.Contains(p, "/btmp") && !strings.HasSuffix(p, "/lastlog") {
			b = cleanText(b)
		}
		prefix := "persistence/"
		if strings.HasPrefix(p, "var/log/") {
			prefix = "logs/"
		}
		if err = add(prefix+p, b); err != nil {
			return res, err
		}
	}
	// /proc/PID/exe — единственное исключение для симлинков; идентичность PID проверяется повторно.
	pr, e := os.OpenRoot(opt.ProcRoot)
	if e != nil {
		warn("proc: " + e.Error())
	} else {
		defer pr.Close()
		for _, p := range []string{"net/route", "net/arp", "net/dev", "modules", "sys/kernel/tainted", "sys/kernel/osrelease", "uptime", "self/mountinfo"} {
			b, e := read(pr, p, 2<<20)
			if e != nil {
				warn("proc/" + p + ": " + e.Error())
				continue
			}
			if err = add("proc/"+p, cleanText(b)); err != nil {
				return res, err
			}
		}
		pfs := procfs.New(opt.ProcRoot, opt.HostRoot)
		var hashes strings.Builder
		binaryBudget := opt.MaxBytes
		for _, p := range snap.Processes {
			if p.Kernel {
				continue
			}
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			current, e := pfs.ReadProcess(p.PID, opt.Now)
			if e != nil || current.Proc.Key != p.Key || current.Proc.Exe != p.Exe || current.Proc.ExeDeleted != p.ExeDeleted {
				warn(p.Key + ": process changed")
				continue
			}
			prefix := strconv.Itoa(p.PID) + "/"
			for _, name := range []string{"maps", "environ"} {
				b, e := read(pr, prefix+name, 1<<20)
				if e != nil {
					warn(prefix + name + ": " + e.Error())
					continue
				}
				if name == "environ" {
					var out strings.Builder
					for _, field := range bytes.Split(b, []byte{0}) {
						k, _, ok := bytes.Cut(field, []byte{'='})
						if ok {
							out.Write(k)
							out.WriteString("=***\n")
						}
					}
					clear(b)
					b = []byte(out.String())
				}
				check, ce := pfs.ReadProcess(p.PID, opt.Now)
				if ce != nil || check.Proc.Key != p.Key {
					clear(b)
					warn(p.Key + ": process changed")
					continue
				}
				if err = add("process/"+prefix+name, cleanText(b)); err != nil {
					return res, err
				}
			}
			in, fi, e := safefile.Open(filepath.Join(opt.ProcRoot, prefix, "exe"), true)
			if e != nil {
				warn(p.Key + ": exe unavailable")
				continue
			}
			if fi.Size() > opt.MaxBinaryBytes || fi.Size() > binaryBudget {
				in.Close()
				warn(p.Key + ": binary size limit")
				continue
			}
			readLimit := min(opt.MaxBinaryBytes, binaryBudget)
			b, e := io.ReadAll(io.LimitReader(in, readLimit+1))
			in.Close()
			binaryBudget -= int64(len(b))
			after, ae := pfs.ReadProcess(p.PID, opt.Now)
			exeAfter, se := os.Stat(filepath.Join(opt.ProcRoot, prefix, "exe"))
			if e != nil || int64(len(b)) > readLimit || se != nil || !os.SameFile(fi, exeAfter) || fi.Size() != exeAfter.Size() || !fi.ModTime().Equal(exeAfter.ModTime()) || ae != nil || after.Proc.Key != p.Key || after.Proc.Exe != current.Proc.Exe {
				clear(b)
				warn(p.Key + ": unstable executable")
				continue
			}
			sum := sha256.Sum256(b)
			fmt.Fprintf(&hashes, "%x  %s/exe\n", sum, p.Key)
			if p.ExeDeleted || strings.Contains(p.Exe, "memfd:") {
				if err = add("binaries/"+safeName(p.Key)+".bin", b); err != nil {
					return res, err
				}
			}
			clear(b)
		}
		if err = add("hashes.txt", []byte(hashes.String())); err != nil {
			return res, err
		}
	}
	finalizing = true
	if err = add("README.txt", []byte(i18n.S("cli.collect_readme", opt.Version, opt.Now.UTC().Format(time.RFC3339)))); err != nil {
		return res, err
	}
	if err = addJSON("collection.json", struct {
		Version string    `json:"version"`
		Time    time.Time `json:"time"`
		Result  Result    `json:"result"`
	}{opt.Version, opt.Now, res}); err != nil {
		return res, err
	}
	var manifestText strings.Builder
	fmt.Fprintf(&manifestText, "# ServerSecurityGo %s\n# %s\n", safeName(opt.Version), opt.Now.UTC().Format(time.RFC3339Nano))
	for _, e := range manifest {
		fmt.Fprintf(&manifestText, "%s  %s\n", e.SHA256, e.Path)
	}
	if err = tw.WriteHeader(&tar.Header{Name: "MANIFEST.sha256", Mode: 0600, Size: int64(manifestText.Len()), ModTime: opt.Now}); err != nil {
		return res, err
	}
	if _, err = io.WriteString(tw, manifestText.String()); err != nil {
		return res, err
	}
	if err = tw.Close(); err != nil {
		return res, err
	}
	if err = gz.Close(); err != nil {
		return res, err
	}
	if err = f.Sync(); err != nil {
		return res, err
	}
	if err = f.Close(); err != nil {
		return res, err
	}
	res.SHA256 = hex.EncodeToString(digest.Sum(nil))
	done = true
	return res, nil
}
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (w *limitWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.left {
		return 0, safefile.ErrTooLarge
	}
	n, e := w.w.Write(b)
	w.left -= int64(n)
	return n, e
}
