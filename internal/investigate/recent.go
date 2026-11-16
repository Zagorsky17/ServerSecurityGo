// Пакет investigate объединяет наблюдения для локального расследования.
package investigate

import (
	"bufio"
	"context"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var RecentRoots = []string{"etc", "usr/bin", "usr/sbin", "usr/lib", "lib", "root", "home", "tmp", "var/tmp", "dev/shm", "opt", "var/www", "boot"}

// Walk ограничивает чтение каталогов и не обходит симлинки на каталоги.
func Walk(ctx context.Context, root *os.Root, roots []string, max int, fn func(string, os.FileInfo)) bool {
	count := 0
	complete := true
	var walk func(string, int)
	walk = func(p string, depth int) {
		if ctx.Err() != nil || count >= max || depth > 64 {
			complete = false
			return
		}
		count++
		fi, e := root.Lstat(p)
		if e != nil {
			if !os.IsNotExist(e) {
				complete = false
			}
			return
		}
		if fi.Mode().IsRegular() {
			fn(p, fi)
			return
		}
		if !fi.IsDir() {
			return
		}
		f, e := root.Open(p)
		if e != nil {
			complete = false
			return
		}
		after, e := f.Stat()
		if e != nil || !os.SameFile(fi, after) {
			f.Close()
			complete = false
			return
		}
		entries, e := f.ReadDir(min(4096, max-count) + 1)
		f.Close()
		if e != nil && e != io.EOF {
			complete = false
			return
		}
		if len(entries) > 4096 || len(entries) > max-count {
			complete = false
			entries = entries[:min(len(entries), min(4096, max-count))]
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if ctx.Err() != nil || count >= max {
				complete = false
				break
			}
			walk(path.Join(p, entry.Name()), depth+1)
		}
	}
	for _, p := range roots {
		walk(p, 0)
	}
	return complete
}
func Recent(ctx context.Context, host string, since, now time.Time) *model.RecentReport {
	r := &model.RecentReport{Time: now, Files: []model.RecentFile{}}
	root, e := os.OpenRoot(host)
	if e != nil {
		r.Incomplete = true
		r.Warnings = append(r.Warnings, i18n.T("warn.recent_limit"))
		return r
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	loc := time.Local
	if host != "/" {
		loc = nil
		if f, _, e := safefile.OpenRooted(root, "etc/timezone"); e == nil {
			b, e := io.ReadAll(io.LimitReader(f, 1024))
			f.Close()
			if e == nil {
				loc, _ = time.LoadLocation(strings.TrimSpace(string(b)))
			}
		}
	}
	windows := packageWindows(root, loc)
	complete := Walk(ctx, root, RecentRoots, 100000, func(p string, fi os.FileInfo) {
		ct := changeTime(fi)
		if ct.Before(since) && fi.ModTime().Before(since) {
			return
		}
		if len(r.Files) >= 10000 {
			r.Incomplete = true
			return
		}
		f := model.RecentFile{Path: "/" + p, ModTime: fi.ModTime(), ChangeTime: ct, Size: fi.Size(), Mode: fi.Mode().String(), TimeMismatch: ct.Sub(fi.ModTime()) > 24*time.Hour}
		for _, w := range windows {
			if !ct.Before(w[0]) && !ct.After(w[1]) {
				f.PackageWindow = true
				break
			}
		}
		r.Files = append(r.Files, f)
	})
	r.Incomplete = r.Incomplete || !complete
	if r.Incomplete {
		r.Warnings = append(r.Warnings, i18n.T("warn.recent_limit"))
	}
	sort.Slice(r.Files, func(i, j int) bool {
		if r.Files[i].ChangeTime.Equal(r.Files[j].ChangeTime) {
			return r.Files[i].Path < r.Files[j].Path
		}
		return r.Files[i].ChangeTime.After(r.Files[j].ChangeTime)
	})
	return r
}
func packageWindows(root *os.Root, loc *time.Location) [][2]time.Time {
	if loc == nil {
		return nil
	}
	var out [][2]time.Time
	for _, p := range []string{"var/log/dpkg.log", "var/log/dpkg.log.1", "var/log/apt/history.log", "var/log/apt/history.log.1"} {
		f, _, e := safefile.OpenRooted(root, p)
		if e != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, 2<<20))
		var start time.Time
		for sc.Scan() {
			s := sc.Text()
			if strings.HasPrefix(s, "Start-Date:") {
				start, _ = time.ParseInLocation("2006-01-02  15:04:05", strings.TrimSpace(strings.TrimPrefix(s, "Start-Date:")), loc)
			} else if strings.HasPrefix(s, "End-Date:") {
				end, e := time.ParseInLocation("2006-01-02  15:04:05", strings.TrimSpace(strings.TrimPrefix(s, "End-Date:")), loc)
				if e == nil && !start.IsZero() && !end.Before(start) {
					out = append(out, [2]time.Time{start, end})
				}
				start = time.Time{}
			} else if len(s) >= 20 {
				t, e := time.ParseInLocation("2006-01-02 15:04:05", s[:19], loc)
				if e == nil && (strings.Contains(s, " install ") || strings.Contains(s, " upgrade ") || strings.Contains(s, " status installed ")) {
					out = append(out, [2]time.Time{t.Add(-time.Minute), t.Add(time.Minute)})
				}
			}
			if len(out) >= 10000 {
				break
			}
		}
		f.Close()
	}
	return out
}
