package advanced

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/investigate"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var webRootDirective = regexp.MustCompile(`(?im)(?:^|[;{}\n])\s*(?:root|DocumentRoot)\s+(?:"([^"\n]+)"|'([^'\n]+)'|([^\s;{}]+))`)

func WebRoots(data string) []string {
	var roots []string
	for _, m := range webRootDirective.FindAllStringSubmatch(data, 64) {
		v := ""
		for _, part := range m[1:] {
			if part != "" {
				v = part
				break
			}
		}
		if !strings.HasPrefix(v, "/") || path.Clean(v) != v || v == "/" || strings.ContainsAny(v, "$\\\x00\r\n") {
			continue
		}
		roots = append(roots, strings.TrimPrefix(v, "/"))
	}
	return roots
}

var shellPatterns = []struct {
	id     string
	re     *regexp.Regexp
	strong bool
}{
	{"encoded-eval", regexp.MustCompile(`(?i)(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(`), true},
	{"request-command", regexp.MustCompile(`(?i)(?:system|exec|shell_exec|passthru|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b`), true},
	{"jsp-command", regexp.MustCompile(`(?i)Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`), true},
	{"aspx-command", regexp.MustCompile(`(?i)Process\s*\.\s*Start\s*\(`), true},
	{"passthru", regexp.MustCompile(`(?i)\bpassthru\s*\(`), false},
	{"long-base64", regexp.MustCompile(`[A-Za-z0-9+/]{512,}={0,2}`), false},
	{"preg-replace-eval", regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"\n]{1,256}/[a-z]*e[a-z]*['"]`), true},
}

func WebshellSignals(data []byte) []string {
	var out []string
	for _, p := range shellPatterns {
		if p.re.Match(data) {
			out = append(out, p.id)
		}
	}
	return out
}
func webshells(ctx context.Context, host string, procs []*model.Process, days int) ([]model.SystemFinding, bool) {
	web := false
	for _, p := range procs {
		n := filepath.Base(p.Exe)
		web = web || n == "nginx" || n == "apache2" || n == "httpd" || strings.HasPrefix(n, "php-fpm")
	}
	if !web {
		return nil, true
	}
	root, e := os.OpenRoot(host)
	if e != nil {
		return nil, false
	}
	defer root.Close()
	roots := []string{"var/www"}
	complete := true
	configs := 0
	if !investigate.Walk(ctx, root, []string{"etc/nginx", "etc/apache2", "etc/httpd"}, 4096, func(p string, fi os.FileInfo) {
		if configs >= 256 {
			complete = false
			return
		}
		configs++
		data, _, e := safefile.ReadRooted(root, p, 256<<10)
		if e != nil {
			complete = false
			return
		}
		parsed := WebRoots(string(data))
		if len(webRootDirective.FindAllStringSubmatch(string(data), 65)) != len(parsed) {
			complete = false
		}
		roots = append(roots, parsed...)
		clear(data)
	}) {
		complete = false
	}
	slices.Sort(roots)
	roots = slices.Compact(roots)
	if len(roots) > 32 {
		roots = roots[:32]
		complete = false
	}
	budget := int64(16 << 20)
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	var out []model.SystemFinding
	seen := map[string]bool{}
	if !investigate.Walk(ctx, root, roots, 100000, func(p string, fi os.FileInfo) {
		if seen[p] {
			return
		}
		seen[p] = true
		ext := strings.ToLower(path.Ext(p))
		if (ext != ".php" && ext != ".jsp" && ext != ".aspx") || fi.ModTime().Before(since) {
			return
		}
		if budget <= 0 || len(out) >= 1000 {
			complete = false
			return
		}
		data, after, e := safefile.ReadRooted(root, p, min(1<<20, budget))
		budget -= int64(len(data))
		if e != nil || !os.SameFile(fi, after) || fi.Size() != after.Size() || !fi.ModTime().Equal(after.ModTime()) {
			complete = false
			return
		}
		final, statErr := root.Lstat(p)
		if statErr != nil || !os.SameFile(after, final) || after.Size() != final.Size() || !after.ModTime().Equal(final.ModTime()) {
			clear(data)
			complete = false
			return
		}
		signals := WebshellSignals(data)
		clear(data)
		if len(signals) == 0 {
			return
		}
		risk := model.RiskInfo
		for _, pattern := range shellPatterns {
			if pattern.strong && slices.Contains(signals, pattern.id) {
				risk = model.RiskMedium
			}
		}
		out = append(out, model.SystemFinding{Path: "/" + p, Risk: risk, ModTime: fi.ModTime(), Finding: model.Finding{ID: "webshell_pattern", Category: model.CatContent, Title: i18n.T("rule.webshell_pattern.title"), Evidence: []i18n.Msg{i18n.L(strings.Join(signals, ", "))}, Recommendation: i18n.T("rule.webshell_pattern.rec")}})
	}) {
		complete = false
	}
	return out, complete
}
