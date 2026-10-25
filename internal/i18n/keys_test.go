package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// keyLike — строка, похожая на ключ каталога.
var keyLike = regexp.MustCompile(`^(cat|score|rec|allow|rule|ev|event|hist|warn|log|err|tui|web|cli|audit)\.[a-z0-9_.]*[a-z0-9_]$`)

// dynamicPrefixes — ключи, которые код собирает из префикса и значения
// (категория признака, тип события); они проверяются отдельно.
var dynamicPrefixes = []string{"cat.", "event.", "tui.event."}

// usedKeys собирает ключи из исходников: строковые литералы Go, похожие
// на ключ, вызовы tr('…') в JavaScript и атрибуты data-i18n* в HTML.
func usedKeys(t *testing.T) map[string][]string {
	t.Helper()
	root := filepath.Join("..", "..")
	used := map[string][]string{}
	jsKey := regexp.MustCompile(`\btr\('([a-z0-9_.]*[a-z0-9_])'`)
	htmlKey := regexp.MustCompile(`data-i18n(?:-[a-z-]+)?="([a-z0-9_.]+)"`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "dist" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") && !strings.Contains(path, "internal/i18n/"):
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil && keyLike.MatchString(s) {
						used[s] = append(used[s], path)
					}
				}
				return true
			})
		case strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".html"):
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			re := jsKey
			if strings.HasSuffix(path, ".html") {
				re = htmlKey
			}
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				used[m[1]] = append(used[m[1]], path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return used
}

// TestUsedKeysExist: каждый ключ из кода, скриптов и разметки есть в
// каталоге — иначе пользователь увидит сам ключ вместо текста.
func TestUsedKeysExist(t *testing.T) {
	for k, where := range usedKeys(t) {
		if !Has(k) {
			t.Errorf("ключа %q нет в каталоге (используется в %v)", k, where)
		}
	}
}

// TestCatalogKeysUsed: в каталоге нет забытых ключей, которые нигде не
// используются.
func TestCatalogKeysUsed(t *testing.T) {
	used := usedKeys(t)
	for k := range catalog {
		if _, ok := used[k]; ok {
			continue
		}
		dynamic := false
		for _, p := range dynamicPrefixes {
			if strings.HasPrefix(k, p) && !strings.Contains(strings.TrimPrefix(k, p), ".") {
				dynamic = true
			}
		}
		if !dynamic {
			t.Errorf("ключ %q нигде не используется", k)
		}
	}
}
