package view

import (
	"fmt"
	"path"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// SystemGroup ссылается на исходные находки; данные и их уровни не изменяются.
type SystemGroup struct {
	Key       string `json:"key"`
	Directory string `json:"directory"`
	Owner     string `json:"owner"`
	Indices   []int  `json:"indices"`
}

func GroupSystem(findings []model.SystemFinding) []SystemGroup {
	groups := []SystemGroup{}
	byKey := map[string]int{}
	for i, f := range findings {
		if f.ID != "fs_unowned" || len(f.Evidence) != 1 || !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path {
			continue
		}
		e := f.Evidence[0]
		var uid, gid uint32
		if e.Key != "" || e.Join || len(e.Args) != 0 {
			continue
		}
		if n, err := fmt.Sscanf(e.Lit, "uid=%d gid=%d", &uid, &gid); err != nil || n != 2 || e.Lit != fmt.Sprintf("uid=%d gid=%d", uid, gid) {
			continue
		}
		dir := path.Dir(f.Path)
		// Ограничиваем глубину группировки, чтобы подкаталоги одного дерева не создавали тысячи групп.
		if parts := strings.Split(strings.TrimPrefix(dir, "/"), "/"); len(parts) > 3 {
			dir = "/" + strings.Join(parts[:3], "/")
		}
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%t", dir, e.Lit, f.Risk, f.Suppressed)
		n, ok := byKey[key]
		if !ok {
			n = len(groups)
			byKey[key] = n
			groups = append(groups, SystemGroup{Key: key, Directory: dir, Owner: e.Lit})
		}
		groups[n].Indices = append(groups[n].Indices, i)
	}
	result := groups[:0]
	for _, g := range groups {
		if len(g.Indices) > 1 {
			result = append(result, g)
		}
	}
	return result
}
