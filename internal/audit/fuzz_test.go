package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Фаззинг разборщиков файлов, которые читаются с сервера. go test
// выполняет только начальный корпус; долгий прогон:
// go test -fuzz=FuzzX ./internal/audit.

func FuzzSplitSSHLine(f *testing.F) {
	for _, s := range []string{"PasswordAuthentication yes", `Banner "a b"`, "Key=\"", "x # y", "\t\"\"\"", "Match User a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		k, args := splitSSHLine(line)
		if k != strings.ToLower(k) {
			t.Fatalf("ключ не в нижнем регистре: %q", k)
		}
		if k == "" && len(args) != 0 {
			t.Fatalf("значения без ключа: %q", args)
		}
	})
}

// FuzzSudoers — произвольный файл sudoers: разбор и все проверки sudo не
// паникуют и не зацикливаются (включая include самого себя).
func FuzzSudoers(f *testing.F) {
	f.Add(sudoersText)
	f.Add("Cmnd_Alias A = B\nCmnd_Alias B = A\nu ALL = A\n")
	f.Add("@include /etc/sudoers\nx ALL=(\nDefaults env_keep=\"\nU ALL = (root NOPASSWD: \\\n")
	f.Add("User_Alias U = U\nU ALL=ALL\n#include sudoers\n")
	f.Fuzz(func(t *testing.T, data string) {
		root := t.TempDir()
		p := filepath.Join(root, "etc", "sudoers")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o440); err != nil {
			t.Fatal(err)
		}
		a := &auditor{opt: Options{HostRoot: root, RootUID: os.Getuid(), Baseline: &Baseline{}},
			next: Baseline{Users: map[string]int{}, Priv: map[string][]string{}, Sudoers: map[string]string{}}}
		for _, c := range a.sudoChecks() {
			if c.Status == "" || len(c.Evidence) > maxEvidence {
				t.Fatalf("%s: статус %q, фактов %d", c.ID, c.Status, len(c.Evidence))
			}
		}
	})
}

func FuzzAccounts(f *testing.F) {
	f.Add(passwd, shadow, group)
	f.Add("a:b:c:d:e:f:g\n::::::\n", "x:\n:$\n", "g:x:1:a,,b\n")
	f.Fuzz(func(t *testing.T, p, s, g string) {
		for _, u := range parsePasswd(p) {
			if u.Line <= 0 {
				t.Fatal("номер строки")
			}
		}
		for _, si := range parseShadow(s) {
			if si.Empty && si.Locked {
				t.Fatal("пусто и заблокировано одновременно")
			}
			if strings.Contains(si.Algo, "$") {
				t.Fatalf("в алгоритм попал хеш: %q", si.Algo)
			}
		}
		for _, gr := range parseGroup(g) {
			for _, m := range gr.Members {
				if m == "" {
					t.Fatal("пустой член группы")
				}
			}
		}
	})
}
