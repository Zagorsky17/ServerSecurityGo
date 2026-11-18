package selfcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func shellEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// На macOS нет sha256sum, но есть совместимый shasum из системы.
	if _, err := exec.LookPath("sha256sum"); err != nil {
		write(t, filepath.Join(dir, "sha256sum"), "#!/bin/sh\nexec shasum -a 256 \"$@\"\n")
		os.Chmod(filepath.Join(dir, "sha256sum"), 0700)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func TestInstallerBaselineAtomicAndCompatible(t *testing.T) {
	f := setup(t)
	app := filepath.Join(f.root, "app")
	write(t, filepath.Join(app, "bin/serversecuritygo"), "executable")
	write(t, f.unit+".d/with spaces.conf", "[Service]\nNice=10\n")
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	run := func() error {
		cmd := exec.Command("bash", "-c", `. "$1"; APP_DIR="$2"; DATA_DIR="$3"; write_self_baseline "$4"`, "test", lib, app, filepath.Dir(f.baseline), f.root)
		cmd.Env = append(os.Environ(), "PATH="+shellEnv(t))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Log(string(out))
		}
		return err
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := parseBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 3 {
		t.Fatal(baseline)
	}
	f.opt.Executable = filepath.Join(app, "bin/serversecuritygo")
	m := New(f.opt)
	if len(ids(m)) != 0 {
		t.Fatal(ids(m))
	}
	fi, _ := os.Stat(f.baseline)
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	// Ошибка не затирает рабочий эталон и не оставляет временный файл.
	write(t, f.unit, strings.Repeat("x", (1<<20)+1))
	if err := run(); err == nil {
		t.Fatal("oversized unit accepted")
	}
	current, _ := os.ReadFile(f.baseline)
	if string(current) != string(data) {
		t.Fatal("baseline destroyed after failure")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(f.baseline), ".self.sha256.*"))
	if len(files) != 0 {
		t.Fatal("temporary files left", files)
	}
}

func TestUpdateAndRollbackLifecycle(t *testing.T) {
	for _, failure := range []string{"", "restart", "baseline", "checkout"} {
		t.Run("failure="+failure, func(t *testing.T) {
			f := setup(t)
			app := filepath.Join(f.root, "app")
			scripts := filepath.Join(app, "scripts")
			os.MkdirAll(filepath.Join(app, ".git"), 0700)
			old := "#!/bin/sh\necho old\n"
			newBin := "#!/bin/sh\necho new\n"
			write(t, filepath.Join(app, "bin/serversecuritygo"), old)
			os.Chmod(filepath.Join(app, "bin/serversecuritygo"), 0700)
			write(t, filepath.Join(f.root, "new-binary"), newBin)
			os.Chmod(filepath.Join(f.root, "new-binary"), 0700)
			write(t, filepath.Join(app, "deploy/serversecuritygo.service"), "new unit")
			write(t, filepath.Join(f.root, "old-unit"), "old unit")
			write(t, f.unit, "old unit")
			f.binary = filepath.Join(app, "bin/serversecuritygo")
			f.baselineNow(t)
			original, _ := os.ReadFile(f.baseline)
			lib, err := os.ReadFile("../../scripts/lib.sh")
			if err != nil {
				t.Fatal(err)
			}
			// Используем реальные функции работы с эталоном и реальные update/rollback;
			// заменяем только границы системы: systemctl, git и получение бинарника.
			lib = []byte(strings.Replace(string(lib), "write_self_baseline() (", "real_write_self_baseline() (", 1))
			lib = append(lib, []byte(`
APP_DIR="$TEST_ROOT/app"
DATA_DIR="$TEST_ROOT/var/lib/serversecuritygo"
UNIT_PATH="$TEST_ROOT/etc/systemd/system/serversecuritygo.service"
require_root() { :; }
require_systemd() { :; }
obtain_binary() { cp "$TEST_ROOT/new-binary" "$1"; }
install_unit() { cp "$APP_DIR/deploy/serversecuritygo.service" "$UNIT_PATH"; }
install_link() { :; }
health_check() { :; }
journalctl() { :; }
systemctl() {
  echo "$*" >> "$TEST_ROOT/calls"
  if [ "$1" = restart ] && { [ "$TEST_FAILURE" = restart ] || [ "$TEST_FAILURE" = checkout ]; } && [ ! -e "$TEST_ROOT/failed-once" ]; then
    touch "$TEST_ROOT/failed-once"; return 1
  fi
}
git() { if [ "$TEST_FAILURE" = checkout ]; then return 1; fi; cp "$TEST_ROOT/old-unit" "$APP_DIR/deploy/serversecuritygo.service"; }
write_self_baseline() {
  if [ "$TEST_FAILURE" = baseline ]; then return 1; fi
  real_write_self_baseline "$TEST_ROOT"
}
`)...)
			write(t, filepath.Join(scripts, "lib.sh"), string(lib))
			for _, name := range []string{"update.sh", "rollback.sh"} {
				data, err := os.ReadFile("../../scripts/" + name)
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(scripts, name), string(data))
			}
			run := func(name string, args ...string) error {
				cmd := exec.Command("bash", append([]string{filepath.Join(scripts, name)}, args...)...)
				cmd.Env = append(os.Environ(), "TEST_ROOT="+f.root, "TEST_FAILURE="+failure, "PATH="+shellEnv(t))
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Log(string(out))
				}
				return err
			}
			err = run("update.sh", "--apply", "", "old-ref")
			if (err != nil) != (failure != "") {
				t.Fatalf("update error %v", err)
			}
			if failure == "" {
				got, _ := os.ReadFile(f.binary)
				if string(got) != newBin {
					t.Fatal("update did not install binary")
				}
				f.opt.Executable = f.binary
				if got := ids(New(f.opt)); len(got) != 0 {
					t.Fatal("updated baseline", got)
				}
				if err := run("rollback.sh"); err != nil {
					t.Fatal(err)
				}
			}
			got, _ := os.ReadFile(f.binary)
			if string(got) != old {
				t.Fatal("old binary not restored")
			}
			unit, _ := os.ReadFile(f.unit)
			if string(unit) != "old unit" {
				t.Fatal("old unit not restored")
			}
			restored, _ := os.ReadFile(f.baseline)
			if string(restored) != string(original) {
				t.Fatal("old baseline not restored")
			}
			calls, _ := os.ReadFile(filepath.Join(f.root, "calls"))
			if !strings.HasPrefix(string(calls), "stop serversecuritygo\n") {
				t.Fatal("changed files while service running", string(calls))
			}
			if !strings.HasSuffix(string(calls), "restart serversecuritygo\n") {
				t.Fatal("service left stopped", string(calls))
			}
		})
	}
}

func TestInstallerGoVersion(t *testing.T) {
	lib, err := filepath.Abs("../../scripts/lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		v  string
		ok bool
	}{{"go1.24.13", false}, {"go1.26.2", false}, {"go1.27.3", false}, {"go1.27.4", true}, {"go1.27.10", true}, {"go1.28.0", true}, {"go1.28rc1", false}, {"devel go1.28", false}, {"garbage", false}} {
		t.Run(tc.v, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `. "$1"; go() { printf '%s\n' "$TEST_GO_VERSION"; }; have_go`, "test", lib)
			cmd.Env = append(os.Environ(), "TEST_GO_VERSION="+tc.v)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("%v %s", err, out)
			}
		})
	}
}
