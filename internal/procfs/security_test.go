package procfs

import (
	"encoding/json"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSecurityStatus(t *testing.T) {
	s := ParseStatus("TracerPid:\t42\nCapEff:\t0000000000280002\nCapPrm:\t0000000000000080\nCapBnd:\t8000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	if s.Security.TracerPID != 42 || !slices.Equal(s.Security.CapEff, []string{"CAP_DAC_OVERRIDE", "CAP_SYS_PTRACE", "CAP_SYS_ADMIN"}) || !slices.Equal(s.Security.CapPrm, []string{"CAP_SETUID"}) || !slices.Equal(s.Security.CapBnd, []string{"CAP_63"}) || s.Security.CapAmb == nil || *s.Security.NoNewPrivs != 1 || *s.Security.Seccomp != 2 {
		t.Fatalf("%+v", s.Security)
	}
	s = ParseStatus("CapEff: malformed\nSeccomp: bad\nNoNewPrivs: -1\n")
	if s.Security.CapEff != nil || s.Security.Seccomp != nil || s.Security.NoNewPrivs != nil {
		t.Fatalf("bad status: %+v", s.Security)
	}
}
func TestEnvironmentSignals(t *testing.T) {
	cases := []struct{ input, flag string }{
		{"HISTFILE=", "history_disabled"}, {"HISTFILE=/dev/null", "history_disabled"}, {"HISTFILE=/dev/null.other", ""}, {"HISTSIZE=0", "history_disabled"}, {"HISTFILESIZE=100", ""},
		{"PROMPT_COMMAND=curl --token SUPER_SECRET https://example.test", "prompt_command_net"}, {"PROMPT_COMMAND=echo curliness", ""}, {"LD_LIBRARY_PATH=/usr/lib:/tmp/lib", "ld_library_path_temp"}, {"LD_LIBRARY_PATH=/usr/lib:", "ld_library_path_temp"}, {"LD_LIBRARY_PATH=/usr/lib:/opt/lib", ""},
		{"LD_LIBRARY_PATH=/home/u/.private/lib", "ld_library_path_temp"}, {"PASSWORD=SUPER_SECRET", ""}, {"PYTHON_JIT=1", "PYTHON_JIT"}, {"PYTHON_JIT=0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := appendEnvSignals(nil, []byte(tc.input))
			if tc.flag == "" && len(got) != 0 || tc.flag != "" && !slices.Contains(got, tc.flag) {
				t.Fatalf("%v", got)
			}
			data, _ := json.Marshal(got)
			if strings.Contains(string(data), "SUPER_SECRET") {
				t.Fatal("secret retained")
			}
		})
	}
}
func TestParseSecurityMaps(t *testing.T) {
	input := "1000-2000 r-xp 00000000 08:01 10 /tmp/lib with spaces.so (deleted)\n" +
		"2000-3000 rwxp 00000000 00:00 0\n" +
		"3000-4000 r-xp 00000000 00:00 0 [vdso]\n" +
		"4000-5000 r-xp 00000000 00:00 0 [anon:jit]\n" +
		"5000-6000 rw-p 00000000 08:01 10 /usr/lib/libc.so\n"
	got, bad := ParseMaps([]byte(input))
	if bad || len(got) != 3 || got[0].Path != "/tmp/lib with spaces.so" || !got[0].Deleted || got[1].Path != "" || got[2].Path != "" {
		t.Fatalf("%+v bad=%v", got, bad)
	}
	if _, bad := ParseMaps([]byte("broken\n2000-1000 r-xp 0 0 0\n")); !bad {
		t.Fatal("malformed accepted")
	}
}
func FuzzSecurityMaps(f *testing.F) {
	f.Add([]byte("1000-2000 r-xp 0 00:00 0\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		maps, _ := ParseMaps(b)
		if len(maps) > 256 {
			t.Fatal("limit")
		}
		for _, m := range maps {
			if len(m.Path) > 4096 || len(m.Perms) != 4 {
				t.Fatal("invalid map")
			}
		}
	})
}

func TestReadSecurityBudgets(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "10"), 0700)
	fs := New(root, t.TempDir())
	p := &model.Process{}
	os.WriteFile(filepath.Join(root, "10/environ"), []byte("HISTFILE="+strings.Repeat("x", 5000)+"\x00PROMPT_COMMAND=curl x\x00"), 0600)
	flags, n := fs.readEnvFlags("10", p, 8192)
	if n == 0 || !slices.Contains(flags, "prompt_command_net") || slices.Contains(flags, "history_disabled") || !slices.Contains(p.Access, "environ:entry-limit") {
		t.Fatalf("%v %v %d", flags, p.Access, n)
	}
	p = &model.Process{}
	flags, _ = fs.readEnvFlags("10", p, 9)
	if len(flags) != 0 || !slices.Contains(p.Access, "environ:limit") {
		t.Fatalf("partial record: %v %v", flags, p.Access)
	}
	os.WriteFile(filepath.Join(root, "10/maps"), []byte("1000-2000 r-xp 0 00:00 0 /tmp/x.so\n2000-3000 r-xp 0 00:00 0 /tmp/y.so\n"), 0600)
	p = &model.Process{}
	n = fs.readMaps("10", p, 40)
	if n != 40 || len(p.Maps) != 1 || !slices.Contains(p.Access, "maps:incomplete") {
		t.Fatalf("%d %+v %v", n, p.Maps, p.Access)
	}
	p = &model.Process{}
	fs.readMaps("10", p, 0)
	if !slices.Contains(p.Access, "maps:budget") {
		t.Fatal("budget invisible")
	}
}
