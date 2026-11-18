package detect_test

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/advanced"
	"github.com/Zagorsky17/ServerSecurityGo/internal/detect"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"os"
	"runtime"
	"testing"
)

func TestOrdinaryGoELFDoesNotAddPackingRisk(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires a Linux Go test executable")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	x, err := advanced.InspectELF(b)
	if err != nil {
		t.Fatal(err)
	}
	p := &model.Process{PID: 100, PPID: 1, Name: "scanner.test", Args: []string{"/tmp/scanner.test"}, Exe: "/tmp/scanner.test", ExeInfo: &model.FileInfo{}, Executable: &x}
	detect.Analyze([]*model.Process{p}, &detect.Context{Cfg: detect.DefaultConfig()})
	seen := map[string]bool{}
	for _, f := range p.Findings {
		seen[f.ID] = true
	}
	if seen["exe_packed"] || !seen["exe_in_temp"] || !seen["root_from_writable"] {
		t.Fatalf("false packing or lost location/privilege signals: %+v", p.Findings)
	}
	if p.Risk != model.RiskMedium {
		t.Fatalf("ordinary root Go test: risk=%s score=%d", p.Risk, p.Score)
	}
	t.Logf("ordinary root Go test: risk=%s score=%d", p.Risk, p.Score)
	if x.Static && !seen["exe_static_in_temp"] {
		t.Fatal("static ELF signal lost")
	}
}
