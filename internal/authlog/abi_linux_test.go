package authlog

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Validate the layout against the runner's glibc headers, not a duplicate Go fixture.
func TestRealAccountingABI(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "record.c")
	bin := filepath.Join(dir, "record")
	code := `#include <utmp.h>
#include <stdio.h>
#include <string.h>
int main(void){struct utmp u={0};u.ut_type=USER_PROCESS;u.ut_pid=42;strcpy(u.ut_line,"pts/0");strcpy(u.ut_user,"root");strcpy(u.ut_host,"192.0.2.1");u.ut_tv.tv_sec=1780000000;fwrite(&u,sizeof(u),1,stdout);return 0;}`
	if err = os.WriteFile(src, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, src, "-o", bin).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	data, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := utRecord(runtime.GOARCH == "arm64", 7, 1780000000)
	if !bytes.Equal(data, want) {
		t.Fatalf("C ABI differs: C %d bytes, fixture %d", len(data), len(want))
	}
	events, bad := Utmp(data, "wtmp", runtime.GOARCH == "arm64")
	if bad || len(events) != 1 || events[0].User != "root" {
		t.Fatal(events, bad)
	}
}
