package procfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityDetectsRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if e := os.WriteFile(path, []byte("old"), 0600); e != nil {
		t.Fatal(e)
	}
	before, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	id := FileIdentity(before)
	if id == "" {
		t.Skip("file identity unavailable")
	}
	time.Sleep(10 * time.Millisecond)
	if e = os.WriteFile(path, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chtimes(path, before.ModTime(), before.ModTime()); e != nil {
		t.Fatal(e)
	}
	after, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("invalid fixture")
	}
	if FileIdentity(after) == id {
		t.Fatal("restored mtime concealed a change")
	}
}
