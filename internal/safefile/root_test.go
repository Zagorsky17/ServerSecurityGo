package safefile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRootedReadAndAtomicState(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), []byte("data"), 0600)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, fi, err := OpenRooted(root, "file")
	if err != nil || fi.Size() != 4 {
		t.Fatalf("%v %v", fi, err)
	}
	f.Close()
	for _, p := range []string{"..", "../outside", "."} {
		if f, _, err := OpenRooted(root, p); err == nil {
			f.Close()
			t.Fatal("unsafe open", p)
		}
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(dir, "escape"))
	if f, _, err := OpenRooted(root, "escape/secret"); err == nil {
		f.Close()
		t.Fatal("root escaped")
	}
	os.Symlink("file", filepath.Join(dir, "link"))
	if f, _, err := OpenRooted(root, "link"); err == nil {
		f.Close()
		t.Fatal("final symlink followed")
	}
	state := filepath.Join(dir, "state.json")
	if err := WriteJSON(state, map[string]int{"v": 1}, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(state, make(chan int), 1<<20); err == nil {
		t.Fatal("encoded unsupported value")
	}
	if err := WriteJSON(state, "too large", 2); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if err := WriteJSON(state, "invalid limit", 0); err == nil {
		t.Fatal("invalid limit accepted")
	}
	data, _ := os.ReadFile(state)
	var v map[string]int
	if err := json.Unmarshal(data, &v); err != nil || v["v"] != 1 {
		t.Fatal("old state damaged")
	}
	fi, err = os.Stat(state)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", fi, err)
	}
	if err := WriteJSON(filepath.Join(dir, "missing/state"), v, 1<<20); err == nil {
		t.Fatal("missing directory ignored")
	}
	if err := WriteJSON(dir, v, 1<<20); err == nil {
		t.Fatal("directory replaced")
	}
	files, err := ReadDir(dir, 100)
	if err != nil || len(files) < 3 {
		t.Fatalf("%v %v", files, err)
	}
	for _, e := range files {
		if len(e.Name()) >= 11 && e.Name()[:11] == ".ssg-state-" {
			t.Fatal("leaked temporary state")
		}
	}
	if _, err := ReadDir(dir, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := ReadDir(state, 10); err == nil {
		t.Fatal("file treated as directory")
	}
}
