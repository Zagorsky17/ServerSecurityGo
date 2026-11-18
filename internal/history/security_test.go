package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestHistoryChurnBounded(t *testing.T) {
	s, _ := Open(Options{})
	now := time.Now()
	trimmed := false
	for batch := 0; batch < 100; batch++ {
		ps := []*model.Process{}
		for i := 0; i < 32; i++ {
			k := fmt.Sprintf("%d-%d", batch, i)
			ps = append(ps, &model.Process{Key: k, PID: i + 1, Cmdline: k + strings.Repeat("x", 30<<10)})
		}
		for _, e := range s.Record(now.Add(time.Duration(batch)*time.Second), ps, nil) {
			if e.Name == "history_trimmed" {
				trimmed = true
			}
		}
	}
	n := 0
	for _, p := range s.tracks {
		if p.Exited {
			n += len(p.Cmdline)
		}
	}
	if n > 8<<20 || !trimmed {
		t.Fatalf("bytes=%d trimmed=%v", n, trimmed)
	}
	if p, ok := s.Track("99-0"); !ok || p.Exited {
		t.Fatal("active process lost")
	}
	if _, ok := s.Track("0-0"); ok {
		t.Fatal("oldest process retained")
	}
}
func TestHistoryStateReadBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(16<<20 + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Open(Options{Dir: dir}); err == nil {
		t.Fatal("oversized state accepted")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 16<<20+1 {
		t.Fatal("original state changed")
	}
}

func TestHistoryCountLimitAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	procs := []*model.Process{}
	for i := 0; i < 4200; i++ {
		key := fmt.Sprintf("%05d", i)
		procs = append(procs, &model.Process{Key: key, PID: i + 1, Cmdline: "sleep"})
	}
	s.Record(now, procs, nil)
	s.Record(now.Add(time.Second), nil, nil)
	if len(s.tracks) != 4096 {
		t.Fatal(len(s.tracks))
	}
	restored, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.tracks) != 4096 {
		t.Fatal(len(restored.tracks))
	}
	if _, ok := restored.Track("00000"); ok {
		t.Fatal("oldest retained")
	}
	if _, ok := restored.Track("04199"); !ok {
		t.Fatal("newest missing")
	}
}
func TestHistoryUnsafeState(t *testing.T) {
	for _, body := range []string{`{"tracks":{"x":null}}`, `{"tracks":{"x":{"key":"y"}}}`} {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.json")
		os.WriteFile(path, []byte(body), 0600)
		if _, err := Open(Options{Dir: dir}); err == nil {
			t.Fatal("invalid track accepted")
		}
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "state")
	os.WriteFile(outside, []byte(`{}`), 0600)
	os.Symlink(outside, filepath.Join(dir, "state.json"))
	if _, err := Open(Options{Dir: dir}); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestHistoryOversizedSavePreservesState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Record(now, []*model.Process{{Key: "one", PID: 1, Cmdline: "old"}}, nil)
	path := filepath.Join(dir, "state.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// JSON экранирует «<»: строки в пределах бюджета могут превысить лимит файла.
	ev := s.Record(now.Add(time.Second), []*model.Process{{Key: "one", PID: 1, Cmdline: strings.Repeat("<", 3<<20)}}, nil)
	failed := false
	for _, e := range ev {
		if e.Name == "history_save_failed" {
			failed = true
		}
	}
	if !failed {
		t.Fatal("missing save diagnostic")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("previous state overwritten", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ssg-state-") {
			t.Fatal("temporary state left")
		}
	}
}
func TestHistoryLoadedExitedBudget(t *testing.T) {
	dir := t.TempDir()
	st := stateFile{Version: 1, Tracks: map[string]*Track{}}
	for i := 0; i < 4200; i++ {
		k := fmt.Sprintf("%05d", i)
		st.Tracks[k] = &Track{Key: k, Exited: true}
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "state.json"), b, 0600)
	s, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.tracks) != 4096 {
		t.Fatal(len(s.tracks))
	}
	if ev := s.Events(1); len(ev) != 1 || ev[0].Name != "history_trimmed" {
		t.Fatal(ev)
	}
}
