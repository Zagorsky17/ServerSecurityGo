// Package baseline stores bounded private snapshots and compares only compatible complete sections.
package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

const maxBytes = 16 << 20

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var autoRE = regexp.MustCompile(`^weekly-[0-9]{8}T[0-9]{6}Z$`)

type Store struct{ Dir string }

func New(dataDir string) *Store { return &Store{Dir: filepath.Join(dataDir, "baselines")} }
func (s *Store) root(create bool) (*os.Root, error) {
	if create {
		if e := os.Mkdir(s.Dir, 0700); e != nil && !os.IsExist(e) {
			return nil, e
		}
	}
	fi, e := os.Lstat(s.Dir)
	if e != nil {
		return nil, e
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 {
		return nil, i18n.Errorf("err.baseline_private")
	}
	r, e := os.OpenRoot(s.Dir)
	if e != nil {
		return nil, e
	}
	after, e := r.Stat(".")
	if e != nil || !os.SameFile(fi, after) {
		r.Close()
		return nil, os.ErrInvalid
	}
	return r, nil
}
func valid(b *model.BaselineSnapshot) bool {
	if b == nil || b.Version != 1 || b.Time.IsZero() || b.Host == "" || len(b.Sections) > 20 {
		return false
	}
	total := 0
	for _, s := range b.Sections {
		if s.Scope == "" || s.Items == nil {
			return false
		}
		total += len(s.Items)
		if total > 50000 {
			return false
		}
		for k, v := range s.Items {
			if len(k) > 4096 || len(v) > 8192 {
				return false
			}
		}
	}
	return true
}
func (s *Store) Save(name string, b *model.BaselineSnapshot) error {
	if !nameRE.MatchString(name) || !valid(b) {
		return i18n.Errorf("err.baseline_invalid")
	}
	data, e := json.Marshal(b)
	if e != nil {
		return e
	}
	if len(data) > maxBytes {
		return i18n.Errorf("err.baseline_invalid")
	}
	r, e := s.root(true)
	if e != nil {
		return e
	}
	defer r.Close()
	// O_EXCL refuses both existing files and links; incomplete writes are removed.
	f, e := r.OpenFile(name+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			r.Remove(name + ".json")
		}
	}()
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
func (s *Store) Load(name string) (*model.BaselineSnapshot, error) {
	if !nameRE.MatchString(name) {
		return nil, i18n.Errorf("err.baseline_invalid")
	}
	r, e := s.root(false)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	data, fi, e := safefile.ReadRooted(r, name+".json", maxBytes)
	if e != nil {
		return nil, e
	}
	if fi.Mode().Perm()&0077 != 0 {
		return nil, i18n.Errorf("err.baseline_private")
	}
	var b model.BaselineSnapshot
	if e = json.Unmarshal(data, &b); e != nil || !valid(&b) {
		return nil, i18n.Errorf("err.baseline_invalid")
	}
	return &b, nil
}
func (s *Store) List() ([]string, error) {
	r, e := s.root(false)
	if os.IsNotExist(e) {
		return []string{}, nil
	}
	if e != nil {
		return nil, e
	}
	defer r.Close()
	entries, e := safefile.ReadDirRooted(r, ".", 1000)
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, ent := range entries {
		n := ent.Name()
		if len(n) > 5 && filepath.Ext(n) == ".json" && ent.Type().IsRegular() {
			n = n[:len(n)-5]
			if nameRE.MatchString(n) {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names, nil
}
func (s *Store) PruneWeekly() error {
	names, e := s.List()
	if e != nil {
		return e
	}
	var weekly []string
	for _, n := range names {
		if autoRE.MatchString(n) {
			weekly = append(weekly, n)
		}
	}
	if len(weekly) <= 12 {
		return nil
	}
	r, e := s.root(false)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, n := range weekly[:len(weekly)-12] {
		if _, e = s.Load(n); e != nil {
			return e
		}
		if e = r.Remove(n + ".json"); e != nil {
			return e
		}
	}
	return nil
}
func Diff(a, b *model.BaselineSnapshot) *model.BaselineDiff {
	d := &model.BaselineDiff{Changes: []model.BaselineChange{}}
	if a == nil || b == nil {
		d.Incomplete = true
		d.Warnings = append(d.Warnings, i18n.T("warn.baseline_missing"))
		return d
	}
	d.From = a.Time
	d.To = b.Time
	if !valid(a) || !valid(b) || a.Host != b.Host {
		d.Incomplete = true
		d.Warnings = append(d.Warnings, i18n.T("warn.baseline_host"))
		return d
	}
	sections := map[string]bool{}
	for k := range a.Sections {
		sections[k] = true
	}
	for k := range b.Sections {
		sections[k] = true
	}
	for k := range sections {
		old, ok := a.Sections[k]
		cur, yes := b.Sections[k]
		if !ok || !yes || !old.Complete || !cur.Complete || old.Scope != cur.Scope {
			d.Incomplete = true
			d.Warnings = append(d.Warnings, i18n.T("warn.baseline_section", k))
			continue
		}
		for key, v := range old.Items {
			n, exists := cur.Items[key]
			if !exists {
				d.Changes = append(d.Changes, model.BaselineChange{Section: k, Key: key, Kind: "removed", Before: v})
			} else if n != v {
				d.Changes = append(d.Changes, model.BaselineChange{Section: k, Key: key, Kind: "changed", Before: v, After: n})
			}
		}
		for key, v := range cur.Items {
			if _, exists := old.Items[key]; !exists {
				d.Changes = append(d.Changes, model.BaselineChange{Section: k, Key: key, Kind: "added", After: v})
			}
		}
	}
	for i := range d.Changes {
		switch d.Changes[i].Section {
		case "ports", "ssh_keys", "suid", "capabilities":
			d.Changes[i].ReviewFirst = true
		}
	}
	sort.Slice(d.Changes, func(i, j int) bool {
		x, y := d.Changes[i], d.Changes[j]
		if x.ReviewFirst != y.ReviewFirst {
			return x.ReviewFirst
		}
		if x.Section != y.Section {
			return x.Section < y.Section
		}
		return x.Key < y.Key
	})
	sort.Slice(d.Warnings, func(i, j int) bool { return d.Warnings[i].In(i18n.EN) < d.Warnings[j].In(i18n.EN) })
	return d
}
