package investigate

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

// ReadEvents только читает историю: разовые команды не открывают хранилище для записи.
func ReadEvents(dir string, since time.Time) ([]model.Event, bool) {
	if dir == "" {
		return nil, false
	}
	var out []model.Event
	complete := true
	for _, name := range []string{"events.jsonl.1", "events.jsonl"} {
		f, _, err := safefile.Open(filepath.Join(dir, name), false)
		if err != nil {
			if !os.IsNotExist(err) {
				complete = false
			}
			continue
		}
		lr := &io.LimitedReader{R: f, N: 20 << 20}
		sc := bufio.NewScanner(lr)
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			var e model.Event
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				complete = false
				continue
			}
			if !e.Time.Before(since) {
				out = append(out, e)
			}
			if len(out) > 10000 {
				out = out[len(out)-10000:]
				complete = false
			}
		}
		if sc.Err() != nil || lr.N == 0 {
			complete = false
		}
		f.Close()
	}
	return out, complete
}
func Timeline(snap *model.Snapshot, events []model.Event, recent *model.RecentReport, since time.Time) []model.TimelineEvent {
	out := []model.TimelineEvent{}
	for _, e := range events {
		if e.Time.Before(since) {
			continue
		}
		out = append(out, model.TimelineEvent{Time: e.Time, Kind: e.Type, Source: "events.jsonl", Detail: e.Details, Risk: e.Risk})
	}
	if snap != nil && snap.Auth != nil {
		for _, e := range snap.Auth.Events {
			if e.Time.Before(since) {
				continue
			}
			out = append(out, model.TimelineEvent{Time: e.Time, Kind: e.Kind, Source: e.Source, Detail: i18n.L(e.User + " " + e.IP + " " + e.Method + " " + e.Detail), Risk: e.Risk, VerifyCommands: []string{"journalctl -u ssh --since " + Quote(e.Time.Add(-time.Minute).Format(time.RFC3339)) + " --until " + Quote(e.Time.Add(time.Minute).Format(time.RFC3339))}})
		}
	}
	if recent != nil {
		for _, f := range recent.Files {
			t := f.ChangeTime
			if t.IsZero() {
				t = f.ModTime
			}
			if t.Before(since) {
				continue
			}
			out = append(out, model.TimelineEvent{Time: t, Kind: "file", Source: f.Path, Detail: i18n.T("ev.file_times", f.Path, f.ModTime.Format(time.RFC3339), f.ChangeTime.Format(time.RFC3339), f.PackageWindow, f.TimeMismatch), Risk: model.RiskInfo, VerifyCommands: []string{"stat -- " + Quote(f.Path)}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 10000 {
		out = out[:10000]
	}
	return out
}
