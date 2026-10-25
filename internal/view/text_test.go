package view

import (
	"testing"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                "nginx",
		"a\x1b]52;c;QUFB\x07b": "a�]52;c;QUFB�b",
		"a\tb\nc":              "a b c",
		"ss​hd":                "ss�hd",
		"‮txt.exe":             "�txt.exe",
		"кириллица é":          "кириллица é",
		"bad\xffutf8":          "bad�utf8",
		"c1\u009b31m":          "c1�31m",
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestAuditBrief: облегчённая сводка для /api/status совпадает с полной.
func TestAuditBrief(t *testing.T) {
	rep := &model.AuditReport{Time: time.Now(), Checks: []model.AuditCheck{
		{Status: model.AuditFail}, {Status: model.AuditWarn}, {Status: model.AuditWarn}, {Status: model.AuditPass}, {Status: model.AuditInfo},
	}}
	full := BuildAudit(true, true, time.Hour, rep).Brief()
	if got := BuildAuditBrief(true, true, rep); got != full || got.Fail != 1 || got.Warn != 2 || !got.Ready {
		t.Errorf("сводка %+v, полная %+v", got, full)
	}
	if got := BuildAuditBrief(false, false, nil); got.Ready || got.Enabled {
		t.Errorf("без отчёта: %+v", got)
	}
}
