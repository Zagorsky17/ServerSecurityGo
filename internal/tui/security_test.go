package tui

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/view"
	"strings"
	"testing"
)

func TestProcessSecurityDetail(t *testing.T) {
	for _, lang := range []i18n.Lang{i18n.RU, i18n.EN} {
		nnp, seccomp := 1, 2
		p := &model.Process{Key: "10-1", PID: 10, Name: "bash", ContainerName: "app", ContainerImage: "image", Security: &model.ProcessSecurity{CapEff: []string{"CAP_SYS_ADMIN"}, CapPrm: []string{}, CapBnd: []string{"CAP_NET_RAW"}, CapAmb: []string{}, NoNewPrivs: &nnp, Seccomp: &seccomp}}
		a := New(Options{Lang: lang})
		a.detailKey = p.Key
		a.detail = &view.Detail{Process: p}
		b := &lb{w: 120, lang: lang}
		a.processDetail(b, p.Key)
		var text strings.Builder
		for _, line := range b.lines {
			for _, s := range line {
				text.WriteString(s.t)
			}
			text.WriteByte('\n')
		}
		for _, want := range []string{"CapEff", "CAP_SYS_ADMIN", "CapBnd", "CAP_NET_RAW", "NoNewPrivs", "Seccomp", "app (image)"} {
			if !strings.Contains(text.String(), want) {
				t.Errorf("missing %s: %s", want, text.String())
			}
		}
	}
}
