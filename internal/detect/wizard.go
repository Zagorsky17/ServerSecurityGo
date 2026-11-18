package detect

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// AllowlistProposal формирует только текст; критические процессы и сильные сигналы исключены.
func AllowlistProposal(p *model.Process, f model.Finding) string {
	if p == nil || p.Risk >= model.RiskCritical || f.Strong || f.Suppressed || f.Category == model.CatInfo || f.ID == "" || !filepath.IsAbs(p.Exe) || filepath.Clean(p.Exe) != p.Exe || p.ExeDeleted {
		return ""
	}
	if strings.IndexFunc(p.Exe, unicode.IsControl) >= 0 || strings.IndexFunc(p.User, unicode.IsControl) >= 0 {
		return ""
	}
	// Exact не даёт символам в имени недоверенного файла стать шаблоном.
	data, e := json.MarshalIndent(struct {
		Rules []AllowRule `json:"rules"`
	}{[]AllowRule{{Exe: p.Exe, Exact: true, User: p.User, Rules: []string{f.ID}}}}, "", "  ")
	if e != nil {
		return ""
	}
	return string(data)
}
