package redact

import (
	"regexp"
	"strings"
)

var textSecret = regexp.MustCompile(`(?i)((?:[a-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential)[a-z0-9_]*|--password|--token)\s*(?:=|:|\s)\s*)("[^"\n]*"|'[^'\n]*'|[^\s;]+)`)

// Text also handles quoted assignments and command flags in log/config excerpts.
func Text(s string) string {
	if strings.Contains(strings.ToUpper(s), "PRIVATE KEY") {
		return "[private key material omitted]"
	}
	return textSecret.ReplaceAllString(String(s), "${1}"+Mask)
}
