package redact

import (
	"regexp"
	"strings"
)

var textSecret = regexp.MustCompile(`(?i)((?:[a-z0-9_]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential)[a-z0-9_]*|--password|--token)\s*(?:=|:|\s)\s*)("[^"\n]*"|'[^'\n]*'|[^\s;]+)`)

// Text также маскирует присваивания в кавычках и флаги команд в журналах и конфигурациях.
func Text(s string) string {
	if strings.Contains(strings.ToUpper(s), "PRIVATE KEY") {
		return "[private key material omitted]"
	}
	return textSecret.ReplaceAllString(String(s), "${1}"+Mask)
}
