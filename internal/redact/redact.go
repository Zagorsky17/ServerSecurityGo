// Пакет redact маскирует секреты в командных строках процессов.
//
// Командная строка видна любому пользователю системы, но всё равно
// нередко содержит пароли (mysql -pSECRET), токены (--token=...) и
// учётные данные в URL. Приложение не должно тиражировать их в интерфейс,
// историю и логи, поэтому маскирование выполняется сразу после чтения,
// до анализа и сохранения.
package redact

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Mask — чем заменяется секрет.
const Mask = "***"

var (
	// --password=..., --api-key=..., -token=... (имя флага содержит
	// «секретное» слово, значение после «=»).
	flagWithValue = regexp.MustCompile(`(?i)^(--?[a-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key|apikey|auth|credential|private[-_]?key|access[-_]?key)[a-z0-9_.-]*)=(.+)$`)
	// Флаг, значение которого идёт следующим аргументом: --password SECRET.
	flagAlone = regexp.MustCompile(`(?i)^--?[a-z0-9_.-]*(?:password|passwd|secret|token|api[-_]?key|apikey|credential|private[-_]?key|access[-_]?key)[a-z0-9_.-]*$`)
	// Учётные данные в URL: scheme://user:pass@host.
	urlCreds = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+):([^/\s@]+)@`)
	// Заголовок авторизации внутри аргумента.
	authHeader = regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+`)
	// KEY=value внутри строк (sh -c "PGPASSWORD=... psql"), в том числе
	// составные имена вроде DB_PASSWORD, GITHUB_TOKEN.
	kvSecret = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:password|passwd|pwd|secret|token|api_?key|access_?key)[a-z0-9_]*)=([^\s&;'"]+)`)
	// Узнаваемые форматы ключей: AWS, GitHub, Slack, JWT, токен бота вида «123456789:…».
	knownTokens = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}\b|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b\d{8,10}:[A-Za-z0-9_-]{35}\b`)
)

// mysqlLike — программы, у которых «-pПАРОЛЬ» означает пароль. У других
// программ -p чаще всего порт (ssh -p 22), его трогать нельзя.
var mysqlLike = map[string]bool{
	"mysql": true, "mysqldump": true, "mysqladmin": true, "mariadb": true,
	"mariadb-dump": true, "mysqlimport": true, "mysqlcheck": true,
}

// Args возвращает копию аргументов с замаскированными секретами.
func Args(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	isMySQL := mysqlLike[filepath.Base(args[0])]
	maskNext := false
	for i, a := range args {
		if maskNext {
			out[i] = Mask
			maskNext = false
			continue
		}
		switch {
		case flagWithValue.MatchString(a):
			out[i] = flagWithValue.ReplaceAllString(a, "${1}="+Mask)
			continue
		case flagAlone.MatchString(a):
			out[i] = a
			maskNext = true
			continue
		case isMySQL && strings.HasPrefix(a, "-p") && len(a) > 2:
			out[i] = "-p" + Mask
			continue
		}
		out[i] = String(a)
	}
	return out
}

// String маскирует секреты внутри произвольной строки.
func String(s string) string {
	s = urlCreds.ReplaceAllString(s, "${1}:"+Mask+"@")
	s = authHeader.ReplaceAllString(s, "${1}"+Mask)
	s = kvSecret.ReplaceAllString(s, "${1}="+Mask)
	s = knownTokens.ReplaceAllString(s, Mask)
	return s
}

// Join собирает аргументы в одну строку для показа. Аргументы с
// пробелами берутся в кавычки, чтобы строку можно было прочитать
// однозначно.
func Join(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}
