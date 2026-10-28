package metrics

import (
	"fmt"
	"strconv"
)

// round1, round2 — числа для подписей: «12.3», «1.75». Строки, а не
// float64, потому что подставляются в тексты каталога как факты.
func round1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
func round2(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

// humanBytes — размер для подписи: 12,3 ГБ → «12.3G».
func humanBytes(n uint64) string {
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.1fT", float64(n)/(1<<40))
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(n)/(1<<10))
	}
	return strconv.FormatUint(n, 10)
}
