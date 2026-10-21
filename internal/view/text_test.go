package view

import "testing"

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
