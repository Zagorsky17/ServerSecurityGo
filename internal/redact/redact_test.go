package redact

import (
	"slices"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	cases := []struct {
		in, want []string
	}{
		{[]string{"app", "--password=hunter2"}, []string{"app", "--password=***"}},
		{[]string{"app", "--api-key", "abc123", "--port", "80"}, []string{"app", "--api-key", "***", "--port", "80"}},
		{[]string{"app", "-token=xyz"}, []string{"app", "-token=***"}},
		{[]string{"mysql", "-uroot", "-pS3cret", "db"}, []string{"mysql", "-uroot", "-p***", "db"}},
		// У ssh -p — это порт, его маскировать нельзя.
		{[]string{"ssh", "-p", "2222", "host"}, []string{"ssh", "-p", "2222", "host"}},
		{[]string{"psql", "postgresql://user:pa55@db/app"}, []string{"psql", "postgresql://user:***@db/app"}},
		{[]string{"sh", "-c", "PGPASSWORD=topsecret pg_dump app"}, []string{"sh", "-c", "PGPASSWORD=*** pg_dump app"}},
		{[]string{"curl", "-H", "Authorization: Bearer eyJabc.def"}, []string{"curl", "-H", "Authorization: Bearer ***"}},
		{[]string{"nginx: worker process"}, []string{"nginx: worker process"}},
	}
	for _, c := range cases {
		if got := Args(c.in); !slices.Equal(got, c.want) {
			t.Errorf("Args(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if Args(nil) != nil {
		t.Error("nil → nil")
	}
}

func TestKnownTokens(t *testing.T) {
	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_" + strings.Repeat("a", 36),
		"123456789:" + strings.Repeat("B", 35),
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	}
	for _, s := range secrets {
		out := String("run --x " + s)
		if strings.Contains(out, s) {
			t.Errorf("секрет не замаскирован: %s", out)
		}
	}
}

func TestDetectionPatternsSurvive(t *testing.T) {
	// Маскирование не должно ломать признаки, которые ищет анализатор.
	out := Join(Args([]string{"xmrig", "-o", "stratum+tcp://wallet:x@pool.example:3333", "--donate-level=1"}))
	if !strings.Contains(out, "stratum+tcp://") || !strings.Contains(out, "--donate-level=1") {
		t.Errorf("признаки потеряны: %s", out)
	}
	if strings.Contains(out, "wallet:x@") {
		t.Errorf("учётные данные в URL не замаскированы: %s", out)
	}
}

func TestJoin(t *testing.T) {
	got := Join([]string{"sh", "-c", "echo 'hi' there", ""})
	want := `sh -c 'echo '\''hi'\'' there' ''`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
