//go:build linux

package exposure

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Создание отдельного остановленного контейнера выполняет CI-скрипт.
func TestRealDockerSecurity(t *testing.T) {
	id := os.Getenv("SSG_TEST_CONTAINER_ID")
	if id == "" {
		t.Skip("isolated Docker fixture not supplied")
	}
	data := readDockerData("/", true)
	found := map[string]bool{}
	for _, f := range data.findings {
		if f.Path == "docker:"+id {
			found[f.ID] = true
		}
	}
	for _, rule := range []string{"ctr_privileged", "ctr_docker_sock", "ctr_host_root_mount", "ctr_dangerous_caps", "ctr_no_seccomp", "ctr_runs_as_root", "ctr_secrets_in_env"} {
		if !found[rule] {
			t.Errorf("missing %s; got %v", rule, found)
		}
	}
	b, _ := json.Marshal(data.findings)
	if strings.Contains(string(b), "SSG_SENTINEL_SECRET_VALUE") {
		t.Fatal("environment value leaked")
	}
}
