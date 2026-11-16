package exposure

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

func TestContainerSecurityRules(t *testing.T) {
	var c containerConfig
	if err := json.Unmarshal([]byte(`{"ID":"abcdef","Name":"/app","Config":{"Image":"example/app","User":"root:1000","Env":["PASSWORD=DO_NOT_LEAK","API_TOKEN=DO_NOT_LEAK","NORMAL=value"]},"State":{"Running":true}}`), &c); err != nil {
		t.Fatal(err)
	}
	var h hostConfig
	if err := json.Unmarshal([]byte(`{"Privileged":true,"Binds":["/:/host:ro","/run/docker.sock:/sock:ro"],"CapAdd":["CAP_SYS_ADMIN","NET_ADMIN"],"NetworkMode":"host","PidMode":"host","SecurityOpt":["seccomp=unconfined","apparmor:unconfined"],"Devices":[{"PathOnHost":"/dev/nvme0n1"}]}`), &h); err != nil {
		t.Fatal(err)
	}
	findings := containerChecks(c, h)
	got := map[string]model.SystemFinding{}
	for _, f := range findings {
		got[f.ID] = f
	}
	for id, risk := range map[string]model.Risk{"ctr_privileged": model.RiskCritical, "ctr_docker_sock": model.RiskCritical, "ctr_host_root_mount": model.RiskHigh, "ctr_dangerous_caps": model.RiskHigh, "ctr_host_namespaces": model.RiskHigh, "ctr_no_seccomp": model.RiskHigh, "ctr_no_apparmor": model.RiskHigh, "ctr_runs_as_root": model.RiskLow, "ctr_devices": model.RiskCritical, "ctr_secrets_in_env": model.RiskInfo} {
		if f, ok := got[id]; !ok || f.Risk != risk {
			t.Errorf("%s: %+v", id, f)
		}
	}
	data, _ := json.Marshal(struct {
		Config   containerConfig
		Findings []model.SystemFinding
	}{c, findings})
	if strings.Contains(string(data), "DO_NOT_LEAK") || strings.Contains(string(data), "=value") {
		t.Fatal("environment values retained")
	}
}
func TestContainerSecurityCalibration(t *testing.T) {
	for _, tc := range []struct {
		source string
		hit    bool
	}{{"/etc", true}, {"/etc/ssh", true}, {"/etcetera", false}, {"/opt/app", false}, {"/root/../etc", true}, {"named-volume", false}} {
		var c containerConfig
		c.ID = "test"
		c.Config.User = "1000:1000"
		c.Config.Image = "app"
		h := hostConfig{Binds: []string{tc.source + ":/data"}}
		got := containerChecks(c, h)
		if (len(got) > 0) != tc.hit {
			t.Fatalf("%s: %+v", tc.source, got)
		}
	}
	var c containerConfig
	c.ID = "test"
	c.Config.User = "1000"
	c.Config.Image = "traefik:v3"
	got := containerChecks(c, hostConfig{Binds: []string{"/var/run/docker.sock:/sock:ro"}})
	for _, f := range got {
		if f.ID == "ctr_docker_sock" && f.Risk != model.RiskHigh {
			t.Fatalf("known image: %+v", f)
		}
	}
	// --mount и сохранённый MountPoints тоже проверяются.
	var h hostConfig
	json.Unmarshal([]byte(`{"Mounts":[{"Type":"bind","Source":"/etc","ReadOnly":false}]}`), &h)
	if f := containerChecks(c, h); len(f) != 1 || f[0].Risk != model.RiskCritical {
		t.Fatalf("mount: %+v", f)
	}
	json.Unmarshal([]byte(`{"MountPoints":{"/data":{"Type":"bind","Source":"/root","RW":false}}}`), &c)
	if f := containerChecks(c, hostConfig{}); len(f) != 1 || f[0].Risk != model.RiskHigh {
		t.Fatalf("mountpoints: %+v", f)
	}
}
func TestReadDockerSecurityAndProcessAssociation(t *testing.T) {
	root := t.TempDir()
	base := "var/lib/docker/containers/" + cid1 + "/"
	writeFiles(t, root, map[string]string{base + "config.v2.json": fmt.Sprintf(`{"ID":%q,"Name":"/web","Config":{"Image":"example/web","User":"1000","Env":["SECRET=NEVER_SERIALIZE"]},"State":{"Running":true}}`, cid1), base + "hostconfig.json": `{"Privileged":true}`})
	p := &model.Process{Container: cid1[:12], ContainerRuntime: "docker"}
	rep := Build(Input{HostRoot: root, Procs: []*model.Process{p}})
	if p.ContainerName != "web" || p.ContainerImage != "example/web" {
		t.Fatalf("association: %+v", p)
	}
	got := SystemFindings(rep)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	data, _ := json.Marshal(rep)
	if strings.Contains(string(data), "NEVER_SERIALIZE") {
		t.Fatal("secret in API")
	}
	os.Remove(filepath.Join(root, base, "hostconfig.json"))
	rep = Build(Input{HostRoot: root})
	incomplete := false
	for _, f := range rep.ContainerFindings {
		incomplete = incomplete || f.Incomplete()
	}
	if !incomplete {
		t.Fatal("missing hostconfig marked clean")
	}
}
func TestDockerMetadataErrors(t *testing.T) {
	for _, body := range []string{"{", `{"ID":"wrong"}`} {
		t.Run(body, func(t *testing.T) {
			root := t.TempDir()
			writeFiles(t, root, map[string]string{"var/lib/docker/containers/" + cid1 + "/config.v2.json": body})
			r := readDockerData(root, true)
			if len(r.warnings) == 0 || len(r.findings) == 0 || !r.findings[0].Incomplete() {
				t.Fatal("invalid config marked clean")
			}
		})
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"config.v2.json": fmt.Sprintf(`{"ID":%q,"State":{"Running":true}}`, cid1)})
	dir := filepath.Join(root, "var/lib/docker/containers")
	os.MkdirAll(dir, 0700)
	os.Symlink(outside, filepath.Join(dir, cid1))
	r := readDockerData(root, true)
	if len(r.containers) > 0 || len(r.warnings) == 0 {
		t.Fatal("outside root followed")
	}
}
func FuzzContainerSecurity(f *testing.F) {
	f.Add([]byte(`{"ID":"test","Config":{"Env":["TOKEN=secret"]}}`), []byte(`{"Binds":["/:/host:ro"]}`))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a) > 1<<20 || len(b) > 1<<20 {
			return
		}
		var c containerConfig
		var h hostConfig
		if json.Unmarshal(a, &c) == nil && json.Unmarshal(b, &h) == nil {
			got := containerChecks(c, h)
			if len(got) > len(containerMessages) {
				t.Fatal("unbounded findings")
			}
			for _, f := range got {
				if len(f.Evidence) > 12 {
					t.Fatal("evidence limit")
				}
			}
		}
	})
}

func TestDockerSocketPermissionsAndGroup(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "ssg-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(rootDir) })
	os.MkdirAll(filepath.Join(rootDir, "run"), 0700)
	ln, err := net.Listen("unix", filepath.Join(rootDir, "run/docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	writeFiles(t, rootDir, map[string]string{"etc/group": "docker:x:900:alice,bob\n"})
	os.Chmod(filepath.Join(rootDir, "run/docker.sock"), 0666)
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got := dockerSocketChecks(root)
	if len(got) != 2 {
		t.Fatalf("group and world access: %+v", got)
	}
	for _, f := range got {
		if f.ID != "ctr_sock_perms" {
			t.Fatalf("%+v", f)
		}
	}
	os.Chmod(filepath.Join(rootDir, "run/docker.sock"), 0600)
	got = dockerSocketChecks(root)
	expected := 1
	if os.Geteuid() != 0 {
		expected++
	}
	if len(got) != expected {
		t.Fatalf("root-only mode: %+v", got)
	}
}

func TestDockerMetadataLimitsAndDaemonErrors(t *testing.T) {
	root := t.TempDir()
	path := "var/lib/docker/containers/" + cid1 + "/config.v2.json"
	writeFiles(t, root, map[string]string{path: strings.Repeat(" ", maxContainerConfig+1)})
	got := readDockerData(root, true)
	if len(got.findings) == 0 || !got.findings[0].Incomplete() {
		t.Fatal("oversized config marked clean")
	}
	writeFiles(t, root, map[string]string{"etc/docker/daemon.json": "{malformed"})
	got = readDockerData(root, true)
	if len(got.warnings) == 0 {
		t.Fatal("invalid daemon config hidden")
	}
}
