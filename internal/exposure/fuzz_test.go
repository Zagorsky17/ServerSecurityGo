package exposure

import (
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// Фаззинг парсеров данных, которые читаются с сервера. go test выполняет
// только начальный корпус; долгий прогон: go test -fuzz=FuzzX ./internal/exposure.

func FuzzParseUFWRules(f *testing.F) {
	f.Add(ufwRules, 22)
	f.Add("### tuple ### allow tcp 1:65535,any 0.0.0.0/0 any ::/0 in comment=00", 80)
	f.Add("### tuple ###", 0)
	f.Fuzz(func(t *testing.T, data string, port int) {
		rules := ParseUFWRules(data)
		if len(rules) > maxUFWRules {
			t.Fatalf("правил %d", len(rules))
		}
		u := &UFW{Info: model.FirewallInfo{UFW: "active", DefaultInput: "DROP"}, rules4: rules, rules6: rules}
		switch st := u.PortState("tcp", port, FamBoth); st {
		case model.FwOpen, model.FwFiltered:
		default:
			t.Fatalf("состояние %q", st)
		}
	})
}

func FuzzParseDockerProxyArgs(f *testing.F) {
	f.Add("/usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80")
	f.Add("--host-port=1 --container-port=65535 --proto=udp")
	f.Fuzz(func(t *testing.T, cmd string) {
		b, ok := ParseDockerProxyArgs(strings.Fields(cmd))
		if !ok {
			return
		}
		if b.HostPort < 1 || b.HostPort > 65535 || b.ContainerPort < 1 || b.ContainerPort > 65535 || (b.Proto != "tcp" && b.Proto != "udp") || b.HostIP == "" {
			t.Fatalf("неверная привязка %+v", b)
		}
	})
}

func FuzzParseContainerConfig(f *testing.F) {
	f.Add([]byte(`{"ID":"abc","Name":"/x","Config":{"Image":"redis"},"State":{"Running":true},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"","HostPort":"6379"}]}}}`))
	f.Add([]byte(`{"State":{"Running":true},"NetworkSettings":{"Ports":{"/":[{}]}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, b := range ParseContainerConfig(data) {
			if b.HostPort < 1 || b.HostPort > 65535 || b.ContainerPort < 1 || b.ContainerPort > 65535 || (b.Proto != "tcp" && b.Proto != "udp") || b.HostIP == "" || len(b.ContainerID) > 12 {
				t.Fatalf("неверная привязка %+v", b)
			}
		}
	})
}

func FuzzClassify(f *testing.F) {
	for _, a := range []string{"0.0.0.0", "::", "127.0.0.1", "10.0.0.1", "::ffff:1.2.3.4", "fe80::1%eth0", "x"} {
		f.Add(a)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		s, w := Classify(addr)
		switch s {
		case model.ScopePublic, model.ScopePrivate, model.ScopeLoopback:
		default:
			t.Fatalf("область %q", s)
		}
		if w && s != model.ScopePublic {
			t.Fatalf("все интерфейсы, но %s", s)
		}
		_ = ImageBase(addr)
	})
}
