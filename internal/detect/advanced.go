package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var bpfTools = set("systemd", "systemd-networkd", "cilium", "cilium-agent", "falco", "tracee", "bpftrace", "datadog-agent", "pixie", "node_exporter")
var packetTools = set("dhclient", "tcpdump", "wireshark", "dumpcap", "tshark", "suricata", "zeek", "systemd-networkd", "NetworkManager", "keepalived", "lldpd")

func expectedTool(p *model.Process, names map[string]bool, owners map[string]bool) bool {
	return names[filepath.Base(p.Exe)] && owners != nil && owners[p.Exe] && p.ExeInfo != nil && p.ExeInfo.UID == 0 && !p.ExeInfo.WorldWritable && !p.ExeInfo.GroupWritable && !p.ExeDeleted
}
func ruleAdvanced(p *model.Process, c *Context) []model.Finding {
	if skipUserRules(p) {
		return nil
	}
	var out []model.Finding
	if len(p.BPF) > 0 {
		weight, strong := 12, false
		known := expectedTool(p, bpfTools, c.Owners)
		if known {
			weight = 0
		}
		var ev []i18n.Msg
		for _, b := range p.BPF {
			if !known && b.Kind == "bpf-prog" && slices.Contains([]uint32{1, 2, 3, 4, 5, 6, 17, 26}, b.Type) {
				weight = 35
				strong = true
			}
			if len(ev) < 20 {
				ev = append(ev, i18n.L(fmt.Sprintf("fd=%d %s type=%d id=%d tag=%s", b.FD, b.Kind, b.Type, b.ID, b.Tag)))
			}
		}
		cat := model.CatPrivilege
		if known {
			cat = model.CatInfo
		}
		out = append(out, model.Finding{ID: "bpf_unexpected", Title: i18n.T("rule.bpf_unexpected.title"), Category: cat, Weight: weight, Strong: strong, Evidence: ev, Recommendation: i18n.T("rule.bpf_unexpected.rec")})
	}
	var packet []i18n.Msg
	for _, s := range p.Sockets {
		if s.Proto == "packet" && len(packet) < 20 {
			packet = append(packet, i18n.L(fmt.Sprintf("inode=%d ifindex=%d protocol=%#x type=%d", s.Inode, s.PacketInterface, s.PacketProtocol, s.PacketType)))
		}
	}
	if len(packet) > 0 {
		weight, strong, cat := 35, true, model.CatNetwork
		if expectedTool(p, packetTools, c.Owners) {
			weight, strong, cat = 0, false, model.CatInfo
		}
		out = append(out, model.Finding{ID: "raw_packet_socket", Title: i18n.T("rule.raw_packet_socket.title"), Category: cat, Weight: weight, Strong: strong, Evidence: packet, Recommendation: i18n.T("rule.raw_packet_socket.rec")})
	}
	if x := p.Executable; x != nil && !x.Incomplete && x.ELF {
		if x.Packing != "" {
			weight, cat := 15, model.CatIntegrity
			if x.Packing == "entropy" {
				weight, cat = 0, model.CatInfo
			}
			out = append(out, model.Finding{ID: "exe_packed", Title: i18n.T("rule.exe_packed.title"), Category: cat, Weight: weight, Evidence: []i18n.Msg{i18n.L(fmt.Sprintf("%s entropy=%.3f observed=%s", x.Packing, x.Entropy, x.Time.UTC().Format(time.RFC3339)))}, Recommendation: i18n.T("rule.exe_packed.rec")})
		}
		if x.Static && inTemp(p.Exe) {
			out = append(out, model.Finding{ID: "exe_static_in_temp", Title: i18n.T("rule.exe_static_in_temp.title"), Category: model.CatIntegrity, Weight: 8, Evidence: []i18n.Msg{i18n.L(p.Exe)}, Recommendation: i18n.T("rule.exe_static_in_temp.rec")})
		}
	}
	return out
}
func PromiscuousInterfaces(host string, procs []*model.Process, owners map[string]bool) []model.SystemFinding {
	unavailable := model.SystemFinding{Risk: model.RiskInfo, Finding: model.Finding{ID: "promisc_unavailable", Category: model.CatInfo, Title: i18n.T("warn.promisc_unavailable")}}

	root, e := os.OpenRoot(host)
	if e != nil {
		return []model.SystemFinding{unavailable}
	}
	defer root.Close()
	entries, e := safefile.ReadDirRooted(root, "sys/class/net", 256)
	if e != nil {
		return []model.SystemFinding{unavailable}
	}
	var out []model.SystemFinding
	incomplete := false
	for _, entry := range entries {
		n, e := safefile.ResolveRooted(root, "sys/class/net/"+entry.Name()+"/flags")
		if e != nil {
			incomplete = true
			continue
		}
		data, _, e := safefile.ReadRooted(root, n, 128)
		if e != nil {
			incomplete = true
			continue
		}
		flags, e := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 32)
		if e != nil {
			incomplete = true
			continue
		}
		if flags&0x100 == 0 {
			continue
		}
		expected := false
		indexPath, indexErr := safefile.ResolveRooted(root, "sys/class/net/"+entry.Name()+"/ifindex")
		if indexErr == nil {
			indexData, _, err := safefile.ReadRooted(root, indexPath, 128)
			index, parseErr := strconv.Atoi(strings.TrimSpace(string(indexData)))
			if err == nil && parseErr == nil && index > 0 {
				for _, p := range procs {
					if expectedTool(p, packetTools, owners) && !slices.Contains(p.ForeignNS, "net") {
						for _, s := range p.Sockets {
							expected = expected || (s.Proto == "packet" && (s.PacketInterface == 0 || s.PacketInterface == index))
						}
					}
				}
			}
		}
		risk := model.RiskMedium
		if expected {
			risk = model.RiskInfo
		}
		out = append(out, model.SystemFinding{Path: "/sys/class/net/" + entry.Name() + "/flags", Risk: risk, Finding: model.Finding{ID: "iface_promisc", Category: model.CatNetwork, Title: i18n.T("rule.iface_promisc.title"), Evidence: []i18n.Msg{i18n.L(entry.Name() + " IFF_PROMISC")}, Recommendation: i18n.T("rule.iface_promisc.rec")}})
	}
	if incomplete {
		out = append(out, unavailable)
	}
	return out
}
