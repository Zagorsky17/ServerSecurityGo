package procfs

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

func ParseBPFInfo(data, kind string) (model.BPFDescriptor, error) {
	out := model.BPFDescriptor{Kind: kind}
	prefix := "prog_"
	if kind == "bpf-map" {
		prefix = "map_"
	} else if kind != "bpf-prog" {
		return out, os.ErrInvalid
	}
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == prefix+"type" || k == prefix+"id" || k == "prog_tag" {
			if _, dup := values[k]; dup {
				return out, os.ErrInvalid
			}
			values[k] = strings.TrimSpace(v)
		}
	}
	typ, e := strconv.ParseUint(values[prefix+"type"], 10, 32)
	if e != nil || typ == 0 {
		return out, os.ErrInvalid
	}
	id, e := strconv.ParseUint(values[prefix+"id"], 10, 32)
	if e != nil || id == 0 {
		return out, os.ErrInvalid
	}
	out.Type = uint32(typ)
	out.ID = uint32(id)
	if kind == "bpf-prog" {
		tag, e := hex.DecodeString(values["prog_tag"])
		if e != nil || len(tag) != 8 {
			return out, os.ErrInvalid
		}
		out.Tag = hex.EncodeToString(tag)
	}
	return out, nil
}
func (f *FS) readBPF(pid string, fd int, target string, p *model.Process) {
	kind := strings.Trim(strings.TrimPrefix(target, "anon_inode:"), "[]")
	if kind != "bpf-prog" && kind != "bpf-map" {
		return
	}
	data, _, e := safefile.ReadRegular(f.path(pid, "fdinfo", strconv.Itoa(fd)), 4096, false)
	if e != nil {
		p.Access = append(p.Access, "bpf:fdinfo")
		return
	}
	b, e := ParseBPFInfo(string(data), kind)
	if e != nil {
		p.Access = append(p.Access, "bpf:format")
		return
	}
	again, e := os.Readlink(f.path(pid, "fd", strconv.Itoa(fd)))
	if e != nil || again != target {
		p.Access = append(p.Access, "bpf:changed")
		return
	}
	b.FD = fd
	p.BPF = append(p.BPF, b)
}
func ParsePacketTable(data, ns string) ([]model.Socket, error) {
	var out []model.Socket
	lines := strings.Split(strings.TrimSpace(data), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "Inode") || !strings.Contains(lines[0], "Iface") {
		return nil, os.ErrInvalid
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v := strings.Fields(line)
		if len(v) != 9 || len(out) >= 10000 {
			return out, os.ErrInvalid
		}
		typ, e1 := strconv.ParseUint(v[2], 10, 16)
		proto, e2 := strconv.ParseUint(v[3], 16, 16)
		iface, e3 := strconv.ParseUint(v[4], 10, 31)
		uid, e4 := strconv.ParseUint(v[7], 10, 32)
		ino, e5 := strconv.ParseUint(v[8], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || ino == 0 || (typ != 2 && typ != 3) {
			return out, os.ErrInvalid
		}
		out = append(out, model.Socket{Proto: "packet", State: "RAW", Inode: ino, UID: int(uid), NetNS: ns, PacketInterface: int(iface), PacketProtocol: uint16(proto), PacketType: int(typ)})
	}
	return out, nil
}
func (f *FS) ReadPacketTable(pid int, ns string) ([]model.Socket, error) {
	base := f.path("net")
	if pid > 0 {
		base = f.path(strconv.Itoa(pid), "net")
	}
	data, _, e := safefile.ReadRegular(filepath.Join(base, "packet"), 2<<20, true)
	if e != nil {
		return nil, e
	}
	return ParsePacketTable(string(data), ns)
}
