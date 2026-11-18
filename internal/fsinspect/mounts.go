package fsinspect

import (
	"os"
	"path"
	"strings"
)

type Mount struct {
	Point, Type string
	Options     map[string]bool
}

func ParseMountInfo(data string) ([]Mount, error) {
	var out []Mount
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(data, "\n") {
		if line == "" {
			continue
		}
		halves := strings.SplitN(line, " - ", 2)
		if len(halves) != 2 {
			return nil, os.ErrInvalid
		}
		a, b := strings.Fields(halves[0]), strings.Fields(halves[1])
		if len(a) < 6 || len(b) < 3 || len(out) >= 10000 {
			return nil, os.ErrInvalid
		}
		p := decode.Replace(a[4])
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
			return nil, os.ErrInvalid
		}
		m := Mount{Point: p, Type: b[0], Options: map[string]bool{}}
		for _, o := range strings.Split(a[5], ",") {
			m.Options[o] = true
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, os.ErrInvalid
	}
	return out, nil
}
func NetworkFS(t string) bool {
	return strings.HasPrefix(t, "fuse") || strings.HasPrefix(t, "nfs") || t == "cifs" || t == "smb3" || t == "9p" || t == "ceph" || t == "afs" || t == "autofs" || t == "virtiofs"
}
func MountAt(mounts []Mount, p string) (Mount, bool) {
	var found Mount
	ok := false
	for _, m := range mounts {
		if m.Point == "/" || under(p, m.Point) {
			if !ok || len(m.Point) > len(found.Point) {
				found = m
				ok = true
			}
		}
	}
	return found, ok
}
