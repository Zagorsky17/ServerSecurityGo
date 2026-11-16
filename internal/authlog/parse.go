// Package authlog reads bounded local authentication records without running commands.
package authlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
	"github.com/Zagorsky17/ServerSecurityGo/internal/redact"
)

var sshLine = regexp.MustCompile(`^(Accepted|Failed) ([a-zA-Z/-]+) for (?:invalid user )?(\S+) from (\S+) port [0-9]+(?: ssh2)?(?:: (.*))?$`)
var daemonLine = regexp.MustCompile(`(?:^|\s)(sshd|sshd-session|sudo|su|useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chpasswd)(?:\[([0-9]+)\])?:\s*(.*)$`)

// ParseLine never retains the original log line or an unredacted sudo command.
func ParseLine(line, source string, reference time.Time, loc *time.Location) (model.LoginEvent, bool) {
	e := model.LoginEvent{Source: source}
	if len(line) > 64<<10 {
		return e, false
	}
	if loc == nil {
		loc = time.UTC
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return e, false
	}
	var err error
	e.Time, err = time.Parse(time.RFC3339Nano, fields[0])
	if err != nil {
		if len(line) < 15 {
			return e, false
		}
		e.Time, err = time.ParseInLocation("2006 Jan _2 15:04:05", fmt.Sprintf("%d %s", reference.Year(), line[:15]), loc)
		if err != nil {
			return e, false
		}
		// Syslog has no year. Infer the most recent occurrence, not a future year.
		if e.Time.After(reference.Add(24 * time.Hour)) {
			e.Time = e.Time.AddDate(-1, 0, 0)
		}
	}
	m := daemonLine.FindStringSubmatch(line)
	if m == nil {
		return e, false
	}
	e.PID, _ = strconv.Atoi(m[2])
	msg := m[3]
	if m[1] == "sshd" || m[1] == "sshd-session" {
		a := sshLine.FindStringSubmatch(msg)
		if a == nil {
			return e, false
		}
		ip, err := netip.ParseAddr(a[4])
		if err != nil {
			return e, false
		}
		e.Kind = "login"
		if a[1] == "Failed" {
			e.Kind = "failed"
		}
		e.User, e.IP, e.Method = a[3], ip.Unmap().String(), a[2]
		if e.Method == "publickey" {
			for _, f := range strings.Fields(a[5]) {
				if strings.HasPrefix(f, "SHA256:") {
					if b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(f, "SHA256:")); err == nil && len(b) == 32 {
						e.Fingerprint = f
					}
					break
				}
			}
		}
	} else {
		e.Kind = m[1]
		if m[1] == "sudo" {
			e.User = strings.TrimSpace(strings.SplitN(msg, ":", 2)[0])
			if i := strings.Index(msg, "COMMAND="); i >= 0 {
				e.Detail = redact.Text(msg[i+8:])
			}
			for _, part := range strings.Split(msg, ";") {
				if i := strings.Index(part, "TTY="); i >= 0 {
					e.TTY = strings.TrimSpace(part[i+4:])
				}
			}
			if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "NOT in sudoers") || strings.Contains(msg, "authentication failure") {
				e.Kind = "sudo_failed"
			}
		} else {
			// Keep structured account/session facts; arbitrary PAM text can contain secrets.
			for _, f := range strings.Fields(msg) {
				if strings.HasPrefix(f, "name=") {
					e.User = strings.TrimRight(strings.TrimPrefix(f, "name="), ",")
				}
			}
			if m[1] == "su" {
				e.Detail = redact.Text(msg)
			}
		}
	}
	return e, true
}

// Keys handles quoted authorized_keys options before the key type and blob.
func Keys(data []byte, user, path string) []model.SSHKey {
	var out []model.SSHKey
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || len(line) > 64<<10 {
			continue
		}
		fields := keyFields(line)
		for i := 0; i+1 < len(fields); i++ {
			typ := fields[i]
			if !strings.HasPrefix(typ, "ssh-") && !strings.HasPrefix(typ, "ecdsa-") && !strings.HasPrefix(typ, "sk-") {
				continue
			}
			b, err := base64.StdEncoding.DecodeString(fields[i+1])
			if err != nil || len(b) < 4 {
				continue
			}
			n := int(binary.BigEndian.Uint32(b))
			if n > len(b)-4 || n < 1 || string(b[4:4+n]) != typ {
				continue
			}
			sum := sha256.Sum256(b)
			out = append(out, model.SSHKey{User: user, Path: path, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: strings.Join(fields[i+2:], " ")})
			break
		}
	}
	return out
}
func keyFields(s string) []string {
	var out []string
	start := -1
	quote, escape := false, false
	for i, r := range s {
		if start < 0 {
			if r == ' ' || r == '\t' {
				continue
			}
			start = i
		}
		if escape {
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			continue
		}
		if r == '"' {
			quote = !quote
		}
		if !quote && (r == ' ' || r == '\t') {
			out = append(out, s[start:i])
			start = -1
		}
	}
	if start >= 0 && !quote {
		out = append(out, s[start:])
	}
	return out
}

// Utmp decodes glibc little-endian amd64 (384) and arm64 (400) records.
// Layout comes from the inspected architecture; never guess from a divisible file size.
func Utmp(data []byte, source string, arm64 bool) ([]model.LoginEvent, bool) {
	size, off := 384, 340
	if arm64 {
		size, off = 400, 344
	}
	bad := len(data)%size != 0
	var out []model.LoginEvent
	str := func(b []byte) string {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	for len(data) >= size {
		b := data[:size]
		data = data[size:]
		typ := binary.LittleEndian.Uint16(b)
		if typ == 0 {
			continue
		}
		if typ > 9 {
			bad = true
			continue
		}
		sec := int64(binary.LittleEndian.Uint32(b[off:]))
		usec := int64(binary.LittleEndian.Uint32(b[off+4:]))
		if arm64 {
			sec = int64(binary.LittleEndian.Uint64(b[off:]))
			usec = int64(binary.LittleEndian.Uint64(b[off+8:]))
		}
		if sec <= 0 || usec < 0 || usec >= 1e6 {
			bad = true
			continue
		}
		kind := ""
		switch typ {
		case 2:
			kind = "boot"
		case 7:
			kind = "session"
		case 8:
			kind = "logout"
		default:
			continue
		}
		if strings.Contains(source, "btmp") {
			kind = "failed_session"
		}
		e := model.LoginEvent{Time: time.Unix(sec, usec*1000), Kind: kind, PID: int(int32(binary.LittleEndian.Uint32(b[4:]))), TTY: str(b[8:40]), User: str(b[44:76]), Source: source, IP: str(b[76:332])}
		out = append(out, e)
	}
	return out, bad
}
