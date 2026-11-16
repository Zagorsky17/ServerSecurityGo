package model

import "fmt"

// ProcessSecurity содержит только поля ядра, без значений окружения.
type ProcessSecurity struct {
	TracerKey  string   `json:"tracerKey,omitempty"`
	TracerPID  int      `json:"tracerPid"`
	CapEff     []string `json:"capEff"`
	CapPrm     []string `json:"capPrm"`
	CapBnd     []string `json:"capBnd"`
	CapAmb     []string `json:"capAmb"`
	NoNewPrivs *int     `json:"noNewPrivs,omitempty"`
	Seccomp    *int     `json:"seccomp,omitempty"`
}

type MemoryMap struct {
	Path        string `json:"path,omitempty"`
	Perms       string `json:"perms"`
	Deleted     bool   `json:"deleted,omitempty"`
	Replacement bool   `json:"-"`
}

func CapabilityNames(mask uint64) []string {
	names := []string{"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE"}
	out := []string{}
	for bit := 0; bit < 64; bit++ {
		if mask&(uint64(1)<<bit) != 0 {
			if bit < len(names) {
				out = append(out, "CAP_"+names[bit])
			} else {
				out = append(out, fmt.Sprintf("CAP_%d", bit))
			}
		}
	}
	return out
}
