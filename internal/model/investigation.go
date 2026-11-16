package model

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"time"
)

type LoginEvent struct {
	Time        time.Time  `json:"time"`
	Kind        string     `json:"kind"`
	User        string     `json:"user,omitempty"`
	IP          string     `json:"ip,omitempty"`
	Method      string     `json:"method,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	KeyComment  string     `json:"keyComment,omitempty"`
	TTY         string     `json:"tty,omitempty"`
	PID         int        `json:"pid,omitempty"`
	Detail      string     `json:"detail,omitempty"`
	Source      string     `json:"source"`
	End         *time.Time `json:"end,omitempty"`
	Risk        Risk       `json:"risk"`
	Findings    []string   `json:"findings,omitempty"`
}
type AuthCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
type AuthReport struct {
	Time        time.Time       `json:"time"`
	Since       time.Time       `json:"since"`
	Events      []LoginEvent    `json:"events"`
	FailedIPs   []AuthCount     `json:"failedIPs"`
	FailedUsers []AuthCount     `json:"failedUsers"`
	FailedHours []AuthCount     `json:"failedHours"`
	Keys        []SSHKey        `json:"keys"`
	Warnings    []i18n.Msg      `json:"warnings"`
	Findings    []SystemFinding `json:"findings"`
	Incomplete  bool            `json:"incomplete"`
}
type SSHKey struct {
	User        string `json:"user"`
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Used        bool   `json:"usedInWindow"`
}
type RecentFile struct {
	Path          string    `json:"path"`
	ModTime       time.Time `json:"mtime"`
	ChangeTime    time.Time `json:"ctime"`
	Size          int64     `json:"size"`
	Mode          string    `json:"mode"`
	PackageWindow bool      `json:"packageWindow"`
	TimeMismatch  bool      `json:"timeMismatch"`
}
type RecentReport struct {
	Time       time.Time    `json:"time"`
	Files      []RecentFile `json:"files"`
	Warnings   []i18n.Msg   `json:"warnings"`
	Incomplete bool         `json:"incomplete"`
}
type TimelineEvent struct {
	Time           time.Time `json:"time"`
	Kind           string    `json:"kind"`
	Source         string    `json:"source"`
	Detail         i18n.Msg  `json:"detail"`
	Risk           Risk      `json:"risk"`
	VerifyCommands []string  `json:"verifyCommands,omitempty"`
}
