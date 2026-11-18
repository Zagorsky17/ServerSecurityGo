package model

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"time"
)

type FilePrivilege struct {
	Path         string `json:"path"`
	Mode         string `json:"mode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	SUID         bool   `json:"suid"`
	SGID         bool   `json:"sgid"`
	Permitted    uint64 `json:"permitted"`
	Inheritable  uint64 `json:"inheritable"`
	Effective    bool   `json:"effective"`
	RootID       uint32 `json:"rootId"`
	PackageOwned *bool  `json:"packageOwned,omitempty"`
}

type FileInventory struct {
	Time       time.Time       `json:"time"`
	Scope      string          `json:"scope"`
	Files      []FilePrivilege `json:"files"`
	Findings   []SystemFinding `json:"findings"`
	Warnings   []i18n.Msg      `json:"warnings"`
	Scanned    int             `json:"scanned"`
	Incomplete bool            `json:"incomplete"`
}

// FindingContext contains explanation, contextual ATT&CK mappings and bounded history.
type FindingContext struct {
	ReviewFirst   bool     `json:"reviewFirst,omitempty"`
	Confidence    i18n.Msg `json:"confidence,omitzero"`
	Why           i18n.Msg `json:"why"`
	Legitimate    i18n.Msg `json:"legitimate"`
	Attack        []string `json:"attack,omitempty"`
	RelatedEvents []Event  `json:"relatedEvents,omitempty"`
}
