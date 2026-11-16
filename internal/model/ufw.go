package model

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"time"
)

// UFWReport описывает сохранённую конфигурацию, а не активные правила ядра.
type UFWReport struct {
	Time     time.Time    `json:"time"`
	State    string       `json:"state"` // enabled, disabled, unknown, absent
	Settings []UFWSetting `json:"settings"`
	Files    []UFWFile    `json:"files"`
	Warnings []i18n.Msg   `json:"warnings"`
}
type UFWFile struct {
	Path    string   `json:"path"`
	Content string   `json:"content"`
	Status  string   `json:"status"` // ok, missing, unavailable
	Error   i18n.Msg `json:"error,omitempty"`
}

type UFWSetting struct {
	Key   string   `json:"key"`
	Label i18n.Msg `json:"label"`
	Value i18n.Msg `json:"value"`
}
