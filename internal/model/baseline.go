package model

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"time"
)

type BaselineSection struct {
	Scope    string            `json:"scope"`
	Complete bool              `json:"complete"`
	Items    map[string]string `json:"items"`
}
type BaselineSnapshot struct {
	Version  int                        `json:"version"`
	Time     time.Time                  `json:"time"`
	Host     string                     `json:"host"`
	Sections map[string]BaselineSection `json:"sections"`
}
type BaselineChange struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Kind    string `json:"kind"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}
type BaselineDiff struct {
	From       time.Time        `json:"from"`
	To         time.Time        `json:"to"`
	Changes    []BaselineChange `json:"changes"`
	Warnings   []i18n.Msg       `json:"warnings"`
	Incomplete bool             `json:"incomplete"`
}
type ChangesReport struct {
	Installation *BaselineDiff `json:"installation"`
	Week         *BaselineDiff `json:"week"`
	Warnings     []i18n.Msg    `json:"warnings"`
}
