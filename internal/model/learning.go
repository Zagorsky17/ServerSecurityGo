package model

import (
	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"time"
)

type LearningCandidate struct {
	Exe      string    `json:"exe"`
	User     string    `json:"user"`
	Rule     string    `json:"rule"`
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Proposal string    `json:"proposal"`
}
type LearningReport struct {
	BaselineCommand string              `json:"baselineCommand,omitempty"`
	Enabled         bool                `json:"enabled"`
	Until           time.Time           `json:"until"`
	Candidates      []LearningCandidate `json:"candidates"`
	Warnings        []i18n.Msg          `json:"warnings"`
}
