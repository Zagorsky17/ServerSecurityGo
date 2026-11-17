package model

import "time"

type BPFDescriptor struct {
	FD   int    `json:"fd"`
	Kind string `json:"kind"`
	Type uint32 `json:"type"`
	ID   uint32 `json:"id"`
	Tag  string `json:"tag,omitempty"`
}
type ExecutableInspection struct {
	Time       time.Time `json:"time"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"modTime"`
	ELF        bool      `json:"elf"`
	Static     bool      `json:"static"`
	Packing    string    `json:"packing,omitempty"`
	Entropy    float64   `json:"entropy"`
	Incomplete bool      `json:"incomplete"`
}
