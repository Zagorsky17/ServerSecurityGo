//go:build !linux && !darwin

package tui

import "errors"

// На остальных ОС терминальный интерфейс не поддерживается (приложение
// рассчитано на Linux; macOS — для разработки и демо).

type termState struct{}

var errUnsupported = errors.New("терминальный интерфейс поддерживается только в Linux и macOS")

func isTerminal(int) bool             { return false }
func makeRaw(int) (*termState, error) { return nil, errUnsupported }
func (s *termState) restore()         {}
func termSize(int) (int, int, error)  { return 80, 24, nil }
