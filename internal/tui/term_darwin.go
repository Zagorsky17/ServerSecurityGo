//go:build darwin

package tui

import "syscall"

// Номера ioctl для чтения и записи настроек терминала в macOS
// (нужны для демо-режима и разработки на маке).
const (
	ioctlGetTermios = syscall.TIOCGETA
	ioctlSetTermios = syscall.TIOCSETA
)
