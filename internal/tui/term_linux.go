//go:build linux

package tui

import "syscall"

// Номера ioctl для чтения и записи настроек терминала в Linux.
const (
	ioctlGetTermios = syscall.TCGETS
	ioctlSetTermios = syscall.TCSETS
)
