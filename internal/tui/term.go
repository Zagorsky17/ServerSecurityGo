//go:build linux || darwin

package tui

import (
	"errors"
	"syscall"
	"unsafe"
)

// Работа с терминалом без внешних библиотек: сырой режим через termios
// и размер окна через TIOCGWINSZ.

// termState — сохранённые настройки терминала для восстановления.
type termState struct {
	fd  int
	old syscall.Termios
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// isTerminal сообщает, что fd — терминал.
func isTerminal(fd int) bool {
	var t syscall.Termios
	return ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)) == nil
}

// makeRaw переводит терминал в сырой режим (как cfmakeraw): без эха,
// построчного ввода и обработки сигналов — каждое нажатие приходит
// сразу, Ctrl+C приходит байтом 0x03.
func makeRaw(fd int) (*termState, error) {
	st := &termState{fd: fd}
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&st.old)); err != nil {
		return nil, errors.New("стандартный ввод не является терминалом")
	}
	t := st.old
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := ioctl(fd, ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return st, nil
}

// restore возвращает исходные настройки терминала.
func (s *termState) restore() {
	if s != nil {
		_ = ioctl(s.fd, ioctlSetTermios, unsafe.Pointer(&s.old))
	}
}

// termSize возвращает ширину и высоту терминала в символах.
func termSize(fd int) (int, int, error) {
	var ws struct{ Row, Col, X, Y uint16 }
	if err := ioctl(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	if ws.Col == 0 || ws.Row == 0 {
		return 80, 24, nil
	}
	return int(ws.Col), int(ws.Row), nil
}
