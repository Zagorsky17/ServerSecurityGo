//go:build unix

package safefile

import (
	"os"
	"syscall"
)

func readFlags() int { return os.O_RDONLY | syscall.O_NONBLOCK }
func openDir(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
}
