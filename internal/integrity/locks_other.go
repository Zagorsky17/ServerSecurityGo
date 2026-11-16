//go:build !linux

package integrity

import "os"

// shortcut: вне Linux поддерживаются только файловые тестовые деревья, блокировок dpkg здесь нет.
func packageLocks(root *os.Root) error { return nil }
