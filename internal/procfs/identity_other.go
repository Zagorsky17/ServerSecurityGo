//go:build !linux && !darwin

package procfs

import "os"

func FileIdentity(fi os.FileInfo) string { return "" }
