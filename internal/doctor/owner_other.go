//go:build !unix

package doctor

import "os"

func fileUID(fi os.FileInfo) int { return -1 }
