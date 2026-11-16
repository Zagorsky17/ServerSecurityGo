//go:build !linux && !darwin

package investigate

import (
	"os"
	"time"
)

func changeTime(fi os.FileInfo) time.Time { return time.Time{} }
