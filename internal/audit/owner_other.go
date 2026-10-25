//go:build !unix

package audit

import "io/fs"

// owner — на системах без Stat_t владелец неизвестен; аудит рассчитан
// на Linux, здесь нужна только сборка.
func owner(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
