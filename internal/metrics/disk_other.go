//go:build !unix

package metrics

import "errors"

// Usage — место и inode раздела.
type Usage struct {
	Total      uint64
	Free       uint64
	Inodes     uint64
	InodesFree uint64
}

// diskUsage на не-unix не поддерживается: приложение рассчитано на
// Linux, а здесь должен хотя бы собираться.
func diskUsage(string) (Usage, error) {
	return Usage{}, errors.New("statfs не поддерживается")
}
