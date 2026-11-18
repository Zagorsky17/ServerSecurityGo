//go:build !linux && !darwin

package fsinspect

import "os"

func metadata(fi os.FileInfo) (uint64, uint32, uint32) { return 0, 0, 0 }
func capabilities(f *os.File) (Capability, error)      { return Capability{}, os.ErrNotExist }
