package fsinspect

import (
	"encoding/binary"
	"os"
)

type Capability struct {
	Permitted, Inheritable uint64
	Effective              bool
	RootID                 uint32
}

// Формат little-endian vfs_cap_data, включая namespace rootid ревизии 3.
func ParseCapability(b []byte) (Capability, error) {
	var c Capability
	if len(b) < 4 {
		return c, os.ErrInvalid
	}
	magic := binary.LittleEndian.Uint32(b)
	rev := magic >> 24
	size := map[uint32]int{1: 12, 2: 20, 3: 24}[rev]
	if size == 0 || len(b) != size || magic&0x00fffffe != 0 {
		return c, os.ErrInvalid
	}
	c.Effective = magic&1 != 0
	c.Permitted = uint64(binary.LittleEndian.Uint32(b[4:8]))
	c.Inheritable = uint64(binary.LittleEndian.Uint32(b[8:12]))
	if rev >= 2 {
		c.Permitted |= uint64(binary.LittleEndian.Uint32(b[12:16])) << 32
		c.Inheritable |= uint64(binary.LittleEndian.Uint32(b[16:20])) << 32
	}
	if rev == 3 {
		c.RootID = binary.LittleEndian.Uint32(b[20:24])
	}
	return c, nil
}
