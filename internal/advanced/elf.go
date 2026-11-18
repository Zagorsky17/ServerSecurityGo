package advanced

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"os"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

// InspectELF ограничивает таблицы до передачи недоверенных размеров и смещений в debug/elf.
func InspectELF(data []byte) (model.ExecutableInspection, error) {
	var out model.ExecutableInspection
	if len(data) < 4 || !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return out, nil
	}
	out.ELF = true
	if len(data) < 52 {
		return out, os.ErrInvalid
	}
	var order binary.ByteOrder
	switch data[5] {
	case 1:
		order = binary.LittleEndian
	case 2:
		order = binary.BigEndian
	default:
		return out, os.ErrInvalid
	}
	var phoff, shoff uint64
	var phsize, phnum, shsize, shnum, strIndex uint16
	switch data[4] {
	case 1:
		phoff = uint64(order.Uint32(data[28:]))
		shoff = uint64(order.Uint32(data[32:]))
		phsize = order.Uint16(data[42:])
		phnum = order.Uint16(data[44:])
		shsize = order.Uint16(data[46:])
		shnum = order.Uint16(data[48:])
		strIndex = order.Uint16(data[50:])
	case 2:
		if len(data) < 64 {
			return out, os.ErrInvalid
		}
		phoff = order.Uint64(data[32:])
		shoff = order.Uint64(data[40:])
		phsize = order.Uint16(data[54:])
		phnum = order.Uint16(data[56:])
		shsize = order.Uint16(data[58:])
		shnum = order.Uint16(data[60:])
		strIndex = order.Uint16(data[62:])
	default:
		return out, os.ErrInvalid
	}
	bound := func(off uint64, size, n uint16) bool {
		return off <= uint64(len(data)) && uint64(size)*uint64(n) <= uint64(len(data))-off
	}
	if phnum > 1024 || shnum > 4096 || (shnum == 0 && shoff != 0) || !bound(phoff, phsize, phnum) || !bound(shoff, shsize, shnum) {
		return out, os.ErrInvalid
	}

	if strIndex == 0xffff || (strIndex != 0 && strIndex >= shnum) {
		return out, os.ErrInvalid
	}
	required := uint16(40)
	if data[4] == 2 {
		required = 64
	}
	if shnum > 0 && shsize != required {
		return out, os.ErrInvalid
	}
	// debug/elf сразу загружает имена секций: сжатую или чрезмерную таблицу не принимаем.
	if strIndex > 0 {
		h := data[shoff+uint64(strIndex)*uint64(shsize):]
		var flags, off, size uint64
		if data[4] == 1 {
			flags = uint64(order.Uint32(h[8:]))
			off = uint64(order.Uint32(h[16:]))
			size = uint64(order.Uint32(h[20:]))
		} else {
			flags = order.Uint64(h[8:])
			off = order.Uint64(h[24:])
			size = order.Uint64(h[32:])
		}
		if flags&uint64(elf.SHF_COMPRESSED) != 0 || size > 1<<20 || off > uint64(len(data)) || size > uint64(len(data))-off {
			return out, os.ErrInvalid
		}
	}
	f, e := elf.NewFile(bytes.NewReader(data))
	if e != nil {
		return out, e
	}
	defer f.Close()
	out.Static = f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN
	var sample []byte
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			out.Static = false
		}
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Off <= uint64(len(data)) && p.Filesz <= uint64(len(data))-p.Off {
			end := min(p.Filesz, uint64(1<<20))
			if len(sample) == 0 {
				sample = data[p.Off : p.Off+end]
			}
		}
	}
	if hasUPXHeader(data, f) {
		out.Packing = "upx-header"
	}

	if len(sample) >= 4096 {
		var counts [256]int
		for _, b := range sample {
			counts[b]++
		}
		for _, n := range counts {
			if n > 0 {
				p := float64(n) / float64(len(sample))
				out.Entropy -= p * math.Log2(p)
			}
		}
		if out.Entropy > 7.2 && out.Packing == "" {
			out.Packing = "entropy"
		}
	}
	return out, nil
}
