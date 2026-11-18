package advanced

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

// Проверяем связанные PackHeader/l_info/p_info, а не строковые константы ELF.
// Формат: upx/upx src/packhead.cpp и src/p_unix.{h,cpp}, версии UPX 3.x–5.x.
func hasUPXHeader(data []byte, f *elf.File) bool {
	// shortcut: только заголовки 11–14 и до 8 КиБ нулевого хвоста; новые форматы требуют отдельной проверки.
	for pos := len(data) - 36; pos >= max(0, len(data)-36-8192); pos-- {
		h := data[pos : pos+32]
		if !bytes.Equal(h[:4], []byte("UPX!")) || h[4] < 11 || h[4] > 14 || !upxELFFormat(h[5], f) {
			continue
		}
		sum := 0
		for _, v := range h[4:31] {
			sum += int(v)
		}
		if byte(sum%251) != h[31] {
			continue
		}
		order := f.ByteOrder
		off := uint64(order.Uint32(data[pos+32 : pos+36]))
		if off < 12 || off+24 > uint64(pos) {
			continue
		}
		loader := data[off-12 : off]
		size := uint64(order.Uint16(loader[8:10]))
		if !bytes.Equal(loader[4:8], []byte("UPX!")) || loader[10] != h[4] || loader[11] != h[5] || size == 0 || size > uint64(pos)-off {
			continue
		}
		original := uint64(order.Uint32(h[24:28]))
		program := data[off : off+12]
		block := uint64(order.Uint32(program[8:12]))
		if original == 0 || uint64(order.Uint32(program[4:8])) != original || block == 0 || block > original {
			continue
		}
		unc, compressed := uint64(order.Uint32(h[16:20])), uint64(order.Uint32(h[20:24]))
		if f.Data == elf.ELFDATA2MSB {
			unc, compressed = uint64(order.Uint32(h[8:12])), uint64(order.Uint32(h[12:16]))
		}
		if unc == 0 || unc > original || compressed == 0 || compressed > uint64(pos) {
			continue
		}
		zeroTail := true
		for _, v := range data[pos+36:] {
			if v != 0 {
				zeroTail = false
				break
			}
		}
		if zeroTail {
			return true
		}
	}
	return false
}

func upxELFFormat(format byte, f *elf.File) bool {
	var class elf.Class
	var machine elf.Machine
	switch format {
	case 12, 20:
		class, machine = elf.ELFCLASS32, elf.EM_386
	case 22:
		class, machine = elf.ELFCLASS64, elf.EM_X86_64
	case 23, 133:
		class, machine = elf.ELFCLASS32, elf.EM_ARM
	case 30, 137:
		class, machine = elf.ELFCLASS32, elf.EM_MIPS
	case 132:
		class, machine = elf.ELFCLASS32, elf.EM_PPC
	case 39, 140:
		class, machine = elf.ELFCLASS64, elf.EM_PPC64
	case 42:
		class, machine = elf.ELFCLASS64, elf.EM_AARCH64
	case 45:
		class, machine = elf.ELFCLASS64, elf.EM_RISCV
	default:
		return false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if format >= 128 {
		order = binary.BigEndian
	}
	return f.Class == class && f.Machine == machine && f.ByteOrder == order
}
