package advanced

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"runtime"
	"testing"
)

func TestUPXLiteralIsNotPacking(t *testing.T) {
	for _, off := range []int{1000, 4096, 8188, 8192} {
		b := append(elfFixture(false), make([]byte, 4)...)
		copy(b[off:], "UPX!")
		got, err := InspectELF(b)
		if err != nil || got.Packing != "" {
			t.Fatalf("offset %d: %+v, %v", off, got, err)
		}
	}
}

func TestOwnGoELFIsNotPacked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires the Linux Go test executable")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectELF(b)
	if err != nil || !got.ELF || got.Packing != "" {
		t.Fatalf("ordinary Go executable: %+v, %v", got, err)
	}
}

func packedELFFixture() []byte {
	b := elfFixture(false)
	o := binary.LittleEndian
	copy(b[180:], "UPX!")
	o.PutUint16(b[184:], 512)
	b[186], b[187] = 14, 22
	o.PutUint32(b[192:], 20000)
	o.PutUint32(b[196:], 12000)
	h := b[len(b)-36:]
	copy(h, "UPX!")
	h[4], h[5], h[6], h[7] = 14, 22, 2, 1
	o.PutUint32(h[16:], 20000)
	o.PutUint32(h[20:], uint32(len(b)-36))
	o.PutUint32(h[24:], 20000)
	o.PutUint32(h[32:], 188)
	upxChecksum(b)
	return b
}

func upxChecksum(b []byte) {
	h := b[len(b)-36:]
	sum := 0
	for _, v := range h[4:31] {
		sum += int(v)
	}
	h[31] = byte(sum % 251)
}

func TestUPXHeader(t *testing.T) {
	for _, padding := range []int{0, 1, 8192} {
		b := append(packedELFFixture(), make([]byte, padding)...)
		before := bytes.Clone(b)
		got, err := InspectELF(b)
		if err != nil || got.Packing != "upx-header" {
			t.Fatalf("padding %d: %+v, %v", padding, got, err)
		}
		if !bytes.Equal(b, before) {
			t.Fatal("input mutated")
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"checksum":          func(b []byte) []byte { b[len(b)-5]++; return b },
		"version":           func(b []byte) []byte { b[len(b)-32] = 15; upxChecksum(b); return b },
		"architecture":      func(b []byte) []byte { b[18] = 183; return b },
		"format":            func(b []byte) []byte { b[len(b)-31] = 42; upxChecksum(b); return b },
		"offset underflow":  func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-4:], 0); return b },
		"offset overflow":   func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-4:], ^uint32(0)); return b },
		"loader magic":      func(b []byte) []byte { b[180] = 0; return b },
		"loader version":    func(b []byte) []byte { b[186]--; return b },
		"loader format":     func(b []byte) []byte { b[187]++; return b },
		"loader size":       func(b []byte) []byte { binary.LittleEndian.PutUint16(b[184:], 65535); return b },
		"original size":     func(b []byte) []byte { b[192]++; return b },
		"block size":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[196:], 20001); return b },
		"zero block":        func(b []byte) []byte { binary.LittleEndian.PutUint32(b[196:], 0); return b },
		"uncompressed size": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-20:], 20001); upxChecksum(b); return b },
		"compressed size": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[len(b)-16:], ^uint32(0))
			upxChecksum(b)
			return b
		},
		"nonzero overlay": func(b []byte) []byte { return append(b, 1) },
		"excess padding":  func(b []byte) []byte { return append(b, make([]byte, 8193)...) },
	} {
		t.Run(name, func(t *testing.T) {
			got, err := InspectELF(mutate(packedELFFixture()))
			if err != nil || got.Packing == "upx-header" {
				t.Fatalf("%+v, %v", got, err)
			}
		})
	}
	b := packedELFFixture()
	for n := 0; n < len(b); n++ {
		got, _ := InspectELF(b[:n])
		if got.Packing == "upx-header" {
			t.Fatalf("truncated at %d", n)
		}
	}
}

func TestUPXFormats(t *testing.T) {
	for _, tc := range []struct {
		format  byte
		class   elf.Class
		machine elf.Machine
	}{
		{12, elf.ELFCLASS32, elf.EM_386}, {20, elf.ELFCLASS32, elf.EM_386},
		{22, elf.ELFCLASS64, elf.EM_X86_64}, {23, elf.ELFCLASS32, elf.EM_ARM},
		{133, elf.ELFCLASS32, elf.EM_ARM}, {30, elf.ELFCLASS32, elf.EM_MIPS},
		{137, elf.ELFCLASS32, elf.EM_MIPS}, {132, elf.ELFCLASS32, elf.EM_PPC},
		{39, elf.ELFCLASS64, elf.EM_PPC64}, {140, elf.ELFCLASS64, elf.EM_PPC64},
		{42, elf.ELFCLASS64, elf.EM_AARCH64}, {45, elf.ELFCLASS64, elf.EM_RISCV},
	} {
		order := binary.ByteOrder(binary.LittleEndian)
		data := elf.ELFDATA2LSB
		if tc.format >= 128 {
			order, data = binary.BigEndian, elf.ELFDATA2MSB
		}
		f := &elf.File{FileHeader: elf.FileHeader{Class: tc.class, Machine: tc.machine, Data: data, ByteOrder: order}}
		b := packedELFFixture()
		b[187] = tc.format
		order.PutUint16(b[184:], 512)
		order.PutUint32(b[192:], 20000)
		order.PutUint32(b[196:], 12000)
		h := b[len(b)-36:]
		h[5] = tc.format
		order.PutUint32(h[24:], 20000)
		order.PutUint32(h[32:], 188)
		offset := 16
		if tc.format >= 128 {
			offset = 8
		}
		order.PutUint32(h[offset:], 20000)
		order.PutUint32(h[offset+4:], uint32(len(b)-36))
		upxChecksum(b)
		if !hasUPXHeader(b, f) {
			t.Fatalf("format %d rejected", tc.format)
		}
		f.Class = elf.ELFCLASSNONE
		if hasUPXHeader(b, f) {
			t.Fatalf("format %d accepted wrong class", tc.format)
		}
	}
}

func TestUPXSectionNameIsNotPacking(t *testing.T) {
	b := elfFixture(false)
	o := binary.LittleEndian
	o.PutUint64(b[40:], 256)
	o.PutUint16(b[58:], 64)
	o.PutUint16(b[60:], 3)
	o.PutUint16(b[62:], 1)
	names := []byte("\x00.shstrtab\x00UPX0\x00")
	copy(b[1024:], names)
	o.PutUint32(b[320:], 1)
	o.PutUint32(b[324:], uint32(elf.SHT_STRTAB))
	o.PutUint64(b[344:], 1024)
	o.PutUint64(b[352:], uint64(len(names)))
	o.PutUint32(b[384:], 11)
	o.PutUint32(b[388:], uint32(elf.SHT_PROGBITS))
	got, err := InspectELF(b)
	if err != nil || got.Packing != "" {
		t.Fatalf("%+v, %v", got, err)
	}
}
