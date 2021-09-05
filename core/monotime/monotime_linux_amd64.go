// monotime_linux_amd64.go - Linux AMD64 Monotonic clock.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// +build !noasm
// +build !go1.9

package monotime

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"
	"unsafe"
)

func getSysinfoEhdr() (uintptr, error) {
	const AT_SYSINFO_EHDR = 33

	auxv, err := ioutil.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}

	for i := 0; i < len(auxv)/(8*2); i++ {
		id := binary.LittleEndian.Uint64(auxv[i*16:])
		val := binary.LittleEndian.Uint64(auxv[i*16+8:])
		if id == AT_SYSINFO_EHDR {
			return uintptr(val), nil
		}
	}

	return 0, nil
}

//go:noescape
//go:nosplit
func vdsoClockGettimeTrampoline(clkID uint64, res uintptr, fn uintptr)

func initArchDep() error {
	// A trivial vDSO parser based on the CC0 parse_vdso.c in the Linux source
	// tree.

	const symClockGettime = "clock_gettime"

	// Find the vDSO base, if present.
	base, err := getSysinfoEhdr()
	if err != nil {
		return err
	} else if base == 0 {
		return errors.New("monotime: ELF AT_SYSINFO_EHDR missing")
	}

	// Shadow the vDSO pages.  This is hilariously unsafe.
	vDSOPage := make([]byte, os.Getpagesize()*2)
	for i := range vDSOPage {
		ptr := (*byte)(unsafe.Pointer(base + uintptr(i)))
		vDSOPage[i] = *ptr
	}

	f, err := elf.NewFile(bytes.NewReader(vDSOPage))
	if err != nil {
		return err
	}
	defer f.Close()

	// Find the PT_LOAD and store the load offset.
	loadOffset := uintptr(0)
	for _, v := range f.Progs {
		if v.Type == elf.PT_LOAD {
			loadOffset = base + uintptr(v.Off) + uintptr(v.Vaddr)
			break
		}
	}
	if loadOffset == 0 {
		return errors.New("monotime: Failed to find ELF PT_LOAD")
	}

	// Find the VERSYM and VERDEF sections.
	verSym := f.SectionByType(elf.SHT_GNU_VERSYM)
	if verSym == nil {
		return errors.New("monotime: Failed to find ELF SHT_GNU_VERSYM")
	}
	verDef := f.SectionByType(elf.SHT_GNU_VERDEF)
	if verDef == nil {
		return errors.New("monotime: Failed to find ELF SHT_GNU_VERDEF")
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		return err
	}
	for _, v := range syms {
		if v.Name == symClockGettime {
			// Ensure the correct type and binding.
			if elf.ST_TYPE(v.Info) != elf.STT_FUNC {
				continue
			}
			switch elf.ST_BIND(v.Info) {
			case elf.STB_WEAK, elf.STB_GLOBAL:
				break
			default:
				continue
			}
			if v.Section == elf.SHN_UNDEF {
				continue
			}

			// XXX: Validate the version. ("LINUX_2.6").  In theory this needs
			// to happen.  Go's ELF parser package actually has most of what's
			// needed here, but not exported, and incomplete.  YOLO.

			// Save the vdso clock_gettime() address.
			vdsoClockGettime = loadOffset + uintptr(v.Value)
			return nil
		}
	}

	return errors.New("monotime: Failed to find vDSO clock_gettime")
}
