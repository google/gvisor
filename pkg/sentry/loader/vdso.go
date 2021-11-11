// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/loader/vdsodata"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

const vdsoPrelink = 0xffffffffff700000

type fileContext struct {
	context.Context
}

func (f *fileContext) Value(key interface{}) interface{} {
	switch key {
	case uniqueid.CtxGlobalUniqueID:
		return uint64(0)
	default:
		return f.Context.Value(key)
	}
}

type byteFullReader struct {
	data []byte
}

func (b *byteFullReader) ReadFull(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if offset >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, b.data[offset:])
	return int64(n), err
}

// validateVDSO checks that the VDSO can be loaded by loadVDSO.
//
// VDSOs are special (see below). Since we are going to map the VDSO directly
// rather than using a normal loading process, we require that the PT_LOAD
// segments have the same layout in the ELF as they expect to have in memory.
//
// Namely, this means that we must verify:
// * PT_LOAD file offsets are equivalent to the memory offset from the first
//   segment.
// * No extra zeroed space (memsz) is required.
// * PT_LOAD segments are in order.
// * No two PT_LOAD segments occupy parts of the same page.
// * PT_LOAD segments don't extend beyond the end of the file.
//
// ctx may be nil if f does not need it.
func validateVDSO(ctx context.Context, f fullReader, size uint64) (elfInfo, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		log.Infof("Unable to parse VDSO header: %v", err)
		return elfInfo{}, err
	}

	var first *elf.ProgHeader
	var prev *elf.ProgHeader
	var prevEnd hostarch.Addr
	for i, phdr := range info.phdrs {
		if phdr.Type != elf.PT_LOAD {
			continue
		}

		if first == nil {
			first = &info.phdrs[i]
			if phdr.Off != 0 {
				log.Warningf("First PT_LOAD segment has non-zero file offset")
				return elfInfo{}, linuxerr.ENOEXEC
			}
		}

		memoryOffset := phdr.Vaddr - first.Vaddr
		if memoryOffset != phdr.Off {
			log.Warningf("PT_LOAD segment memory offset %#x != file offset %#x", memoryOffset, phdr.Off)
			return elfInfo{}, linuxerr.ENOEXEC
		}

		// memsz larger than filesz means that extra zeroed space should be
		// provided at the end of the segment. Since we are mapping the ELF
		// directly, we don't want to just overwrite part of the ELF with
		// zeroes.
		if phdr.Memsz != phdr.Filesz {
			log.Warningf("PT_LOAD segment memsz %#x != filesz %#x", phdr.Memsz, phdr.Filesz)
			return elfInfo{}, linuxerr.ENOEXEC
		}

		start := hostarch.Addr(memoryOffset)
		end, ok := start.AddLength(phdr.Memsz)
		if !ok {
			log.Warningf("PT_LOAD segment size overflows: %#x + %#x", start, end)
			return elfInfo{}, linuxerr.ENOEXEC
		}
		if uint64(end) > size {
			log.Warningf("PT_LOAD segment end %#x extends beyond end of file %#x", end, size)
			return elfInfo{}, linuxerr.ENOEXEC
		}

		if prev != nil {
			if start < prevEnd {
				log.Warningf("PT_LOAD segments out of order")
				return elfInfo{}, linuxerr.ENOEXEC
			}

			// We mprotect entire pages, so each segment must be in
			// its own page.
			prevEndPage := prevEnd.RoundDown()
			startPage := start.RoundDown()
			if prevEndPage >= startPage {
				log.Warningf("PT_LOAD segments share a page: %#x", prevEndPage)
				return elfInfo{}, linuxerr.ENOEXEC
			}
		}
		prev = &info.phdrs[i]
		prevEnd = end
	}

	return info, nil
}

// VDSO describes a VDSO.
//
// NOTE(mpratt): to support multiple architectures or operating systems, this
// would need to contain a VDSO for each.
//
// +stateify savable
type VDSO struct {
	// ParamPage is the VDSO parameter page. This page should be updated to
	// inform the VDSO for timekeeping data.
	ParamPage *mm.SpecialMappable

	// vdso is the VDSO ELF itself.
	vdso *mm.SpecialMappable

	// os is the operating system targeted by the VDSO.
	os abi.OS

	// arch is the architecture targeted by the VDSO.
	arch arch.Arch

	// phdrs are the VDSO ELF phdrs.
	phdrs []elf.ProgHeader `state:".([]elfProgHeader)"`
}

// PrepareVDSO validates the system VDSO and returns a VDSO, containing the
// param page for updating by the kernel.
func PrepareVDSO(mfp pgalloc.MemoryFileProvider) (*VDSO, error) {
	vdsoFile := &byteFullReader{data: vdsodata.Binary}

	// First make sure the VDSO is valid. vdsoFile does not use ctx, so a
	// nil context can be passed.
	info, err := validateVDSO(nil, vdsoFile, uint64(len(vdsodata.Binary)))
	if err != nil {
		return nil, err
	}

	// Then copy it into a VDSO mapping.
	size, ok := hostarch.Addr(len(vdsodata.Binary)).RoundUp()
	if !ok {
		return nil, fmt.Errorf("VDSO size overflows? %#x", len(vdsodata.Binary))
	}

	mf := mfp.MemoryFile()
	vdso, err := mf.Allocate(uint64(size), pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		return nil, fmt.Errorf("unable to allocate VDSO memory: %v", err)
	}

	ims, err := mf.MapInternal(vdso, hostarch.ReadWrite)
	if err != nil {
		mf.DecRef(vdso)
		return nil, fmt.Errorf("unable to map VDSO memory: %v", err)
	}

	_, err = safemem.CopySeq(ims, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(vdsodata.Binary)))
	if err != nil {
		mf.DecRef(vdso)
		return nil, fmt.Errorf("unable to copy VDSO into memory: %v", err)
	}

	// Finally, allocate a param page for this VDSO.
	paramPage, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		mf.DecRef(vdso)
		return nil, fmt.Errorf("unable to allocate VDSO param page: %v", err)
	}

	return &VDSO{
		ParamPage: mm.NewSpecialMappable("[vvar]", mfp, paramPage),
		// TODO(gvisor.dev/issue/157): Don't advertise the VDSO, as
		// some applications may not be able to handle multiple [vdso]
		// hints.
		vdso:  mm.NewSpecialMappable("", mfp, vdso),
		os:    info.os,
		arch:  info.arch,
		phdrs: info.phdrs,
	}, nil
}

// loadVDSO loads the VDSO into m.
//
// VDSOs are special.
//
// VDSOs are fully position independent. However, instead of loading a VDSO
// like a normal ELF binary, mapping only the PT_LOAD segments, the Linux
// kernel simply directly maps the entire file into process memory, with very
// little real ELF parsing.
//
// NOTE(b/25323870): This means that userspace can, and unfortunately does,
// depend on parts of the ELF that would normally not be mapped.  To maintain
// compatibility with such binaries, we load the VDSO much like Linux.
//
// loadVDSO takes a reference on the VDSO and parameter page FrameRegions.
func loadVDSO(ctx context.Context, m *mm.MemoryManager, v *VDSO, bin loadedELF) (hostarch.Addr, error) {
	if v.os != bin.os {
		ctx.Warningf("Binary ELF OS %v and VDSO ELF OS %v differ", bin.os, v.os)
		return 0, linuxerr.ENOEXEC
	}
	if v.arch != bin.arch {
		ctx.Warningf("Binary ELF arch %v and VDSO ELF arch %v differ", bin.arch, v.arch)
		return 0, linuxerr.ENOEXEC
	}

	// Reserve address space for the VDSO and its parameter page, which is
	// mapped just before the VDSO.
	mapSize := v.vdso.Length() + v.ParamPage.Length()
	addr, err := m.MMap(ctx, memmap.MMapOpts{
		Length:  mapSize,
		Private: true,
	})
	if err != nil {
		ctx.Infof("Unable to reserve VDSO address space: %v", err)
		return 0, err
	}

	// Now map the param page.
	_, err = m.MMap(ctx, memmap.MMapOpts{
		Length:          v.ParamPage.Length(),
		MappingIdentity: v.ParamPage,
		Mappable:        v.ParamPage,
		Addr:            addr,
		Fixed:           true,
		Unmap:           true,
		Private:         true,
		Perms:           hostarch.Read,
		MaxPerms:        hostarch.Read,
	})
	if err != nil {
		ctx.Infof("Unable to map VDSO param page: %v", err)
		return 0, err
	}

	// Now map the VDSO itself.
	vdsoAddr, ok := addr.AddLength(v.ParamPage.Length())
	if !ok {
		panic(fmt.Sprintf("Part of mapped range overflows? %#x + %#x", addr, v.ParamPage.Length()))
	}
	_, err = m.MMap(ctx, memmap.MMapOpts{
		Length:          v.vdso.Length(),
		MappingIdentity: v.vdso,
		Mappable:        v.vdso,
		Addr:            vdsoAddr,
		Fixed:           true,
		Unmap:           true,
		Private:         true,
		Perms:           hostarch.Read,
		MaxPerms:        hostarch.AnyAccess,
	})
	if err != nil {
		ctx.Infof("Unable to map VDSO: %v", err)
		return 0, err
	}

	vdsoEnd, ok := vdsoAddr.AddLength(v.vdso.Length())
	if !ok {
		panic(fmt.Sprintf("VDSO mapping overflows? %#x + %#x", vdsoAddr, v.vdso.Length()))
	}

	// Set additional protections for the individual segments.
	var first *elf.ProgHeader
	for i, phdr := range v.phdrs {
		if phdr.Type != elf.PT_LOAD {
			continue
		}

		if first == nil {
			first = &v.phdrs[i]
		}

		memoryOffset := phdr.Vaddr - first.Vaddr
		segAddr, ok := vdsoAddr.AddLength(memoryOffset)
		if !ok {
			ctx.Warningf("PT_LOAD segment address overflows: %#x + %#x", segAddr, memoryOffset)
			return 0, linuxerr.ENOEXEC
		}
		segPage := segAddr.RoundDown()
		segSize := hostarch.Addr(phdr.Memsz)
		segSize, ok = segSize.AddLength(segAddr.PageOffset())
		if !ok {
			ctx.Warningf("PT_LOAD segment memsize %#x + offset %#x overflows", phdr.Memsz, segAddr.PageOffset())
			return 0, linuxerr.ENOEXEC
		}
		segSize, ok = segSize.RoundUp()
		if !ok {
			ctx.Warningf("PT_LOAD segment size overflows: %#x", phdr.Memsz+segAddr.PageOffset())
			return 0, linuxerr.ENOEXEC
		}
		segEnd, ok := segPage.AddLength(uint64(segSize))
		if !ok {
			ctx.Warningf("PT_LOAD segment range overflows: %#x + %#x", segAddr, segSize)
			return 0, linuxerr.ENOEXEC
		}
		if segEnd > vdsoEnd {
			ctx.Warningf("PT_LOAD segment ends beyond VDSO: %#x > %#x", segEnd, vdsoEnd)
			return 0, linuxerr.ENOEXEC
		}

		perms := progFlagsAsPerms(phdr.Flags)
		if perms != hostarch.Read {
			if err := m.MProtect(segPage, uint64(segSize), perms, false); err != nil {
				ctx.Warningf("Unable to set PT_LOAD segment protections %+v at [%#x, %#x): %v", perms, segAddr, segEnd, err)
				return 0, linuxerr.ENOEXEC
			}
		}
	}

	return vdsoAddr, nil
}

// Release drops references on mappings held by v.
func (v *VDSO) Release(ctx context.Context) {
	v.ParamPage.DecRef(ctx)
	v.vdso.DecRef(ctx)
}

var vdsoSigreturnOffset = func() uint64 {
	f, err := elf.NewFile(bytes.NewReader(vdsodata.Binary))
	if err != nil {
		panic(fmt.Sprintf("failed to parse vdso.so as ELF file: %v", err))
	}
	syms, err := f.Symbols()
	if err != nil {
		panic(fmt.Sprintf("failed to read symbols from vdso.so: %v", err))
	}
	const sigreturnSymbol = "__kernel_rt_sigreturn"
	for _, sym := range syms {
		if elf.ST_BIND(sym.Info) != elf.STB_LOCAL && sym.Section != elf.SHN_UNDEF && sym.Name == sigreturnSymbol {
			return sym.Value
		}
	}
	panic(fmt.Sprintf("no symbol %q in vdso.so", sigreturnSymbol))
}()
