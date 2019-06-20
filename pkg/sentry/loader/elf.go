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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

const (
	// elfMagic identifies an ELF file.
	elfMagic = "\x7fELF"

	// maxTotalPhdrSize is the maximum combined size of all program
	// headers.  Linux limits this to one page.
	maxTotalPhdrSize = usermem.PageSize
)

var (
	// header64Size is the size of elf.Header64.
	header64Size = int(binary.Size(elf.Header64{}))

	// Prog64Size is the size of elf.Prog64.
	prog64Size = int(binary.Size(elf.Prog64{}))
)

func progFlagsAsPerms(f elf.ProgFlag) usermem.AccessType {
	var p usermem.AccessType
	if f&elf.PF_R == elf.PF_R {
		p.Read = true
	}
	if f&elf.PF_W == elf.PF_W {
		p.Write = true
	}
	if f&elf.PF_X == elf.PF_X {
		p.Execute = true
	}
	return p
}

// elfInfo contains the metadata needed to load an ELF binary.
type elfInfo struct {
	// os is the target OS of the ELF.
	os abi.OS

	// arch is the target architecture of the ELF.
	arch arch.Arch

	// entry is the program entry point.
	entry usermem.Addr

	// phdrs are the program headers.
	phdrs []elf.ProgHeader

	// phdrSize is the size of a single program header in the ELF.
	phdrSize int

	// phdrOff is the offset of the program headers in the file.
	phdrOff uint64

	// sharedObject is true if the ELF represents a shared object.
	sharedObject bool
}

// parseHeader parse the ELF header, verifying that this is a supported ELF
// file and returning the ELF program headers.
//
// This is similar to elf.NewFile, except that it is more strict about what it
// accepts from the ELF, and it doesn't parse unnecessary parts of the file.
//
// ctx may be nil if f does not need it.
func parseHeader(ctx context.Context, f *fs.File) (elfInfo, error) {
	// Check ident first; it will tell us the endianness of the rest of the
	// structs.
	var ident [elf.EI_NIDENT]byte
	_, err := readFull(ctx, f, usermem.BytesIOSequence(ident[:]), 0)
	if err != nil {
		log.Infof("Error reading ELF ident: %v", err)
		// The entire ident array always exists.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}

	// Only some callers pre-check the ELF magic.
	if !bytes.Equal(ident[:len(elfMagic)], []byte(elfMagic)) {
		log.Infof("File is not an ELF")
		return elfInfo{}, syserror.ENOEXEC
	}

	// We only support 64-bit, little endian binaries
	if class := elf.Class(ident[elf.EI_CLASS]); class != elf.ELFCLASS64 {
		log.Infof("Unsupported ELF class: %v", class)
		return elfInfo{}, syserror.ENOEXEC
	}
	if endian := elf.Data(ident[elf.EI_DATA]); endian != elf.ELFDATA2LSB {
		log.Infof("Unsupported ELF endianness: %v", endian)
		return elfInfo{}, syserror.ENOEXEC
	}
	byteOrder := binary.LittleEndian

	if version := elf.Version(ident[elf.EI_VERSION]); version != elf.EV_CURRENT {
		log.Infof("Unsupported ELF version: %v", version)
		return elfInfo{}, syserror.ENOEXEC
	}
	// EI_OSABI is ignored by Linux, which is the only OS supported.
	os := abi.Linux

	var hdr elf.Header64
	hdrBuf := make([]byte, header64Size)
	_, err = readFull(ctx, f, usermem.BytesIOSequence(hdrBuf), 0)
	if err != nil {
		log.Infof("Error reading ELF header: %v", err)
		// The entire header always exists.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}
	binary.Unmarshal(hdrBuf, byteOrder, &hdr)

	// We only support amd64.
	if machine := elf.Machine(hdr.Machine); machine != elf.EM_X86_64 {
		log.Infof("Unsupported ELF machine %d", machine)
		return elfInfo{}, syserror.ENOEXEC
	}
	a := arch.AMD64

	var sharedObject bool
	elfType := elf.Type(hdr.Type)
	switch elfType {
	case elf.ET_EXEC:
		sharedObject = false
	case elf.ET_DYN:
		sharedObject = true
	default:
		log.Infof("Unsupported ELF type %v", elfType)
		return elfInfo{}, syserror.ENOEXEC
	}

	if int(hdr.Phentsize) != prog64Size {
		log.Infof("Unsupported phdr size %d", hdr.Phentsize)
		return elfInfo{}, syserror.ENOEXEC
	}
	totalPhdrSize := prog64Size * int(hdr.Phnum)
	if totalPhdrSize < prog64Size {
		log.Warningf("No phdrs or total phdr size overflows: prog64Size: %d phnum: %d", prog64Size, int(hdr.Phnum))
		return elfInfo{}, syserror.ENOEXEC
	}
	if totalPhdrSize > maxTotalPhdrSize {
		log.Infof("Too many phdrs (%d): total size %d > %d", hdr.Phnum, totalPhdrSize, maxTotalPhdrSize)
		return elfInfo{}, syserror.ENOEXEC
	}

	phdrBuf := make([]byte, totalPhdrSize)
	_, err = readFull(ctx, f, usermem.BytesIOSequence(phdrBuf), int64(hdr.Phoff))
	if err != nil {
		log.Infof("Error reading ELF phdrs: %v", err)
		// If phdrs were specified, they should all exist.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}

	phdrs := make([]elf.ProgHeader, hdr.Phnum)
	for i := range phdrs {
		var prog64 elf.Prog64
		binary.Unmarshal(phdrBuf[:prog64Size], byteOrder, &prog64)
		phdrBuf = phdrBuf[prog64Size:]
		phdrs[i] = elf.ProgHeader{
			Type:   elf.ProgType(prog64.Type),
			Flags:  elf.ProgFlag(prog64.Flags),
			Off:    prog64.Off,
			Vaddr:  prog64.Vaddr,
			Paddr:  prog64.Paddr,
			Filesz: prog64.Filesz,
			Memsz:  prog64.Memsz,
			Align:  prog64.Align,
		}
	}

	return elfInfo{
		os:           os,
		arch:         a,
		entry:        usermem.Addr(hdr.Entry),
		phdrs:        phdrs,
		phdrOff:      hdr.Phoff,
		phdrSize:     prog64Size,
		sharedObject: sharedObject,
	}, nil
}

// mapSegment maps a phdr into the Task. offset is the offset to apply to
// phdr.Vaddr.
func mapSegment(ctx context.Context, m *mm.MemoryManager, f *fs.File, phdr *elf.ProgHeader, offset usermem.Addr) error {
	// We must make a page-aligned mapping.
	adjust := usermem.Addr(phdr.Vaddr).PageOffset()

	addr, ok := offset.AddLength(phdr.Vaddr)
	if !ok {
		// If offset != 0 we should have ensured this would fit.
		ctx.Warningf("Computed segment load address overflows: %#x + %#x", phdr.Vaddr, offset)
		return syserror.ENOEXEC
	}
	addr -= usermem.Addr(adjust)

	fileSize := phdr.Filesz + adjust
	if fileSize < phdr.Filesz {
		ctx.Infof("Computed segment file size overflows: %#x + %#x", phdr.Filesz, adjust)
		return syserror.ENOEXEC
	}
	ms, ok := usermem.Addr(fileSize).RoundUp()
	if !ok {
		ctx.Infof("fileSize %#x too large", fileSize)
		return syserror.ENOEXEC
	}
	mapSize := uint64(ms)

	if mapSize > 0 {
		// This must result in a page-aligned offset. i.e., the original
		// phdr.Off must have the same alignment as phdr.Vaddr. If that is not
		// true, MMap will reject the mapping.
		fileOffset := phdr.Off - adjust

		prot := progFlagsAsPerms(phdr.Flags)
		mopts := memmap.MMapOpts{
			Length: mapSize,
			Offset: fileOffset,
			Addr:   addr,
			Fixed:  true,
			// Linux will happily allow conflicting segments to map over
			// one another.
			Unmap:    true,
			Private:  true,
			Perms:    prot,
			MaxPerms: usermem.AnyAccess,
		}
		defer func() {
			if mopts.MappingIdentity != nil {
				mopts.MappingIdentity.DecRef()
			}
		}()
		if err := f.ConfigureMMap(ctx, &mopts); err != nil {
			ctx.Infof("File is not memory-mappable: %v", err)
			return err
		}
		if _, err := m.MMap(ctx, mopts); err != nil {
			ctx.Infof("Error mapping PT_LOAD segment %+v at %#x: %v", phdr, addr, err)
			return err
		}

		// We need to clear the end of the last page that exceeds fileSize so
		// we don't map part of the file beyond fileSize.
		//
		// Note that Linux *does not* clear the portion of the first page
		// before phdr.Off.
		if mapSize > fileSize {
			zeroAddr, ok := addr.AddLength(fileSize)
			if !ok {
				panic(fmt.Sprintf("successfully mmaped address overflows? %#x + %#x", addr, fileSize))
			}
			zeroSize := int64(mapSize - fileSize)
			if zeroSize < 0 {
				panic(fmt.Sprintf("zeroSize too big? %#x", uint64(zeroSize)))
			}
			if _, err := m.ZeroOut(ctx, zeroAddr, zeroSize, usermem.IOOpts{IgnorePermissions: true}); err != nil {
				ctx.Warningf("Failed to zero end of page [%#x, %#x): %v", zeroAddr, zeroAddr+usermem.Addr(zeroSize), err)
				return err
			}
		}
	}

	memSize := phdr.Memsz + adjust
	if memSize < phdr.Memsz {
		ctx.Infof("Computed segment mem size overflows: %#x + %#x", phdr.Memsz, adjust)
		return syserror.ENOEXEC
	}

	// Allocate more anonymous pages if necessary.
	if mapSize < memSize {
		anonAddr, ok := addr.AddLength(mapSize)
		if !ok {
			panic(fmt.Sprintf("anonymous memory doesn't fit in pre-sized range? %#x + %#x", addr, mapSize))
		}
		anonSize, ok := usermem.Addr(memSize - mapSize).RoundUp()
		if !ok {
			ctx.Infof("extra anon pages too large: %#x", memSize-mapSize)
			return syserror.ENOEXEC
		}

		if _, err := m.MMap(ctx, memmap.MMapOpts{
			Length: uint64(anonSize),
			Addr:   anonAddr,
			// Fixed without Unmap will fail the mmap if something is
			// already at addr.
			Fixed:   true,
			Private: true,
			// N.B. Linux uses vm_brk to map these pages, ignoring
			// the segment protections, instead always mapping RW.
			// These pages are not included in the final brk
			// region.
			Perms:    usermem.ReadWrite,
			MaxPerms: usermem.AnyAccess,
		}); err != nil {
			ctx.Infof("Error mapping PT_LOAD segment %v anonymous memory: %v", phdr, err)
			return err
		}
	}

	return nil
}

// loadedELF describes an ELF that has been successfully loaded.
type loadedELF struct {
	// os is the target OS of the ELF.
	os abi.OS

	// arch is the target architecture of the ELF.
	arch arch.Arch

	// entry is the entry point of the ELF.
	entry usermem.Addr

	// start is the end of the ELF.
	start usermem.Addr

	// end is the end of the ELF.
	end usermem.Addr

	// interpter is the path to the ELF interpreter.
	interpreter string

	// phdrAddr is the address of the ELF program headers.
	phdrAddr usermem.Addr

	// phdrSize is the size of a single program header in the ELF.
	phdrSize int

	// phdrNum is the number of program headers.
	phdrNum int

	// auxv contains a subset of ELF-specific auxiliary vector entries:
	// * AT_PHDR
	// * AT_PHENT
	// * AT_PHNUM
	// * AT_BASE
	// * AT_ENTRY
	auxv arch.Auxv
}

// loadParsedELF loads f into mm.
//
// info is the parsed elfInfo from the header.
//
// It does not load the ELF interpreter, or return any auxv entries.
//
// Preconditions:
//  * f is an ELF file
func loadParsedELF(ctx context.Context, m *mm.MemoryManager, f *fs.File, info elfInfo, sharedLoadOffset usermem.Addr) (loadedELF, error) {
	first := true
	var start, end usermem.Addr
	var interpreter string
	for _, phdr := range info.phdrs {
		switch phdr.Type {
		case elf.PT_LOAD:
			vaddr := usermem.Addr(phdr.Vaddr)
			if first {
				first = false
				start = vaddr
			}
			if vaddr < end {
				ctx.Infof("PT_LOAD headers out-of-order. %#x < %#x", vaddr, end)
				return loadedELF{}, syserror.ENOEXEC
			}
			var ok bool
			end, ok = vaddr.AddLength(phdr.Memsz)
			if !ok {
				ctx.Infof("PT_LOAD header size overflows. %#x + %#x", vaddr, phdr.Memsz)
				return loadedELF{}, syserror.ENOEXEC
			}

		case elf.PT_INTERP:
			if phdr.Filesz < 2 {
				ctx.Infof("PT_INTERP path too small: %v", phdr.Filesz)
				return loadedELF{}, syserror.ENOEXEC
			}
			if phdr.Filesz > linux.PATH_MAX {
				ctx.Infof("PT_INTERP path too big: %v", phdr.Filesz)
				return loadedELF{}, syserror.ENOEXEC
			}

			path := make([]byte, phdr.Filesz)
			_, err := readFull(ctx, f, usermem.BytesIOSequence(path), int64(phdr.Off))
			if err != nil {
				// If an interpreter was specified, it should exist.
				ctx.Infof("Error reading PT_INTERP path: %v", err)
				return loadedELF{}, syserror.ENOEXEC
			}

			if path[len(path)-1] != 0 {
				ctx.Infof("PT_INTERP path not NUL-terminated: %v", path)
				return loadedELF{}, syserror.ENOEXEC
			}

			// Strip NUL-terminator and everything beyond from
			// string. Note that there may be a NUL-terminator
			// before len(path)-1.
			interpreter = string(path[:bytes.IndexByte(path, '\x00')])
			if interpreter == "" {
				// Linux actually attempts to open_exec("\0").
				// open_exec -> do_open_execat fails to check
				// that name != '\0' before calling
				// do_filp_open, which thus opens the working
				// directory.  do_open_execat returns EACCES
				// because the directory is not a regular file.
				//
				// We bypass that nonsense and simply
				// short-circuit with EACCES. Those this does
				// mean that there may be some edge cases where
				// the open path would return a different
				// error.
				ctx.Infof("PT_INTERP path is empty: %v", path)
				return loadedELF{}, syserror.EACCES
			}
		}
	}

	// Shared objects don't have fixed load addresses. We need to pick a
	// base address big enough to fit all segments, so we first create a
	// mapping for the total size just to find a region that is big enough.
	//
	// It is safe to unmap it immediately with racing with another mapping
	// because we are the only one in control of the MemoryManager.
	//
	// Note that the vaddr of the first PT_LOAD segment is ignored when
	// choosing the load address (even if it is non-zero). The vaddr does
	// become an offset from that load address.
	var offset usermem.Addr
	if info.sharedObject {
		totalSize := end - start
		totalSize, ok := totalSize.RoundUp()
		if !ok {
			ctx.Infof("ELF PT_LOAD segments too big")
			return loadedELF{}, syserror.ENOEXEC
		}

		var err error
		offset, err = m.MMap(ctx, memmap.MMapOpts{
			Length:  uint64(totalSize),
			Addr:    sharedLoadOffset,
			Private: true,
		})
		if err != nil {
			ctx.Infof("Error allocating address space for shared object: %v", err)
			return loadedELF{}, err
		}
		if err := m.MUnmap(ctx, offset, uint64(totalSize)); err != nil {
			panic(fmt.Sprintf("Failed to unmap base address: %v", err))
		}

		start, ok = start.AddLength(uint64(offset))
		if !ok {
			panic(fmt.Sprintf("Start %#x + offset %#x overflows?", start, offset))
		}

		end, ok = end.AddLength(uint64(offset))
		if !ok {
			panic(fmt.Sprintf("End %#x + offset %#x overflows?", end, offset))
		}

		info.entry, ok = info.entry.AddLength(uint64(offset))
		if !ok {
			ctx.Infof("Entrypoint %#x + offset %#x overflows? Is the entrypoint within a segment?", info.entry, offset)
			return loadedELF{}, err
		}
	}

	// Map PT_LOAD segments.
	for _, phdr := range info.phdrs {
		switch phdr.Type {
		case elf.PT_LOAD:
			if phdr.Memsz == 0 {
				// No need to load segments with size 0, but
				// they exist in some binaries.
				continue
			}

			if err := mapSegment(ctx, m, f, &phdr, offset); err != nil {
				ctx.Infof("Failed to map PT_LOAD segment: %+v", phdr)
				return loadedELF{}, err
			}
		}
	}

	// This assumes that the first segment contains the ELF headers. This
	// may not be true in a malformed ELF, but Linux makes the same
	// assumption.
	phdrAddr, ok := start.AddLength(info.phdrOff)
	if !ok {
		ctx.Warningf("ELF start address %#x + phdr offset %#x overflows", start, info.phdrOff)
		phdrAddr = 0
	}

	return loadedELF{
		os:          info.os,
		arch:        info.arch,
		entry:       info.entry,
		start:       start,
		end:         end,
		interpreter: interpreter,
		phdrAddr:    phdrAddr,
		phdrSize:    info.phdrSize,
		phdrNum:     len(info.phdrs),
	}, nil
}

// loadInitialELF loads f into mm.
//
// It creates an arch.Context for the ELF and prepares the mm for this arch.
//
// It does not load the ELF interpreter, or return any auxv entries.
//
// Preconditions:
//  * f is an ELF file
//  * f is the first ELF loaded into m
func loadInitialELF(ctx context.Context, m *mm.MemoryManager, fs *cpuid.FeatureSet, f *fs.File) (loadedELF, arch.Context, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		ctx.Infof("Failed to parse initial ELF: %v", err)
		return loadedELF{}, nil, err
	}

	// Create the arch.Context now so we can prepare the mmap layout before
	// mapping anything.
	ac := arch.New(info.arch, fs)

	l, err := m.SetMmapLayout(ac, limits.FromContext(ctx))
	if err != nil {
		ctx.Warningf("Failed to set mmap layout: %v", err)
		return loadedELF{}, nil, err
	}

	// PIELoadAddress tries to move the ELF out of the way of the default
	// mmap base to ensure that the initial brk has sufficient space to
	// grow.
	le, err := loadParsedELF(ctx, m, f, info, ac.PIELoadAddress(l))
	return le, ac, err
}

// loadInterpreterELF loads f into mm.
//
// The interpreter must be for the same OS/Arch as the initial ELF.
//
// It does not return any auxv entries.
//
// Preconditions:
//  * f is an ELF file
func loadInterpreterELF(ctx context.Context, m *mm.MemoryManager, f *fs.File, initial loadedELF) (loadedELF, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		if err == syserror.ENOEXEC {
			// Bad interpreter.
			err = syserror.ELIBBAD
		}
		return loadedELF{}, err
	}

	if info.os != initial.os {
		ctx.Infof("Initial ELF OS %v and interpreter ELF OS %v differ", initial.os, info.os)
		return loadedELF{}, syserror.ELIBBAD
	}
	if info.arch != initial.arch {
		ctx.Infof("Initial ELF arch %v and interpreter ELF arch %v differ", initial.arch, info.arch)
		return loadedELF{}, syserror.ELIBBAD
	}

	// The interpreter is not given a load offset, as its location does not
	// affect brk.
	return loadParsedELF(ctx, m, f, info, 0)
}

// loadELF loads f into the Task address space.
//
// If loadELF returns ErrSwitchFile it should be called again with the returned
// path and argv.
//
// Preconditions:
//  * f is an ELF file
func loadELF(ctx context.Context, m *mm.MemoryManager, mounts *fs.MountNamespace, root, wd *fs.Dirent, maxTraversals *uint, fs *cpuid.FeatureSet, f *fs.File) (loadedELF, arch.Context, error) {
	bin, ac, err := loadInitialELF(ctx, m, fs, f)
	if err != nil {
		ctx.Infof("Error loading binary: %v", err)
		return loadedELF{}, nil, err
	}

	var interp loadedELF
	if bin.interpreter != "" {
		d, i, err := openPath(ctx, mounts, root, wd, maxTraversals, bin.interpreter)
		if err != nil {
			ctx.Infof("Error opening interpreter %s: %v", bin.interpreter, err)
			return loadedELF{}, nil, err
		}
		defer i.DecRef()
		// We don't need the Dirent.
		d.DecRef()

		interp, err = loadInterpreterELF(ctx, m, i, bin)
		if err != nil {
			ctx.Infof("Error loading interpreter: %v", err)
			return loadedELF{}, nil, err
		}

		if interp.interpreter != "" {
			// No recursive interpreters!
			ctx.Infof("Interpreter requires an interpreter")
			return loadedELF{}, nil, syserror.ENOEXEC
		}
	}

	// ELF-specific auxv entries.
	bin.auxv = arch.Auxv{
		arch.AuxEntry{linux.AT_PHDR, bin.phdrAddr},
		arch.AuxEntry{linux.AT_PHENT, usermem.Addr(bin.phdrSize)},
		arch.AuxEntry{linux.AT_PHNUM, usermem.Addr(bin.phdrNum)},
		arch.AuxEntry{linux.AT_ENTRY, bin.entry},
	}
	if bin.interpreter != "" {
		bin.auxv = append(bin.auxv, arch.AuxEntry{linux.AT_BASE, interp.start})

		// Start in the interpreter.
		// N.B. AT_ENTRY above contains the *original* entry point.
		bin.entry = interp.entry
	} else {
		// Always add AT_BASE even if there is no interpreter.
		bin.auxv = append(bin.auxv, arch.AuxEntry{linux.AT_BASE, 0})
	}

	return bin, ac, nil
}
