// Copyright 2026 The gVisor Authors.
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

package amdgpuproxy

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

func hostBufferPointer(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

// hostIoctl issues cmd with argument arg. nested are the buffers that arg
// points to; they are pinned for the duration of the call.
func hostIoctl(fd int32, cmd uint32, arg []byte, nested ...[]byte) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	for _, b := range nested {
		if len(b) != 0 {
			pinner.Pin(&b[0])
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(cmd), uintptr(unsafe.Pointer(&arg[0]))); errno != 0 {
		return errno
	}
	return nil
}

// userMemory is application memory pinned for a USERPTR registration, with a
// contiguous sentry alias at hostAddr.
type userMemory struct {
	pinned   []mm.PinnedRange
	size     uint64
	hostAddr uintptr
	// mapped is true if hostAddr is a mapping made by mapAlias rather than an
	// internal mapping of the backing file.
	mapped bool
}

func pinUserMemory(t *kernel.Task, addr, size uint64) (*userMemory, error) {
	ar, ok := hostarch.Addr(addr).ToRange(size)
	if !ok || size == 0 || !ar.IsPageAligned() {
		return nil, linuxerr.EINVAL
	}
	// The driver registers user pointers for writing.
	pinned, err := t.MemoryManager().Pin(t, ar, hostarch.ReadWrite, false)
	if err != nil {
		return nil, err
	}
	um := &userMemory{pinned: pinned, size: size}
	if err := um.mapAlias(); err != nil {
		um.release()
		return nil, err
	}
	return um, nil
}

func (um *userMemory) mapAlias() error {
	if len(um.pinned) == 1 {
		pr := um.pinned[0]
		bs, err := pr.File.MapInternal(pr.FileRange(), hostarch.ReadWrite)
		if err != nil {
			return err
		}
		if bs.NumBlocks() == 1 {
			um.hostAddr = bs.Head().Addr()
			return nil
		}
	}
	// Assemble a contiguous alias from the internal mappings: mremap with a
	// zero old size duplicates a shared mapping.
	m, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0, uintptr(um.size), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0), 0)
	if errno != 0 {
		return errno
	}
	um.hostAddr, um.mapped = m, true
	for _, pr := range um.pinned {
		bs, err := pr.File.MapInternal(pr.FileRange(), hostarch.ReadWrite)
		if err != nil {
			return err
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			b := bs.Head()
			if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, b.Addr(), 0, uintptr(b.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, m, 0); errno != 0 {
				return errno
			}
			m += uintptr(b.Len())
		}
	}
	return nil
}

func (um *userMemory) release() {
	if um.mapped {
		unix.RawSyscall(unix.SYS_MUNMAP, um.hostAddr, uintptr(um.size), 0)
	}
	mm.Unpin(um.pinned)
}
