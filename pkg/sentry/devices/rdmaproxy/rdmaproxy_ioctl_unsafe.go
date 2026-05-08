// Copyright 2024 The gVisor Authors.
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

// This file isolates the unsafe.Pointer and raw-syscall surface of the rdma
// proxy: forwarding the RDMA_VERBS_IOCTL to the host, reading from host
// FDs, and mirroring sandbox pages into the sentry's address space via
// mmap/mremap. All other ioctl-handling logic lives in rdmaproxy_ioctl.go.

package rdmaproxy

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// invokeUverbsIoctl forwards a pre-built RDMA_VERBS_IOCTL buffer to the host
// kernel. buf must have its attr data pointers rewritten to sentry-side
// addresses; see attrDataPtr.
//
// The ioctl runs in the calling sentry task's netns. For RoCE this is the
// sandbox container's netns, which is expected to contain the netdev that
// backs the uverbs device's ibdev (see runsc/sandbox.MoveRDMANetdevsIntoSandbox).
// With the netdev local, ibv_modify_qp's GID-to-netdev resolution at
// INIT→RTR succeeds without any namespace switching here.
func invokeUverbsIoctl(hostFD int32, buf []byte) (uintptr, unix.Errno) {
	n, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(hostFD),
		uintptr(rdmaVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))
	return n, errno
}

// attrDataPtr returns the first-byte address of sb as a uint64 suitable for
// placing into an ioctl attr data field.
func attrDataPtr(sb []byte) uint64 {
	return uint64(uintptr(unsafe.Pointer(&sb[0])))
}

// readHostFDNonblocking issues a read(2) on hostFD into buf. The host FD is
// expected to be in O_NONBLOCK mode; callers translate EAGAIN/EWOULDBLOCK into
// ErrWouldBlock.
func readHostFDNonblocking(hostFD int32, buf []byte) (int, unix.Errno) {
	if len(buf) == 0 {
		return 0, 0
	}
	n, _, errno := unix.RawSyscall(unix.SYS_READ,
		uintptr(hostFD),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)))
	return int(n), errno
}

// MirrorSandboxPages pins the sandbox pages backing [addr, addr+length) and
// maps them into the sentry's address space. Returns the mirrored pages and
// the sentry VA corresponding to the original sandbox address.
//
// Exported so per-vendor Driver plug-ins can mirror the DMA buffers
// referenced by their driver-private input attribute.
func MirrorSandboxPages(t *kernel.Task, addr, length uint64) (*MirroredPages, uintptr, error) {
	alignedStart := hostarch.Addr(addr).RoundDown()
	alignedEnd, ok := hostarch.Addr(addr + length).RoundUp()
	if !ok {
		return nil, 0, linuxerr.EINVAL
	}
	alignedLen := uint64(alignedEnd - alignedStart)

	appAR, ok := alignedStart.ToRange(alignedLen)
	if !ok {
		return nil, 0, linuxerr.EINVAL
	}

	at := hostarch.ReadWrite
	prs, pinErr := t.MemoryManager().Pin(t, appAR, at, false /* ignorePermissions */)
	if pinErr != nil {
		return nil, 0, fmt.Errorf("Pin: %w", pinErr)
	}

	cu := cleanup.Make(func() { mm.Unpin(prs) })
	defer cu.Clean()

	// Try to get a single contiguous internal mapping.
	var m uintptr
	mOwned := false
	if len(prs) == 1 {
		pr := prs[0]
		ims, err := pr.File.MapInternal(memmap.FileRange{pr.Offset, pr.Offset + uint64(pr.Source.Length())}, at)
		if err == nil && ims.NumBlocks() == 1 {
			m = ims.Head().Addr()
		}
	}

	// If not contiguous, build a contiguous sentry mapping via mmap+mremap.
	if m == 0 {
		var errno unix.Errno
		m, _, errno = unix.RawSyscall6(unix.SYS_MMAP, 0, uintptr(alignedLen), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0), 0)
		if errno != 0 {
			return nil, 0, fmt.Errorf("mmap anon %d bytes: %w", alignedLen, errno)
		}
		mOwned = true
		cu.Add(func() {
			unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(alignedLen), 0)
		})
		sentryAddr := m
		for _, pr := range prs {
			ims, err := pr.File.MapInternal(memmap.FileRange{pr.Offset, pr.Offset + uint64(pr.Source.Length())}, at)
			if err != nil {
				return nil, 0, fmt.Errorf("MapInternal: %w", err)
			}
			for !ims.IsEmpty() {
				im := ims.Head()
				if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, im.Addr(), 0, uintptr(im.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, sentryAddr, 0); errno != 0 {
					return nil, 0, fmt.Errorf("mremap %#x→%#x len %d: %w", im.Addr(), sentryAddr, im.Len(), errno)
				}
				sentryAddr += uintptr(im.Len())
				ims = ims.Tail()
			}
		}
	}

	// Best-effort pre-fault to avoid mmap_lock contention.
	unix.Syscall(unix.SYS_MADVISE, m, uintptr(alignedLen), unix.MADV_POPULATE_WRITE)

	mp := &MirroredPages{prs: prs}
	if mOwned {
		mp.m = m
		mp.len = uintptr(alignedLen)
	}
	cu.Release()

	sentryVA := m + uintptr(addr-uint64(alignedStart))
	return mp, sentryVA, nil
}
