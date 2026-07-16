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
// proxy: forwarding the RDMA_VERBS_IOCTL to the host, reading from host FDs,
// and mirroring app pages into the sentry's address space via mmap/mremap.

package rdmaproxy

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// maxMirrorLen caps a single DMA-buffer mirror, bounding the memory a malicious
// guest can force the sentry to pin. 64 GiB is far above any legitimate RDMA
// work-queue or host bounce buffer while still refusing an obviously abusive
// length.
const maxMirrorLen = 64 << 30

// invokeUverbsIoctl forwards a pre-built RDMA_VERBS_IOCTL buffer to the host
// kernel. buf must already have its attribute data pointers rewritten to
// sentry-side addresses, and every referenced buffer must be kept alive across
// this call (see the runtime.KeepAlive in handleRDMAVerbsIoctl).
func invokeUverbsIoctl(hostFD int32, buf []byte) (uintptr, unix.Errno) {
	n, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(hostFD),
		uintptr(ib.RDMAVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(buf)
	return n, errno
}

// sentryDataPtr returns the address of the first byte of sb as a uint64 for
// placing into an ioctl attribute data field.
func sentryDataPtr(sb []byte) uint64 {
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

// eventReadBufLen bounds a single guest read(2) of a proxied event FD. Both the
// uverbs cdev async path and the dedicated async-event FD only ever deliver
// fixed 16-byte struct ib_uverbs_async_event_desc records (8-byte completion
// descriptors on a comp channel), so a small stack buffer drains several at
// once without a per-read heap allocation.
const eventReadBufLen = 128

// readProxiedEventFD services a guest read(2) on a proxied host event fd (the
// uverbs FD async stream, or an async-event FD). It is not the ioctl datapath:
// app blocks here waiting for async events that a healthy fabric never raises.
func readProxiedEventFD(ctx context.Context, hostFD int32, dst usermem.IOSequence) (int64, error) {
	n := int(dst.NumBytes())
	if n == 0 {
		return 0, nil
	}
	if fdnotifier.NonBlockingPoll(hostFD, waiter.ReadableEvents) == 0 {
		return 0, linuxerr.ErrWouldBlock
	}
	if n > eventReadBufLen {
		n = eventReadBufLen
	}
	var buf [eventReadBufLen]byte
	got, errno := readHostFDNonblocking(hostFD, buf[:n])
	if errno != 0 {
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return 0, linuxerr.ErrWouldBlock
		}
		return 0, errno
	}
	if got == 0 {
		return 0, nil
	}
	w, err := dst.CopyOut(ctx, buf[:got])
	return int64(w), err
}

var madvPopulateWriteDisabled atomicbitops.Bool

// MirrorAppPages pins the app pages backing [addr, addr+length) and maps them
// contiguously into the sentry's address space so the host kernel can
// pin_user_pages on them for DMA. It returns the mirror and the sentry VA
// corresponding to addr.
func MirrorAppPages(t *kernel.Task, addr, length uint64) (*MirroredPages, uintptr, error) {
	if length == 0 || length > maxMirrorLen {
		return nil, 0, linuxerr.EINVAL
	}
	alignedStart := hostarch.Addr(addr).RoundDown()
	alignedEnd, ok := hostarch.Addr(addr + length).RoundUp()
	if !ok || uint64(alignedEnd) <= addr {
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
		return nil, 0, pinErr
	}

	cu := cleanup.Make(func() { mm.Unpin(prs) })
	defer cu.Clean()

	// Prefer a single contiguous internal mapping if the pinned range is one
	// physically contiguous run.
	var m uintptr
	mOwned := false
	if len(prs) == 1 {
		pr := prs[0]
		ims, err := pr.File.MapInternal(memmap.FileRange{Start: pr.Offset, End: pr.Offset + uint64(pr.Source.Length())}, at)
		if err != nil {
			return nil, 0, err
		}
		if ims.NumBlocks() == 1 {
			m = ims.Head().Addr()
		}
	}

	// Otherwise reserve a contiguous sentry range and remap each internal
	// mapping into it.
	if m == 0 {
		var errno unix.Errno
		m, _, errno = unix.RawSyscall6(unix.SYS_MMAP, 0, uintptr(alignedLen), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0), 0)
		if errno != 0 {
			return nil, 0, errno
		}
		mOwned = true
		cu.Add(func() {
			unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(alignedLen), 0)
		})
		sentryAddr := m
		for _, pr := range prs {
			ims, err := pr.File.MapInternal(memmap.FileRange{Start: pr.Offset, End: pr.Offset + uint64(pr.Source.Length())}, at)
			if err != nil {
				return nil, 0, err
			}
			for !ims.IsEmpty() {
				im := ims.Head()
				if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, im.Addr(), 0, uintptr(im.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, sentryAddr, 0); errno != 0 {
					return nil, 0, errno
				}
				sentryAddr += uintptr(im.Len())
				ims = ims.Tail()
			}
		}
	}

	// Best-effort pre-fault to avoid mmap_lock contention on first DMA.
	// MADV_POPULATE_WRITE needs Linux 5.14; if it is unavailable the failure is
	// permanent, so stop retrying it after the first failure.
	if !madvPopulateWriteDisabled.Load() {
		if _, _, errno := unix.Syscall(unix.SYS_MADVISE, m, uintptr(alignedLen), unix.MADV_POPULATE_WRITE); errno != 0 {
			if !madvPopulateWriteDisabled.Swap(true) {
				log.Infof("rdmaproxy: disabling MADV_POPULATE_WRITE pre-fault: %s", errno)
			}
		}
	}

	mp := &MirroredPages{prs: prs}
	if mOwned {
		mp.m = m
		mp.len = uintptr(alignedLen)
	}
	cu.Release()

	sentryVA := m + uintptr(addr-uint64(alignedStart))
	return mp, sentryVA, nil
}
