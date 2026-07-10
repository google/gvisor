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

package rdmaproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/rdma"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// pendingPins tracks application memory pinned for an in-flight write()
// command whose payload embeds an application buffer address (REG_MR). The
// pins and the sentry VA window live until the host write() resolves:
// commit() releases only the window, since the host kernel then holds its
// own page references (ib_umem_get) and only the MemoryFile pins must
// persist for the MR's lifetime; abort() releases both.
type pendingPins struct {
	prs    []mm.PinnedRange
	window uintptr // sentry VA reservation backing the rewritten Start
	winLen uintptr
}

// setupRegMR parses IBUverbsRegMR from buf, pins the application range it
// describes, and rewrites Start in buf to the sentry address of a mirror
// mapping. HCAVA (the NIC-visible address) deliberately remains the
// application's original address, so the application's SGEs and rkeys keep
// working unchanged.
func (pins *pendingPins) setupRegMR(ctx context.Context, t *kernel.Task, buf []byte) error {
	if len(buf) < int(rdma.SizeofIBUverbsCmdHdr+rdma.SizeofIBUverbsRegMR) {
		return linuxerr.EINVAL
	}
	var regMR rdma.IBUverbsRegMR
	regMR.UnmarshalBytes(buf[rdma.SizeofIBUverbsCmdHdr:])

	// Match ib_umem_get(): pages are pinned writable iff the MR grants
	// write access.
	at := hostarch.Read
	if regMR.AccessFlags&(rdma.IB_UVERBS_ACCESS_LOCAL_WRITE|rdma.IB_UVERBS_ACCESS_REMOTE_WRITE|rdma.IB_UVERBS_ACCESS_REMOTE_ATOMIC) != 0 {
		at = hostarch.ReadWrite
	}
	sentryAddr, pp, err := pinMapAppRange(ctx, t, hostarch.Addr(regMR.Start), regMR.Length, at)
	if err != nil {
		return err
	}
	*pins = pp

	regMR.Start = uint64(sentryAddr)
	regMR.MarshalBytes(buf[rdma.SizeofIBUverbsCmdHdr:])
	return nil
}

// commit releases the sentry VA window after a successful host write() and
// returns the pins, which the caller must retain (see saveMR) until the MR
// is deregistered.
func (pins *pendingPins) commit() []mm.PinnedRange {
	if pins.winLen != 0 {
		unix.RawSyscall(unix.SYS_MUNMAP, pins.window, pins.winLen, 0)
	}
	prs := pins.prs
	*pins = pendingPins{}
	return prs
}

// abort undoes setupRegMR after a failed host write(). It is a no-op on a
// zero pendingPins, so it is safe to call unconditionally.
func (pins *pendingPins) abort() {
	if pins.winLen != 0 {
		unix.RawSyscall(unix.SYS_MUNMAP, pins.window, pins.winLen, 0)
	}
	mm.Unpin(pins.prs)
	*pins = pendingPins{}
}

// pinMapAppRange pins the application address range [addr, addr+length) and
// mirrors it into a single virtually-contiguous sentry VA window, returning
// the sentry address corresponding to addr along with the pendingPins that
// own the window and pins. The window is contiguous even when the backing
// MemoryFile ranges are fragmented, which is what the MR requires and what
// the application's own mapping cannot guarantee. Modeled on tpuproxy's
// iommuMapDma (pkg/sentry/devices/tpuproxy/vfio/vfio_fd.go), except that
// the window must outlive this call: the host write() that consumes the
// rewritten address happens later, so the caller releases the window via
// commit() or abort().
func pinMapAppRange(ctx context.Context, t *kernel.Task, addr hostarch.Addr, length uint64, at hostarch.AccessType) (uintptr, pendingPins, error) {
	if length == 0 || int64(length) <= 0 {
		return 0, pendingPins{}, linuxerr.EINVAL
	}
	tmm := t.MemoryManager()
	ar, ok := tmm.CheckIORange(addr, int64(length))
	if !ok {
		return 0, pendingPins{}, linuxerr.EFAULT
	}
	// mm.Pin requires a page-aligned range. MRs may start and end anywhere
	// within a page; pin the containing pages, as ib_umem_get() does.
	arEnd, ok := ar.End.RoundUp()
	if !ok {
		return 0, pendingPins{}, linuxerr.EFAULT
	}
	ar = hostarch.AddrRange{Start: ar.Start.RoundDown(), End: arEnd}

	// Reserve a contiguous window in the sentry address space.
	window, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(ar.Length()), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0) /* fd */, 0)
	if errno != 0 {
		return 0, pendingPins{}, errno
	}
	cu := cleanup.Make(func() {
		unix.RawSyscall(unix.SYS_MUNMAP, window, uintptr(ar.Length()), 0)
	})
	defer cu.Clean()

	prs, err := tmm.Pin(ctx, ar, at, false /* ignorePermissions */)
	if err != nil {
		// Pin may return a partial result alongside an error.
		mm.Unpin(prs)
		return 0, pendingPins{}, err
	}
	cu.Add(func() {
		mm.Unpin(prs)
	})

	// Mirror the pinned MemoryFile ranges into the window, back to back.
	// mremap with old_size == 0 duplicates the source mapping rather than
	// moving it, which is only possible because MemoryFile mappings are
	// MAP_SHARED.
	sentryAddr := window
	for _, pr := range prs {
		ims, err := pr.File.MapInternal(pr.FileRange(), at)
		if err != nil {
			return 0, pendingPins{}, err
		}
		for !ims.IsEmpty() {
			im := ims.Head()
			if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, im.Addr(), 0 /* old_size */, uintptr(im.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, sentryAddr, 0); errno != 0 {
				return 0, pendingPins{}, errno
			}
			sentryAddr += uintptr(im.Len())
			ims = ims.Tail()
		}
	}

	cu.Release()
	return window + uintptr(addr.PageOffset()), pendingPins{
		prs:    prs,
		window: window,
		winLen: uintptr(ar.Length()),
	}, nil
}

// saveMR records the pins backing a registered MR so they can be released
// on DEREG_MR or Release.
func (fd *rdmaFD) saveMR(handle uint32, prs []mm.PinnedRange) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if fd.mrPins == nil {
		fd.mrPins = make(map[uint32][]mm.PinnedRange)
	}
	fd.mrPins[handle] = prs
}

// forgetMR unpins the memory backing a deregistered MR.
func (fd *rdmaFD) forgetMR(handle uint32) {
	fd.mu.Lock()
	prs := fd.mrPins[handle]
	delete(fd.mrPins, handle)
	fd.mu.Unlock()
	mm.Unpin(prs)
}

// unpinAll releases every pin held by fd; called on Release.
func (fd *rdmaFD) unpinAll() {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	for handle, prs := range fd.mrPins {
		mm.Unpin(prs)
		delete(fd.mrPins, handle)
	}
}
