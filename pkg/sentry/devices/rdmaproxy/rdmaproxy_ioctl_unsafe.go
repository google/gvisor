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

package rdmaproxy

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// ib_uverbs_ioctl_hdr layout constants.
const (
	rdmaIoctlMagic       = 0x1b
	ibUverbsIoctlHdrSize = 24
	ibUverbsAttrSize     = 16
)

// UVERBS object types (from include/uapi/rdma/ib_user_ioctl_cmds.h).
const (
	uverbsObjectDevice = 0
	uverbsObjectCQ     = 3
	uverbsObjectQP     = 4
	uverbsObjectMR     = 7
)

// UVERBS method IDs.
const (
	uverbsMethodInvokeWrite = 0 // DEVICE object
	uverbsMethodMRDestroy   = 1 // MR object
	uverbsMethodRegMR       = 5 // MR object (modern path)
)

// INVOKE_WRITE attr IDs.
const (
	uverbsAttrCoreIn   = 0
	uverbsAttrCoreOut  = 1
	uverbsAttrWriteCmd = 2
)

// Legacy write command numbers (from include/uapi/rdma/ib_user_verbs.h).
const (
	ibUserVerbsCmdCreateCQ  = 6
	ibUserVerbsCmdCreateQP  = 8
	ibUserVerbsCmdRegMR     = 9
	ibUserVerbsCmdDestroyCQ = 11
	ibUserVerbsCmdDeregMR   = 13
	ibUserVerbsCmdDestroyQP = 14
)

// mlx5 driver attr offsets for CQ/QP CREATE (struct mlx5_ib_create_cq / mlx5_ib_create_qp).
const (
	driverAttrBufAddr = 0  // __aligned_u64 buf_addr
	driverAttrDBAddr  = 8  // __aligned_u64 db_addr
	driverAttrMinLen  = 16 // minimum driver attr size we need
)

// mlx5 driver attr IDs.
const (
	mlx5DriverAttrIn  = 0x1000 // input driver data
	mlx5DriverAttrOut = 0x1001 // output driver data
)

// ioctlAction classifies what an ioctl does for page-mirroring purposes.
type ioctlAction int

const (
	actionNone ioctlAction = iota
	actionMRReg
	actionMRDereg
	actionCQCreate
	actionCQDestroy
	actionQPCreate
	actionQPDestroy
)

// ib_uverbs_reg_mr struct field offsets.
const (
	regMROffStart  = 8  // __aligned_u64 start
	regMROffLength = 16 // __aligned_u64 length
	regMROffHcaVA  = 24 // __aligned_u64 hca_va
)

// ib_uverbs_reg_mr_resp field offsets.
const (
	regMRRespOffHandle = 0 // __u32 mr_handle
)

// ib_uverbs_dereg_mr field offsets.
const (
	deregMROffHandle = 0 // __u32 mr_handle
)

// REG_MR attr IDs (modern path).
const (
	uverbsAttrRegMRHandle = 0
	uverbsAttrRegMRAddr   = 4
	uverbsAttrRegMRLength = 5
)

// DESTROY_MR attr IDs.
const (
	uverbsAttrDestroyMRHandle = 0
)

// RDMA_VERBS_IOCTL = _IOWR(0x1b, 1, struct ib_uverbs_ioctl_hdr)
var rdmaVerbsIoctl = linux.IOWR(rdmaIoctlMagic, 1, ibUverbsIoctlHdrSize)

// attrRewrite tracks a sandbox pointer that was rewritten to a sentry buffer.
type attrRewrite struct {
	attrOff  int
	origData uint64
	sentry   []byte
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *uverbsFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("rdmaproxy: ioctl called without task context")
		return 0, unix.EINVAL
	}

	if cmd == rdmaVerbsIoctl {
		return fd.handleRDMAVerbsIoctl(t, argPtr)
	}
	log.Warningf("rdmaproxy: unhandled ioctl cmd=0x%x (magic=0x%x nr=%d size=%d) on hostFD=%d",
		cmd, (cmd>>8)&0xff, cmd&0xff, (cmd>>16)&0x3fff, fd.hostFD)
	return 0, linuxerr.ENOSYS
}

// handleRDMAVerbsIoctl handles the modern RDMA_VERBS_IOCTL which uses a
// self-describing header + variable-length attribute array.
func (fd *uverbsFD) handleRDMAVerbsIoctl(t *kernel.Task, argPtr hostarch.Addr) (uintptr, error) {
	var hdrBuf [ibUverbsIoctlHdrSize]byte
	if _, err := t.CopyInBytes(argPtr, hdrBuf[:]); err != nil {
		log.Warningf("rdmaproxy: ioctl CopyIn header from %#x: %v", argPtr, err)
		return 0, err
	}

	length := binary.LittleEndian.Uint16(hdrBuf[0:2])
	objectID := binary.LittleEndian.Uint16(hdrBuf[2:4])
	methodID := binary.LittleEndian.Uint16(hdrBuf[4:6])
	numAttrs := binary.LittleEndian.Uint16(hdrBuf[6:8])
	reserved1 := binary.LittleEndian.Uint64(hdrBuf[8:16])
	driverID := binary.LittleEndian.Uint32(hdrBuf[16:20])

	log.Infof("rdmaproxy: IOCTL hostFD=%d obj=0x%04x method=%d attrs=%d len=%d reserved=%#x driver=%d",
		fd.hostFD, objectID, methodID, numAttrs, length, reserved1, driverID)

	expectedLen := uint16(ibUverbsIoctlHdrSize) + numAttrs*uint16(ibUverbsAttrSize)
	if length != expectedLen || length > hostarch.PageSize {
		log.Warningf("rdmaproxy: ioctl bad header: length=%d expected=%d (numAttrs=%d)",
			length, expectedLen, numAttrs)
		return 0, linuxerr.EINVAL
	}

	buf := make([]byte, length)
	if _, err := t.CopyInBytes(argPtr, buf); err != nil {
		log.Warningf("rdmaproxy: ioctl CopyIn full buffer (%d bytes) from %#x: %v",
			length, argPtr, err)
		return 0, err
	}

	// Walk attrs: probe each data field to determine if it's a sandbox
	// pointer (CopyIn succeeds) or inline data (CopyIn fails).
	var rewrites []attrRewrite
	for i := 0; i < int(numAttrs); i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		attrFlags := binary.LittleEndian.Uint16(buf[off+4 : off+6])
		attrData := binary.LittleEndian.Uint64(buf[off+8 : off+16])

		if attrLen == 0 {
			log.Infof("rdmaproxy:   attr[%d] id=0x%04x len=0 flags=0x%04x data=%#016x (handle/fd)",
				i, attrID, attrFlags, attrData)
			continue
		}

		sb := make([]byte, attrLen)
		_, copyErr := t.CopyInBytes(hostarch.Addr(attrData), sb)
		if copyErr == nil {
			log.Infof("rdmaproxy:   attr[%d] id=0x%04x len=%d flags=0x%04x data=ptr:%#016x (rewrite)",
				i, attrID, attrLen, attrFlags, attrData)
			if attrLen <= 64 {
				log.Infof("rdmaproxy:   attr[%d] data: %x", i, sb)
			} else {
				log.Infof("rdmaproxy:   attr[%d] data (first 64): %x ...", i, sb[:64])
			}
			binary.LittleEndian.PutUint64(buf[off+8:off+16],
				uint64(uintptr(unsafe.Pointer(&sb[0]))))
			rewrites = append(rewrites, attrRewrite{
				attrOff:  off,
				origData: attrData,
				sentry:   sb,
			})
		} else {
			log.Infof("rdmaproxy:   attr[%d] id=0x%04x len=%d flags=0x%04x data=inline:%#016x",
				i, attrID, attrLen, attrFlags, attrData)
		}
	}

	// Classify and prepare DMA page mirroring before forwarding.
	action, writeCmdVal := fd.classifyIoctl(buf, int(numAttrs), objectID, methodID)

	var mrMirror *mirroredPages
	var cqqpMirror *pinnedDMABufs
	var dmaCleanup cleanup.Cleanup
	defer dmaCleanup.Clean()

	switch action {
	case actionMRReg:
		var err error
		mrMirror, err = fd.prepareMRReg(t, buf, int(numAttrs), objectID, rewrites, writeCmdVal)
		if err != nil {
			log.Warningf("rdmaproxy: MR REG page mirroring: %v", err)
			return 0, err
		}
		if mrMirror != nil {
			dmaCleanup = cleanup.Make(func() { mrMirror.release(t) })
		}

	case actionCQCreate, actionQPCreate:
		var err error
		cqqpMirror, err = fd.prepareCQQPCreate(t, buf, int(numAttrs), rewrites, action)
		if err != nil {
			log.Warningf("rdmaproxy: CQ/QP CREATE page mirroring: %v", err)
			return 0, err
		}
		if cqqpMirror != nil {
			dmaCleanup = cleanup.Make(func() { cqqpMirror.release(t) })
		}
	}

	log.Infof("rdmaproxy: forwarding ioctl to host (hostFD=%d, %d rewrites, action=%d)", fd.hostFD, len(rewrites), action)

	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
		uintptr(fd.hostFD), uintptr(rdmaVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))

	if errno != 0 {
		log.Infof("rdmaproxy: host ioctl returned n=%d errno=%d (%v)", n, errno, errno)
	} else {
		log.Infof("rdmaproxy: host ioctl returned n=%d OK", n)
	}

	// Post-ioctl tracking for successful operations.
	if errno == 0 {
		switch action {
		case actionMRReg:
			if mrMirror != nil {
				mrHandle := fd.extractMRHandle(buf, int(numAttrs), objectID, rewrites, writeCmdVal)
				if mrHandle != 0 {
					fd.mu.Lock()
					if fd.pinnedMRs == nil {
						fd.pinnedMRs = make(map[uint32]*mirroredPages)
					}
					fd.pinnedMRs[mrHandle] = mrMirror
					fd.mu.Unlock()
					dmaCleanup.Release()
					log.Infof("rdmaproxy: pinned MR handle=%d (%d ranges)", mrHandle, len(mrMirror.prs))
				}
			}

		case actionMRDereg:
			mrHandle := fd.extractDeregMRHandle(buf, int(numAttrs), objectID, rewrites, writeCmdVal)
			if mrHandle != 0 {
				fd.mu.Lock()
				if mp, ok := fd.pinnedMRs[mrHandle]; ok {
					delete(fd.pinnedMRs, mrHandle)
					fd.mu.Unlock()
					mp.release(t)
					log.Infof("rdmaproxy: unpinned MR handle=%d", mrHandle)
				} else {
					fd.mu.Unlock()
				}
			}

		case actionCQCreate:
			if cqqpMirror != nil {
				handle := fd.extractCQQPHandle(buf, int(numAttrs), objectID, rewrites)
				if handle != 0 {
					fd.mu.Lock()
					if fd.pinnedCQs == nil {
						fd.pinnedCQs = make(map[uint32]*pinnedDMABufs)
					}
					fd.pinnedCQs[handle] = cqqpMirror
					fd.mu.Unlock()
					dmaCleanup.Release()
					log.Infof("rdmaproxy: pinned CQ handle=%d", handle)
				}
			}

		case actionQPCreate:
			if cqqpMirror != nil {
				handle := fd.extractCQQPHandle(buf, int(numAttrs), objectID, rewrites)
				if handle != 0 {
					fd.mu.Lock()
					if fd.pinnedQPs == nil {
						fd.pinnedQPs = make(map[uint32]*pinnedDMABufs)
					}
					fd.pinnedQPs[handle] = cqqpMirror
					fd.mu.Unlock()
					dmaCleanup.Release()
					log.Infof("rdmaproxy: pinned QP handle=%d", handle)
				}
			}

		case actionCQDestroy:
			handle := fd.extractCQQPDestroyHandle(buf, int(numAttrs), objectID, rewrites)
			if handle != 0 {
				fd.mu.Lock()
				if p, ok := fd.pinnedCQs[handle]; ok {
					delete(fd.pinnedCQs, handle)
					fd.mu.Unlock()
					p.release(t)
					log.Infof("rdmaproxy: unpinned CQ handle=%d", handle)
				} else {
					fd.mu.Unlock()
				}
			}

		case actionQPDestroy:
			handle := fd.extractCQQPDestroyHandle(buf, int(numAttrs), objectID, rewrites)
			if handle != 0 {
				fd.mu.Lock()
				if p, ok := fd.pinnedQPs[handle]; ok {
					delete(fd.pinnedQPs, handle)
					fd.mu.Unlock()
					p.release(t)
					log.Infof("rdmaproxy: unpinned QP handle=%d", handle)
				} else {
					fd.mu.Unlock()
				}
			}
		}
	}

	// Copy output data back and restore original pointers.
	for _, rw := range rewrites {
		t.CopyOutBytes(hostarch.Addr(rw.origData), rw.sentry)
		binary.LittleEndian.PutUint64(buf[rw.attrOff+8:rw.attrOff+16], rw.origData)
	}
	t.CopyOutBytes(argPtr, buf)

	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// classifyIoctl determines what DMA-relevant action this ioctl represents.
func (fd *uverbsFD) classifyIoctl(buf []byte, numAttrs int, objectID, methodID uint16) (action ioctlAction, writeCmdVal uint64) {
	// Modern path: direct object methods.
	switch objectID {
	case uverbsObjectMR:
		if methodID == uverbsMethodRegMR {
			return actionMRReg, 0
		}
		if methodID == uverbsMethodMRDestroy {
			return actionMRDereg, 0
		}
	case uverbsObjectCQ:
		if methodID == 0 {
			return actionCQDestroy, 0
		}
	case uverbsObjectQP:
		if methodID == 0 {
			return actionQPDestroy, 0
		}
	}

	// Legacy path: INVOKE_WRITE on DEVICE object.
	if objectID == uverbsObjectDevice && methodID == uverbsMethodInvokeWrite {
		writeCmdVal = findInlineAttr(buf, numAttrs, uverbsAttrWriteCmd)
		switch writeCmdVal {
		case ibUserVerbsCmdRegMR:
			return actionMRReg, writeCmdVal
		case ibUserVerbsCmdDeregMR:
			return actionMRDereg, writeCmdVal
		case ibUserVerbsCmdCreateCQ:
			return actionCQCreate, writeCmdVal
		case ibUserVerbsCmdCreateQP:
			return actionQPCreate, writeCmdVal
		case ibUserVerbsCmdDestroyCQ:
			return actionCQDestroy, writeCmdVal
		case ibUserVerbsCmdDestroyQP:
			return actionQPDestroy, writeCmdVal
		}
	}
	return actionNone, 0
}

// findInlineAttr finds an attr by ID where CopyIn failed (inline data) and
// returns its data field value. Returns 0 if not found.
func findInlineAttr(buf []byte, numAttrs int, targetID uint16) uint64 {
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		if attrID == targetID {
			// Inline attrs have len=0 or small len with non-pointer data.
			// The data field is the value itself.
			_ = attrLen
			return binary.LittleEndian.Uint64(buf[off+8 : off+16])
		}
	}
	return 0
}

// findRewrite finds the rewrite entry for a given attr ID.
func findRewrite(buf []byte, numAttrs int, rewrites []attrRewrite, targetID uint16) *attrRewrite {
	for i := range rewrites {
		off := rewrites[i].attrOff
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == targetID {
			return &rewrites[i]
		}
	}
	return nil
}

// prepareMRReg detects the MR address in the ioctl and mirrors the sandbox
// pages into the sentry's address space. The address in the ioctl buffer is
// rewritten to the sentry-side mapping.
func (fd *uverbsFD) prepareMRReg(t *kernel.Task, buf []byte, numAttrs int, objectID uint16, rewrites []attrRewrite, writeCmdVal uint64) (*mirroredPages, error) {
	if objectID == uverbsObjectDevice {
		return fd.prepareMRRegInvokeWrite(t, buf, numAttrs, rewrites)
	}
	return fd.prepareMRRegModern(t, buf, numAttrs, rewrites)
}

// prepareMRRegInvokeWrite handles MR REG via the INVOKE_WRITE legacy path.
// The CORE_IN attr contains an ib_uverbs_reg_mr struct with start/length.
func (fd *uverbsFD) prepareMRRegInvokeWrite(t *kernel.Task, buf []byte, numAttrs int, rewrites []attrRewrite) (*mirroredPages, error) {
	rw := findRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
	if rw == nil {
		log.Warningf("rdmaproxy: MR REG INVOKE_WRITE but no CORE_IN attr found")
		return nil, nil
	}
	if len(rw.sentry) < regMROffHcaVA+8 {
		log.Warningf("rdmaproxy: MR REG CORE_IN too short: %d bytes", len(rw.sentry))
		return nil, nil
	}

	sandboxVA := binary.LittleEndian.Uint64(rw.sentry[regMROffStart : regMROffStart+8])
	length := binary.LittleEndian.Uint64(rw.sentry[regMROffLength : regMROffLength+8])

	log.Infof("rdmaproxy: MR REG (INVOKE_WRITE) sandbox_va=%#x length=%d", sandboxVA, length)

	if length == 0 {
		return nil, nil
	}

	mp, sentryVA, err := mirrorSandboxPages(t, sandboxVA, length)
	if err != nil {
		return nil, fmt.Errorf("mirrorSandboxPages: %w", err)
	}

	// Rewrite start to sentry address; keep hca_va as original sandbox VA
	// so RDMA work requests use the app's addresses.
	binary.LittleEndian.PutUint64(rw.sentry[regMROffStart:regMROffStart+8], uint64(sentryVA))
	log.Infof("rdmaproxy: MR REG rewrote start %#x → sentry %#x (hca_va stays %#x)",
		sandboxVA, sentryVA, binary.LittleEndian.Uint64(rw.sentry[regMROffHcaVA:regMROffHcaVA+8]))

	return mp, nil
}

// prepareMRRegModern handles MR REG via the modern UVERBS_METHOD_REG_MR path.
// The ADDR and LENGTH attrs carry the values.
func (fd *uverbsFD) prepareMRRegModern(t *kernel.Task, buf []byte, numAttrs int, rewrites []attrRewrite) (*mirroredPages, error) {
	addrRW := findRewrite(buf, numAttrs, rewrites, uverbsAttrRegMRAddr)
	lengthRW := findRewrite(buf, numAttrs, rewrites, uverbsAttrRegMRLength)
	if addrRW == nil || lengthRW == nil {
		// ADDR and LENGTH might be inline for small values.
		log.Warningf("rdmaproxy: MR REG (modern) ADDR or LENGTH attr not found as pointer")
		return nil, nil
	}
	if len(addrRW.sentry) < 8 || len(lengthRW.sentry) < 8 {
		return nil, nil
	}

	sandboxVA := binary.LittleEndian.Uint64(addrRW.sentry[0:8])
	length := binary.LittleEndian.Uint64(lengthRW.sentry[0:8])

	log.Infof("rdmaproxy: MR REG (modern) sandbox_va=%#x length=%d", sandboxVA, length)

	if length == 0 {
		return nil, nil
	}

	mp, sentryVA, err := mirrorSandboxPages(t, sandboxVA, length)
	if err != nil {
		return nil, fmt.Errorf("mirrorSandboxPages: %w", err)
	}

	// Rewrite ADDR to sentry address. IOVA attr (if present) stays as sandbox VA.
	binary.LittleEndian.PutUint64(addrRW.sentry[0:8], uint64(sentryVA))
	log.Infof("rdmaproxy: MR REG (modern) rewrote addr %#x → sentry %#x", sandboxVA, sentryVA)

	return mp, nil
}

// mirrorSandboxPages pins the sandbox pages backing [addr, addr+length) and
// maps them into the sentry's address space. Returns the mirrored pages and
// the sentry VA corresponding to the original sandbox address.
//
// Modeled on nvproxy's rmAllocOSDescriptor.
func mirrorSandboxPages(t *kernel.Task, addr, length uint64) (*mirroredPages, uintptr, error) {
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
	prs, err := t.MemoryManager().Pin(t, appAR, at, false /* ignorePermissions */)
	cu := cleanup.Make(func() { mm.Unpin(prs) })
	defer cu.Clean()
	if err != nil {
		return nil, 0, fmt.Errorf("mm.Pin(%#x, %d): %w", alignedStart, alignedLen, err)
	}

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

	mp := &mirroredPages{prs: prs}
	if mOwned {
		mp.m = m
		mp.len = uintptr(alignedLen)
	}
	cu.Release()

	// Adjust for page alignment offset.
	sentryVA := m + uintptr(addr-uint64(alignedStart))
	return mp, sentryVA, nil
}

// extractMRHandle reads the MR handle from the ioctl response after
// a successful MR REG.
func (fd *uverbsFD) extractMRHandle(buf []byte, numAttrs int, objectID uint16, rewrites []attrRewrite, writeCmdVal uint64) uint32 {
	if objectID == uverbsObjectDevice {
		// INVOKE_WRITE: response in CORE_OUT attr.
		rw := findRewrite(buf, numAttrs, rewrites, uverbsAttrCoreOut)
		if rw == nil || len(rw.sentry) < regMRRespOffHandle+4 {
			log.Warningf("rdmaproxy: MR REG success but no CORE_OUT to read handle")
			return 0
		}
		return binary.LittleEndian.Uint32(rw.sentry[regMRRespOffHandle : regMRRespOffHandle+4])
	}
	// Modern path: HANDLE attr (id=0) is an output IDR — the handle is
	// returned in the data field of the attr in the response buffer.
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == uverbsAttrRegMRHandle {
			return uint32(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		}
	}
	return 0
}

// extractDeregMRHandle reads the MR handle from a DEREG_MR ioctl.
func (fd *uverbsFD) extractDeregMRHandle(buf []byte, numAttrs int, objectID uint16, rewrites []attrRewrite, writeCmdVal uint64) uint32 {
	if objectID == uverbsObjectDevice {
		// INVOKE_WRITE: mr_handle in CORE_IN attr.
		rw := findRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
		if rw == nil || len(rw.sentry) < deregMROffHandle+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.sentry[deregMROffHandle : deregMROffHandle+4])
	}
	// Modern path: DESTROY_MR_HANDLE attr (id=0).
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == uverbsAttrDestroyMRHandle {
			return uint32(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		}
	}
	return 0
}

// prepareCQQPCreate mirrors the DMA buffers (buf_addr + db_addr) embedded in
// the mlx5 driver attribute of a CQ or QP CREATE ioctl. Uses FindVMARange to
// determine buffer sizes from the mmap region boundaries.
func (fd *uverbsFD) prepareCQQPCreate(t *kernel.Task, buf []byte, numAttrs int, rewrites []attrRewrite, action ioctlAction) (*pinnedDMABufs, error) {
	drv := findRewrite(buf, numAttrs, rewrites, mlx5DriverAttrIn)
	if drv == nil {
		log.Infof("rdmaproxy: CQ/QP CREATE but no driver attr 0x%x found", mlx5DriverAttrIn)
		return nil, nil
	}
	if len(drv.sentry) < driverAttrMinLen {
		log.Infof("rdmaproxy: CQ/QP CREATE driver attr too short: %d bytes", len(drv.sentry))
		return nil, nil
	}

	bufAddr := binary.LittleEndian.Uint64(drv.sentry[driverAttrBufAddr : driverAttrBufAddr+8])
	dbAddr := binary.LittleEndian.Uint64(drv.sentry[driverAttrDBAddr : driverAttrDBAddr+8])
	kind := "CQ"
	if action == actionQPCreate {
		kind = "QP"
	}
	log.Infof("rdmaproxy: %s CREATE buf_addr=%#x db_addr=%#x", kind, bufAddr, dbAddr)

	var bufs pinnedDMABufs
	var cu cleanup.Cleanup
	defer cu.Clean()

	if bufAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(bufAddr))
		if err != nil {
			return nil, fmt.Errorf("FindVMARange(buf %#x): %w", bufAddr, err)
		}
		length := uint64(vmaRange.End) - bufAddr
		mp, sentryVA, err := mirrorSandboxPages(t, bufAddr, length)
		if err != nil {
			return nil, fmt.Errorf("mirrorSandboxPages buf: %w", err)
		}
		bufs.buf = mp
		cu.Add(func() { mp.release(t) })
		binary.LittleEndian.PutUint64(drv.sentry[driverAttrBufAddr:driverAttrBufAddr+8], uint64(sentryVA))
		log.Infof("rdmaproxy: %s CREATE buf %#x → sentry %#x (len=%d)", kind, bufAddr, sentryVA, length)
	}

	if dbAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(dbAddr))
		if err != nil {
			return nil, fmt.Errorf("FindVMARange(db %#x): %w", dbAddr, err)
		}
		length := uint64(vmaRange.End) - dbAddr
		mp, sentryVA, err := mirrorSandboxPages(t, dbAddr, length)
		if err != nil {
			return nil, fmt.Errorf("mirrorSandboxPages db: %w", err)
		}
		bufs.db = mp
		cu.Add(func() { mp.release(t) })
		binary.LittleEndian.PutUint64(drv.sentry[driverAttrDBAddr:driverAttrDBAddr+8], uint64(sentryVA))
		log.Infof("rdmaproxy: %s CREATE db %#x → sentry %#x (len=%d)", kind, dbAddr, sentryVA, length)
	}

	cu.Release()
	return &bufs, nil
}

// extractCQQPHandle reads the CQ or QP handle from the ioctl response after
// a successful CREATE (INVOKE_WRITE path: handle is first __u32 of CORE_OUT).
func (fd *uverbsFD) extractCQQPHandle(buf []byte, numAttrs int, objectID uint16, rewrites []attrRewrite) uint32 {
	if objectID == uverbsObjectDevice {
		rw := findRewrite(buf, numAttrs, rewrites, uverbsAttrCoreOut)
		if rw == nil || len(rw.sentry) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.sentry[0:4])
	}
	return 0
}

// extractCQQPDestroyHandle reads the CQ or QP handle from a DESTROY ioctl.
// INVOKE_WRITE path: handle is first __u32 of CORE_IN.
// Modern path: handle is in attr id=0 data field.
func (fd *uverbsFD) extractCQQPDestroyHandle(buf []byte, numAttrs int, objectID uint16, rewrites []attrRewrite) uint32 {
	if objectID == uverbsObjectDevice {
		rw := findRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
		if rw == nil || len(rw.sentry) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.sentry[0:4])
	}
	// Modern path: attr id=0 contains the handle.
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == 0 {
			return uint32(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		}
	}
	return 0
}

// Write implements vfs.FileDescriptionImpl.Write.
// This handles the legacy uverbs write() command interface where rdma-core
// sends commands like ALLOC_PD, REG_MR, DEREG_MR via write() on the fd.
func (fd *uverbsFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.EINVAL
	}

	size := src.NumBytes()
	if size < 8 {
		return 0, linuxerr.EINVAL
	}

	data := make([]byte, size)
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}

	rawCmd := binary.LittleEndian.Uint32(data[0:4])
	cmdBase := rawCmd & 0x7FFFFFFF
	isExtended := rawCmd&0x80000000 != 0
	inWords := binary.LittleEndian.Uint16(data[4:6])
	outWords := binary.LittleEndian.Uint16(data[6:8])

	log.Infof("rdmaproxy: Write cmd=%d extended=%v in_words=%d out_words=%d len=%d",
		cmdBase, isExtended, inWords, outWords, size)

	// Response pointer is always at byte offset 8 (first field of the
	// command-specific struct for non-extended, or the ex_hdr for extended).
	// Rewrite it to a sentry-side buffer so the host kernel's copy_to_user
	// writes into our address space rather than the sandbox.
	var origResp uint64
	var respBuf []byte
	if outWords > 0 && size >= 16 {
		origResp = binary.LittleEndian.Uint64(data[8:16])
		respLen := int(outWords) * 4
		respBuf = make([]byte, respLen)
		binary.LittleEndian.PutUint64(data[8:16],
			uint64(uintptr(unsafe.Pointer(&respBuf[0]))))
		log.Infof("rdmaproxy: Write cmd=%d resp rewrite %#x → sentry (%d bytes)",
			cmdBase, origResp, respLen)
	}

	// Mirror DMA pages for commands that need sentry-side pinning.
	var mrMirror *mirroredPages
	var cqqpMirror *pinnedDMABufs
	var cu cleanup.Cleanup
	defer cu.Clean()

	if !isExtended {
		switch cmdBase {
		case ibUserVerbsCmdRegMR:
			// Non-extended ib_uverbs_reg_mr layout after 8-byte cmd_hdr:
			//   +0: response (8)  +8: start (8)  +16: length (8)  +24: hca_va (8)
			const startOff, lengthOff, hcaVAOff = 16, 24, 32
			if size >= hcaVAOff+8 {
				sva := binary.LittleEndian.Uint64(data[startOff : startOff+8])
				length := binary.LittleEndian.Uint64(data[lengthOff : lengthOff+8])
				log.Infof("rdmaproxy: Write REG_MR va=%#x len=%d", sva, length)

				if length > 0 {
					mp, sentryVA, err := mirrorSandboxPages(t, sva, length)
					if err != nil {
						log.Warningf("rdmaproxy: Write REG_MR mirrorSandboxPages: %v", err)
						return 0, err
					}
					mrMirror = mp
					cu = cleanup.Make(func() { mp.release(t) })
					binary.LittleEndian.PutUint64(data[startOff:startOff+8], uint64(sentryVA))
					log.Infof("rdmaproxy: Write REG_MR rewrite start %#x → sentry %#x (hca_va=%#x)",
						sva, sentryVA,
						binary.LittleEndian.Uint64(data[hcaVAOff:hcaVAOff+8]))
				}
			}

		case ibUserVerbsCmdCreateCQ, ibUserVerbsCmdCreateQP:
			cqqpMirror = fd.prepareLegacyCQQPCreate(t, data, cmdBase)
			if cqqpMirror != nil {
				cu = cleanup.Make(func() { cqqpMirror.release(t) })
			}
		}
	}

	// Forward write to host fd.
	n, _, errno := unix.RawSyscall(unix.SYS_WRITE,
		uintptr(fd.hostFD),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size))
	if errno != 0 {
		log.Warningf("rdmaproxy: Write to host: n=%d errno=%d (%v)", n, errno, errno)
		return 0, errno
	}
	log.Infof("rdmaproxy: Write to host returned %d OK (cmd=%d)", n, cmdBase)

	// Copy response back to sandbox.
	if respBuf != nil && origResp != 0 {
		if _, err := t.CopyOutBytes(hostarch.Addr(origResp), respBuf); err != nil {
			log.Warningf("rdmaproxy: Write response CopyOut to %#x: %v", origResp, err)
		}
		binary.LittleEndian.PutUint64(data[8:16], origResp)
	}

	// Post-write tracking for successful operations.
	if errno == 0 && !isExtended {
		switch cmdBase {
		case ibUserVerbsCmdRegMR:
			if mrMirror != nil && respBuf != nil && len(respBuf) >= 4 {
				mrHandle := binary.LittleEndian.Uint32(respBuf[0:4])
				fd.mu.Lock()
				if fd.pinnedMRs == nil {
					fd.pinnedMRs = make(map[uint32]*mirroredPages)
				}
				fd.pinnedMRs[mrHandle] = mrMirror
				fd.mu.Unlock()
				cu.Release()
				log.Infof("rdmaproxy: Write REG_MR pinned handle=%d (%d ranges)", mrHandle, len(mrMirror.prs))
			}

		case ibUserVerbsCmdDeregMR:
			if size >= 12 {
				mrHandle := binary.LittleEndian.Uint32(data[8:12])
				fd.mu.Lock()
				if mp, ok := fd.pinnedMRs[mrHandle]; ok {
					delete(fd.pinnedMRs, mrHandle)
					fd.mu.Unlock()
					mp.release(t)
					log.Infof("rdmaproxy: Write DEREG_MR unpinned handle=%d", mrHandle)
				} else {
					fd.mu.Unlock()
				}
			}

		case ibUserVerbsCmdCreateCQ:
			if cqqpMirror != nil && respBuf != nil && len(respBuf) >= 4 {
				handle := binary.LittleEndian.Uint32(respBuf[0:4])
				fd.mu.Lock()
				if fd.pinnedCQs == nil {
					fd.pinnedCQs = make(map[uint32]*pinnedDMABufs)
				}
				fd.pinnedCQs[handle] = cqqpMirror
				fd.mu.Unlock()
				cu.Release()
				log.Infof("rdmaproxy: Write CREATE_CQ pinned handle=%d", handle)
			}

		case ibUserVerbsCmdCreateQP:
			if cqqpMirror != nil && respBuf != nil && len(respBuf) >= 4 {
				handle := binary.LittleEndian.Uint32(respBuf[0:4])
				fd.mu.Lock()
				if fd.pinnedQPs == nil {
					fd.pinnedQPs = make(map[uint32]*pinnedDMABufs)
				}
				fd.pinnedQPs[handle] = cqqpMirror
				fd.mu.Unlock()
				cu.Release()
				log.Infof("rdmaproxy: Write CREATE_QP pinned handle=%d", handle)
			}

		case ibUserVerbsCmdDestroyCQ:
			if size >= 12 {
				handle := binary.LittleEndian.Uint32(data[8:12])
				fd.mu.Lock()
				if p, ok := fd.pinnedCQs[handle]; ok {
					delete(fd.pinnedCQs, handle)
					fd.mu.Unlock()
					p.release(t)
					log.Infof("rdmaproxy: Write DESTROY_CQ unpinned handle=%d", handle)
				} else {
					fd.mu.Unlock()
				}
			}

		case ibUserVerbsCmdDestroyQP:
			if size >= 12 {
				handle := binary.LittleEndian.Uint32(data[8:12])
				fd.mu.Lock()
				if p, ok := fd.pinnedQPs[handle]; ok {
					delete(fd.pinnedQPs, handle)
					fd.mu.Unlock()
					p.release(t)
					log.Infof("rdmaproxy: Write DESTROY_QP unpinned handle=%d", handle)
				} else {
					fd.mu.Unlock()
				}
			}
		}
	}

	return int64(n), nil
}

// prepareLegacyCQQPCreate handles CQ/QP CREATE via the legacy write() path.
// The driver data (buf_addr + db_addr) is appended after the core struct in
// the write buffer. Layout: [cmd_hdr (8)] [core_struct] [driver_data...].
func (fd *uverbsFD) prepareLegacyCQQPCreate(t *kernel.Task, data []byte, cmdBase uint32) *pinnedDMABufs {
	// Core struct sizes (after 8-byte cmd_hdr and 8-byte response field):
	//   CREATE_CQ: response(8) + user_handle(8) + cqe(4) + comp_vector(4) + comp_channel(4) + reserved(4) = 32
	//   CREATE_QP: response(8) + user_handle(8) + pd(4) + scq(4) + rcq(4) + srq(4) +
	//              max_send_wr(4) + max_recv_wr(4) + max_send_sge(4) + max_recv_sge(4) +
	//              max_inline(4) + sq_sig_all(1) + qp_type(1) + is_srq(1) + reserved(1) = 56
	var coreSize int
	var kind string
	switch cmdBase {
	case ibUserVerbsCmdCreateCQ:
		coreSize = 32
		kind = "CQ"
	case ibUserVerbsCmdCreateQP:
		coreSize = 56
		kind = "QP"
	default:
		return nil
	}

	drvOff := 8 + coreSize // cmd_hdr + core struct
	if int64(len(data)) < int64(drvOff)+int64(driverAttrMinLen) {
		log.Infof("rdmaproxy: Write CREATE_%s no driver data (data len=%d, need=%d)", kind, len(data), drvOff+driverAttrMinLen)
		return nil
	}

	bufAddr := binary.LittleEndian.Uint64(data[drvOff : drvOff+8])
	dbAddr := binary.LittleEndian.Uint64(data[drvOff+8 : drvOff+16])
	log.Infof("rdmaproxy: Write CREATE_%s buf_addr=%#x db_addr=%#x", kind, bufAddr, dbAddr)

	var bufs pinnedDMABufs
	var cu cleanup.Cleanup
	defer cu.Clean()

	if bufAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(bufAddr))
		if err != nil {
			log.Warningf("rdmaproxy: Write CREATE_%s FindVMARange(buf %#x): %v", kind, bufAddr, err)
			return nil
		}
		length := uint64(vmaRange.End) - bufAddr
		mp, sentryVA, err := mirrorSandboxPages(t, bufAddr, length)
		if err != nil {
			log.Warningf("rdmaproxy: Write CREATE_%s mirrorSandboxPages buf: %v", kind, err)
			return nil
		}
		bufs.buf = mp
		cu.Add(func() { mp.release(t) })
		binary.LittleEndian.PutUint64(data[drvOff:drvOff+8], uint64(sentryVA))
		log.Infof("rdmaproxy: Write CREATE_%s buf %#x → sentry %#x (len=%d)", kind, bufAddr, sentryVA, length)
	}

	if dbAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(dbAddr))
		if err != nil {
			log.Warningf("rdmaproxy: Write CREATE_%s FindVMARange(db %#x): %v", kind, dbAddr, err)
			return nil
		}
		length := uint64(vmaRange.End) - dbAddr
		mp, sentryVA, err := mirrorSandboxPages(t, dbAddr, length)
		if err != nil {
			log.Warningf("rdmaproxy: Write CREATE_%s mirrorSandboxPages db: %v", kind, err)
			return nil
		}
		bufs.db = mp
		cu.Add(func() { mp.release(t) })
		binary.LittleEndian.PutUint64(data[drvOff+8:drvOff+16], uint64(sentryVA))
		log.Infof("rdmaproxy: Write CREATE_%s db %#x → sentry %#x (len=%d)", kind, dbAddr, sentryVA, length)
	}

	cu.Release()
	return &bufs
}

// Read implements vfs.FileDescriptionImpl.Read.
// Forwards reads to the host fd (used for async event notifications).
func (fd *uverbsFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	buf := make([]byte, dst.NumBytes())
	n, _, errno := unix.RawSyscall(unix.SYS_READ,
		uintptr(fd.hostFD),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)))
	if errno != 0 {
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return 0, linuxerr.ErrWouldBlock
		}
		return 0, errno
	}
	if n == 0 {
		return 0, nil
	}
	written, err := dst.CopyOut(ctx, buf[:n])
	return int64(written), err
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *uverbsFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	log.Infof("rdmaproxy: mmap hostFD=%d len=%d offset=0x%x perms=%v private=%v",
		fd.hostFD, opts.Length, opts.Offset, opts.Perms, opts.Private)
	err := vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts)
	if err != nil {
		log.Warningf("rdmaproxy: mmap hostFD=%d: %v", fd.hostFD, err)
	}
	return err
}

// Translate implements memmap.Mappable.Translate.
func (fd *uverbsFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{
		{
			Source: optional,
			File:   &fd.memmapFile,
			Offset: optional.Start,
			Perms:  hostarch.AnyAccess,
		},
	}, nil
}
