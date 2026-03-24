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
	ibUserVerbsCmdRegMR   = 9
	ibUserVerbsCmdDeregMR = 13
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

	// Detect MR REG and pin sandbox pages before forwarding.
	var mrMirror *mirroredPages
	var mrCleanup cleanup.Cleanup
	defer mrCleanup.Clean()
	isMRReg, isMRDereg, writeCmdVal := fd.classifyIoctl(buf, int(numAttrs), objectID, methodID)

	if isMRReg {
		var err error
		mrMirror, err = fd.prepareMRReg(t, buf, int(numAttrs), objectID, rewrites, writeCmdVal)
		if err != nil {
			log.Warningf("rdmaproxy: MR REG page mirroring: %v", err)
			return 0, err
		}
		if mrMirror != nil {
			mrCleanup = cleanup.Make(func() {
				mrMirror.release(t)
			})
		}
	}

	log.Infof("rdmaproxy: forwarding ioctl to host (hostFD=%d, %d rewrites, mrReg=%v)", fd.hostFD, len(rewrites), isMRReg)

	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL,
		uintptr(fd.hostFD), uintptr(rdmaVerbsIoctl),
		uintptr(unsafe.Pointer(&buf[0])))

	if errno != 0 {
		log.Infof("rdmaproxy: host ioctl returned n=%d errno=%d (%v)", n, errno, errno)
	} else {
		log.Infof("rdmaproxy: host ioctl returned n=%d OK", n)
	}

	// On MR REG success, track the mirror keyed by MR handle.
	if errno == 0 && isMRReg && mrMirror != nil {
		mrHandle := fd.extractMRHandle(buf, int(numAttrs), objectID, rewrites, writeCmdVal)
		if mrHandle != 0 {
			fd.mu.Lock()
			if fd.pinnedMRs == nil {
				fd.pinnedMRs = make(map[uint32]*mirroredPages)
			}
			fd.pinnedMRs[mrHandle] = mrMirror
			fd.mu.Unlock()
			mrCleanup.Release()
			log.Infof("rdmaproxy: pinned MR handle=%d (%d ranges)", mrHandle, len(mrMirror.prs))
		}
	}

	// On MR DEREG success, release the pinned pages.
	if errno == 0 && isMRDereg {
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

// classifyIoctl determines if this ioctl is a MR REG or MR DEREG.
func (fd *uverbsFD) classifyIoctl(buf []byte, numAttrs int, objectID, methodID uint16) (isMRReg, isMRDereg bool, writeCmdVal uint64) {
	// Modern path: direct MR object methods.
	if objectID == uverbsObjectMR {
		if methodID == uverbsMethodRegMR {
			return true, false, 0
		}
		if methodID == uverbsMethodMRDestroy {
			return false, true, 0
		}
		return false, false, 0
	}

	// Legacy path: INVOKE_WRITE on DEVICE object.
	if objectID == uverbsObjectDevice && methodID == uverbsMethodInvokeWrite {
		writeCmdVal = findInlineAttr(buf, numAttrs, uverbsAttrWriteCmd)
		if writeCmdVal == ibUserVerbsCmdRegMR {
			return true, false, writeCmdVal
		}
		if writeCmdVal == ibUserVerbsCmdDeregMR {
			return false, true, writeCmdVal
		}
	}
	return false, false, 0
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
