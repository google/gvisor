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
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ioctlBufPool reuses ioctl buffers to avoid per-call heap allocations.
var ioctlBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, hostarch.PageSize)
		return &b
	},
}

// readBufPool reuses small per-read buffers for async event delivery on
// uverbsFD/asyncEventFD.Read. Async event records are small (~16B for
// struct ib_uverbs_async_event_desc); a 4 KiB buffer covers any practical
// read length and avoids heap allocation in the common case.
var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, hostarch.PageSize)
		return &b
	},
}

// borrowReadBuf returns a buffer of length n. If n fits in the pooled size,
// the returned slice aliases a pooled []byte and the caller must invoke the
// returned release function to put it back. For larger reads we fall back
// to a heap allocation; release is a no-op.
func borrowReadBuf(n int) (buf []byte, release func()) {
	if n <= hostarch.PageSize {
		bp := readBufPool.Get().(*[]byte)
		return (*bp)[:n], func() { readBufPool.Put(bp) }
	}
	return make([]byte, n), func() {}
}

// ib_uverbs_ioctl_hdr layout constants.
const (
	rdmaIoctlMagic       = 0x1b
	ibUverbsIoctlHdrSize = 24
	ibUverbsAttrSize     = 16
)

// UVERBS object types (from include/uapi/rdma/ib_user_ioctl_cmds.h).
const (
	uverbsObjectDevice     = 0
	uverbsObjectCQ         = 3
	uverbsObjectQP         = 4
	uverbsObjectMR         = 7
	uverbsObjectAsyncEvent = 16
)

// UVERBS_OBJECT_DEVICE method IDs.
const (
	uverbsMethodInvokeWrite = 0
)

// UVERBS_OBJECT_MR method IDs.
const (
	uverbsMethodMRDestroy = 1
	uverbsMethodRegMR     = 5 // modern path
)

// UVERBS_OBJECT_QP method IDs.
//
// These come from enum uverbs_methods_qp in include/uapi/rdma/ib_user_ioctl_cmds.h
// and have been stable since the modern UVERBS ioctl ABI was introduced
// (kernel 4.20). DESTROY=1, MODIFY=2.
const (
	uverbsMethodQPDestroy = 1
	uverbsMethodQPModify  = 2
)

// UVERBS_OBJECT_ASYNC_EVENT method and attr IDs.
const (
	uverbsMethodAsyncEventAlloc = 0
	uverbsAttrAsyncEventAllocFD = 0
)

// CQ CREATE attr IDs (from include/uapi/rdma/ib_user_ioctl_cmds.h, enum
// uverbs_attrs_create_cq_cmd_attr_ids). UVERBS_ATTR_CREATE_CQ_HANDLE is the
// IDR (output) handle returned by a successful CREATE_CQ.
const (
	uverbsAttrCreateCQHandle  = 0
	uverbsAttrCreateCQEventFD = 7
)

// QP CREATE/DESTROY attr IDs (enum uverbs_attrs_create_qp_cmd_attr_ids).
// UVERBS_ATTR_CREATE_QP_HANDLE is the IDR (output) handle returned by a
// successful CREATE_QP. Both DESTROY_CQ_HANDLE and DESTROY_QP_HANDLE happen
// to be id 0 by ABI; we keep distinct constants to keep call sites
// self-documenting.
const (
	uverbsAttrCreateQPHandle  = 0
	uverbsAttrDestroyCQHandle = 0
	uverbsAttrDestroyQPHandle = 0
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
	ibUserVerbsCmdModifyQP  = 26
	ibUserVerbsCmdRegMR     = 9
	ibUserVerbsCmdDestroyCQ = 11
	ibUserVerbsCmdDeregMR   = 13
	ibUserVerbsCmdDestroyQP = 14
)

// IoctlAction classifies what an ioctl does for page-mirroring purposes.
// Exported so per-vendor Driver plug-ins can switch on the action passed
// to PrepareCQQPCreate.
type IoctlAction int

// IoctlAction values. Only ActionCQCreate and ActionQPCreate are passed to
// Driver.PrepareCQQPCreate; the rest are internal to the core dispatch
// loop and never reach plug-ins.
const (
	ActionNone IoctlAction = iota
	ActionMRReg
	ActionMRDereg
	ActionCQCreate
	ActionCQDestroy
	ActionQPCreate
	ActionQPDestroy
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
	uverbsAttrRegMRIova   = 3
	uverbsAttrRegMRAddr   = 4
	uverbsAttrRegMRLength = 5
)

// DESTROY_MR attr IDs.
const (
	uverbsAttrDestroyMRHandle = 0
)

// RDMA_VERBS_IOCTL = _IOWR(0x1b, 1, struct ib_uverbs_ioctl_hdr)
var rdmaVerbsIoctl = linux.IOWR(rdmaIoctlMagic, 1, ibUverbsIoctlHdrSize)

// AttrRewrite tracks a sandbox pointer that was rewritten to a sentry
// buffer. Exported so per-vendor Driver plug-ins can find their own
// driver-private attribute by ID inside the rewrites slice and read/write
// the sentry-side bytes that get forwarded to the host.
type AttrRewrite struct {
	// AttrOff is the byte offset of this attribute within the ioctl
	// header buffer, pointing at the 16-byte ib_uverbs_attr struct.
	AttrOff int
	// OrigData is the original sandbox pointer that was placed in the
	// attr's data field; the core restores it before copying out so the
	// sandbox sees its own pointer untouched.
	OrigData uint64
	// Sentry is the sentry-side buffer containing the attribute payload
	// after CopyIn. The host kernel reads/writes through this, and
	// drivers may rewrite individual fields in place (e.g. mlx5
	// buf_addr/db_addr).
	Sentry []byte
}

func taskLogFields(t *kernel.Task) string {
	if t == nil {
		return "tid=0 tgid_root=0"
	}
	return fmt.Sprintf("tid=%d tgid_root=%d", t.ThreadID(), t.TGIDInRoot())
}

func uverbsWriteCmdBase(w uint64) uint32 {
	return uint32(w & 0x7fffffff)
}

func formatMRSummary(t *kernel.Task, sandboxVA, length uint64, sentryVA uintptr, oldHCAVA, newHCAVA, oldIOVA, newIOVA uint64) string {
	relocated := sentryVA != uintptr(sandboxVA)
	return fmt.Sprintf("app=%#x-%#x len=%d sentry=%#x-%#x relocated=%t hca_va=%#x->%#x iova=%#x->%#x %s",
		sandboxVA, sandboxVA+length, length,
		sentryVA, sentryVA+uintptr(length), relocated,
		oldHCAVA, newHCAVA, oldIOVA, newIOVA, taskLogFields(t))
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
	// Single CopyIn: read first 8 bytes to get length, then full buffer.
	var lenBuf [8]byte
	if _, err := t.CopyInBytes(argPtr, lenBuf[:]); err != nil {
		log.Warningf("rdmaproxy: ioctl CopyIn length from %#x: %v", argPtr, err)
		return 0, err
	}
	length := binary.LittleEndian.Uint16(lenBuf[0:2])
	numAttrs := binary.LittleEndian.Uint16(lenBuf[6:8])

	expectedLen := uint16(ibUverbsIoctlHdrSize) + numAttrs*uint16(ibUverbsAttrSize)
	if length != expectedLen || length > hostarch.PageSize {
		log.Warningf("rdmaproxy: ioctl bad header: length=%d expected=%d (numAttrs=%d)",
			length, expectedLen, numAttrs)
		return 0, linuxerr.EINVAL
	}

	// Get buffer from pool to avoid per-ioctl allocation.
	bufPtr := ioctlBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:length]
	defer func() { ioctlBufPool.Put(bufPtr) }()

	if _, err := t.CopyInBytes(argPtr, buf); err != nil {
		log.Warningf("rdmaproxy: ioctl CopyIn full buffer (%d bytes) from %#x: %v",
			length, argPtr, err)
		return 0, err
	}

	objectID := binary.LittleEndian.Uint16(buf[2:4])
	methodID := binary.LittleEndian.Uint16(buf[4:6])

	// Walk attrs: probe each data field to determine if it's a sandbox
	// pointer (CopyIn succeeds) or inline data (CopyIn fails).
	// Pre-allocate rewrites on stack for the common case.
	var rewritesBuf [16]AttrRewrite
	rewrites := rewritesBuf[:0]
	// Stack arena for attribute data to avoid per-attr heap allocation.
	var attrArena [4096]byte
	arenaOff := 0

	for i := 0; i < int(numAttrs); i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		attrData := binary.LittleEndian.Uint64(buf[off+8 : off+16])

		if attrLen == 0 {
			continue
		}

		// Use stack arena when possible, fall back to heap for large attrs.
		var sb []byte
		if arenaOff+int(attrLen) <= len(attrArena) {
			sb = attrArena[arenaOff : arenaOff+int(attrLen)]
			arenaOff += int(attrLen)
		} else {
			sb = make([]byte, attrLen)
		}
		_, copyErr := t.CopyInBytes(hostarch.Addr(attrData), sb)
		if copyErr == nil {
			binary.LittleEndian.PutUint64(buf[off+8:off+16], attrDataPtr(sb))
			rewrites = append(rewrites, AttrRewrite{
				AttrOff:  off,
				OrigData: attrData,
				Sentry:   sb,
			})
		}
	}

	// Rewrite inline FD attrs that reference proxied async event FDs.
	// The application sees sentry FD numbers, but the host kernel needs
	// the original host FDs (e.g. CQ CREATE's comp channel attr).
	//
	// IMPORTANT: Only rewrite attrs with known FD attr IDs. Other inline
	// attrs carry kernel object handles (PD, CQ, QP handles) that have
	// small numeric values which could collide with sandbox FD numbers.
	// Rewriting those would corrupt the handles (e.g., PD handle 92 →
	// host FD 3480 → ibv_create_qp ENOENT).
	const (
		uverbsAttrCQCompChannel = 0x0007 // CQ CREATE comp channel FD
		uverbsAttrQPEventFD     = 0x000c // QP CREATE event FD
	)
	for i := 0; i < int(numAttrs); i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		attrLen := binary.LittleEndian.Uint16(buf[off+2 : off+4])
		if attrLen != 0 {
			continue
		}
		if attrID != uverbsAttrCQCompChannel && attrID != uverbsAttrQPEventFD {
			continue
		}
		sentryVal := int32(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		if sentryVal <= 0 {
			continue
		}
		file, _ := t.FDTable().Get(sentryVal)
		if file == nil {
			continue
		}
		if afd, ok := file.Impl().(*asyncEventFD); ok {
			binary.LittleEndian.PutUint64(buf[off+8:off+16], uint64(afd.hostFD))
		}
		file.DecRef(t)
	}

	// Classify and prepare DMA page mirroring before forwarding.
	action, writeCmdVal := fd.classifyIoctl(buf, int(numAttrs), objectID, methodID)
	// QP MODIFY needs the host netns for RoCE GID-to-netdev resolution.
	// Match it precisely on (objectID, methodID) — UVERBS_METHOD_QP_MODIFY
	// is methodID 2 on the modern ioctl path. On the legacy INVOKE_WRITE
	// path the same op is encoded as IB_USER_VERBS_CMD_MODIFY_QP (cmd 26)
	// in the WRITE_CMD attr.
	isQPModify := (objectID == uverbsObjectQP && methodID == uverbsMethodQPModify) ||
		(objectID == uverbsObjectDevice &&
			methodID == uverbsMethodInvokeWrite &&
			uverbsWriteCmdBase(writeCmdVal) == ibUserVerbsCmdModifyQP)

	var mrMirror *MirroredPages
	var cqqpMirror *PinnedDMABufs
	var dmaCleanup cleanup.Cleanup
	defer dmaCleanup.Clean()
	// asyncFDCleanup is armed if proxyAsyncEventFD installs an FD. It
	// fires on any error path between FD install and successful CopyOut
	// of the response back to the sandbox (see proxyAsyncEventFD comment).
	var asyncFDCleanup cleanup.Cleanup

	switch action {
	case ActionMRReg:
		var err error
		mrMirror, err = fd.prepareMRReg(t, buf, int(numAttrs), objectID, rewrites, writeCmdVal)
		if err != nil {
			log.Warningf("rdmaproxy: MR REG page mirroring: %v", err)
			return 0, linuxerr.ENOMEM
		}
		if mrMirror != nil {
			dmaCleanup = cleanup.Make(func() { mrMirror.Release(t) })
		}

	case ActionCQCreate, ActionQPCreate:
		if fd.driver == nil {
			// No driver attached — DMA buffer mirroring depends on the
			// vendor-specific driver-private attribute layout. Forward
			// the ioctl as-is; the host will fail or work depending on
			// whether buf_addr/db_addr resolve in the sentry's address
			// space (typically not).
			log.Warningf("rdmaproxy: CQ/QP CREATE on uverbsFD with no driver attached - cannot mirror DMA buffers")
			break
		}
		var err error
		cqqpMirror, err = fd.driver.PrepareCQQPCreate(t, buf, int(numAttrs), rewrites, action)
		if err != nil {
			log.Warningf("rdmaproxy: CQ/QP CREATE page mirroring (driver=%s): %v", fd.driver.Name(), err)
			return 0, linuxerr.ENOMEM
		}
		if cqqpMirror != nil {
			dmaCleanup = cleanup.Make(func() { cqqpMirror.Release(t) })
		}
	}

	if isQPModify && log.IsLogging(log.Debug) {
		log.Debugf("rdmaproxy: forwarding MODIFY_QP obj=0x%04x method=%d write_cmd=%d hostFD=%d %s",
			objectID, methodID, uverbsWriteCmdBase(writeCmdVal), fd.hostFD, taskLogFields(t))
	}
	n, errno := invokeUverbsIoctl(fd.hostFD, buf)
	if isQPModify && log.IsLogging(log.Debug) {
		log.Debugf("rdmaproxy: MODIFY_QP returned n=%d errno=%d hostFD=%d %s",
			n, errno, fd.hostFD, taskLogFields(t))
	}

	if errno == unix.EFAULT {
		// Extract the sentry VA that was passed to the host from the ioctl buffer.
		var sentryVA, mrLen uint64
		if action == ActionMRReg {
			if rw := FindRewrite(buf, int(numAttrs), rewrites, uverbsAttrCoreIn); rw != nil && len(rw.Sentry) >= regMROffLength+8 {
				sentryVA = binary.LittleEndian.Uint64(rw.Sentry[regMROffStart : regMROffStart+8])
				mrLen = binary.LittleEndian.Uint64(rw.Sentry[regMROffLength : regMROffLength+8])
			}
		}
		tgid := int32(t.TGIDInRoot())
		log.Warningf("rdmaproxy: EFAULT from host ioctl obj=0x%04x method=%d action=%d hostFD=%d sentryVA=%#x mrLen=%d tgid=%d (%s)",
			objectID, methodID, action, fd.hostFD, sentryVA, mrLen, tgid, taskLogFields(t))
	}

	// Post-ioctl tracking for successful operations.
	if errno == 0 {
		switch action {
		case ActionMRReg:
			if mrMirror != nil {
				mrHandle := fd.extractMRHandle(buf, int(numAttrs), objectID, rewrites, writeCmdVal)
				if mrHandle != 0 {
					fd.pinned.addMR(mrHandle, mrMirror)
					dmaCleanup.Release()
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: pinned MR handle=%d (%d ranges) %s", mrHandle, len(mrMirror.prs), mrMirror.mrSummary)
					}
				}
			}

		case ActionMRDereg:
			mrHandle := fd.extractDeregMRHandle(buf, int(numAttrs), objectID, rewrites, writeCmdVal)
			if mrHandle != 0 {
				if mp := fd.pinned.takeMR(mrHandle); mp != nil {
					mp.Release(t)
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: unpinned MR handle=%d", mrHandle)
					}
				}
			}

		case ActionCQCreate:
			if cqqpMirror != nil {
				handle := fd.extractCQQPHandle(buf, int(numAttrs), objectID, rewrites, action)
				if handle != 0 {
					fd.pinned.addCQ(handle, cqqpMirror)
					dmaCleanup.Release()
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: pinned CQ handle=%d", handle)
					}
				}
			}

		case ActionQPCreate:
			if cqqpMirror != nil {
				handle := fd.extractCQQPHandle(buf, int(numAttrs), objectID, rewrites, action)
				if handle != 0 {
					fd.pinned.addQP(handle, cqqpMirror)
					dmaCleanup.Release()
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: pinned QP handle=%d", handle)
					}
				}
			}

		case ActionCQDestroy:
			handle := fd.extractCQQPDestroyHandle(buf, int(numAttrs), objectID, rewrites, action)
			if handle != 0 {
				if bufs := fd.pinned.takeCQ(handle); bufs != nil {
					bufs.Release(t)
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: unpinned CQ handle=%d", handle)
					}
				}
			}

		case ActionQPDestroy:
			handle := fd.extractCQQPDestroyHandle(buf, int(numAttrs), objectID, rewrites, action)
			if handle != 0 {
				if bufs := fd.pinned.takeQP(handle); bufs != nil {
					bufs.Release(t)
					if log.IsLogging(log.Debug) {
						log.Debugf("rdmaproxy: unpinned QP handle=%d", handle)
					}
				}
			}
		}

		// Proxy the async event FD returned by ASYNC_EVENT_ALLOC.
		// The kernel created this FD in the sentry's host process;
		// we must wrap it so the sandbox can read() async events.
		// The FD is installed into the task's FD table here, but the
		// sandbox only learns its number from the final CopyOut below;
		// if that copy fails we'd leak a referenceable FD, so undo is
		// armed and only released after a successful argPtr copy.
		if objectID == uverbsObjectAsyncEvent && methodID == uverbsMethodAsyncEventAlloc {
			if sentryFD, undo, err := fd.proxyAsyncEventFD(t, buf, int(numAttrs)); err != nil {
				log.Warningf("rdmaproxy: async event FD proxy: %v", err)
			} else if sentryFD >= 0 {
				log.Infof("rdmaproxy: installed async event FD → sandbox fd %d", sentryFD)
				asyncFDCleanup = cleanup.Make(undo)
				defer asyncFDCleanup.Clean()
			}
		}
	}

	// Copy output data back and restore original pointers.
	for _, rw := range rewrites {
		t.CopyOutBytes(hostarch.Addr(rw.OrigData), rw.Sentry)
		binary.LittleEndian.PutUint64(buf[rw.AttrOff+8:rw.AttrOff+16], rw.OrigData)
	}
	if _, copyErr := t.CopyOutBytes(argPtr, buf); copyErr != nil {
		// argPtr CopyOut failed — abandon any async event FD we just
		// installed (the sandbox never received the FD number).
		return 0, copyErr
	}
	asyncFDCleanup.Release()

	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// classifyIoctl determines what DMA-relevant action this ioctl represents.
func (fd *uverbsFD) classifyIoctl(buf []byte, numAttrs int, objectID, methodID uint16) (action IoctlAction, writeCmdVal uint64) {
	// Modern path: direct object methods.
	switch objectID {
	case uverbsObjectMR:
		if methodID == uverbsMethodRegMR {
			return ActionMRReg, 0
		}
		if methodID == uverbsMethodMRDestroy {
			return ActionMRDereg, 0
		}
	case uverbsObjectCQ:
		// Method IDs vary across kernel versions, so detect CREATE vs
		// DESTROY by asking the driver if it sees its own driver-private
		// input attribute. With no driver attached, conservatively treat
		// every CQ ioctl as a DESTROY (the page-mirror for CREATE only
		// fires through the driver path; this avoids spurious
		// ActionCQDestroy releases of mirrors we never registered).
		if fd.driver != nil && fd.driver.HasDriverCreateAttr(buf, numAttrs) {
			return ActionCQCreate, 0
		}
		return ActionCQDestroy, 0
	case uverbsObjectQP:
		if fd.driver != nil && fd.driver.HasDriverCreateAttr(buf, numAttrs) {
			return ActionQPCreate, 0
		}
		// Distinguish DESTROY (method=1) from MODIFY (method=2+).
		// Returning ActionNone for MODIFY prevents the ActionQPDestroy
		// post-ioctl page-release from firing incorrectly on MODIFY_QP.
		if methodID == uverbsMethodQPDestroy {
			return ActionQPDestroy, 0
		}
		return ActionNone, 0 // MODIFY_QP or unknown QP op
	}

	// Legacy path: INVOKE_WRITE on DEVICE object.
	if objectID == uverbsObjectDevice && methodID == uverbsMethodInvokeWrite {
		writeCmdVal = findInlineAttr(buf, numAttrs, uverbsAttrWriteCmd)
		switch writeCmdVal {
		case ibUserVerbsCmdRegMR:
			return ActionMRReg, writeCmdVal
		case ibUserVerbsCmdDeregMR:
			return ActionMRDereg, writeCmdVal
		case ibUserVerbsCmdCreateCQ:
			return ActionCQCreate, writeCmdVal
		case ibUserVerbsCmdCreateQP:
			return ActionQPCreate, writeCmdVal
		case ibUserVerbsCmdDestroyCQ:
			return ActionCQDestroy, writeCmdVal
		case ibUserVerbsCmdDestroyQP:
			return ActionQPDestroy, writeCmdVal
		default:
			return ActionNone, writeCmdVal
		}
	}
	return ActionNone, 0
}

// HasAttrID returns true if any attr in the ioctl buffer has the given ID.
// Exported so per-vendor Driver.HasDriverCreateAttr implementations can
// scan for their driver-private attribute without duplicating the
// attribute-walking loop.
func HasAttrID(buf []byte, numAttrs int, targetID uint16) bool {
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == targetID {
			return true
		}
	}
	return false
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

// FindRewrite finds the rewrite entry for a given attr ID, or nil if no
// rewrite was performed for that ID. Exported so per-vendor Driver
// plug-ins can locate their driver-private input attribute and rewrite
// the embedded sandbox addresses.
func FindRewrite(buf []byte, numAttrs int, rewrites []AttrRewrite, targetID uint16) *AttrRewrite {
	for i := range rewrites {
		off := rewrites[i].AttrOff
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
func (fd *uverbsFD) prepareMRReg(t *kernel.Task, buf []byte, numAttrs int, objectID uint16, rewrites []AttrRewrite, writeCmdVal uint64) (*MirroredPages, error) {
	if objectID == uverbsObjectDevice {
		return fd.prepareMRRegInvokeWrite(t, buf, numAttrs, rewrites)
	}
	return fd.prepareMRRegModern(t, buf, numAttrs, rewrites)
}

// prepareMRRegInvokeWrite handles MR REG via the INVOKE_WRITE legacy path.
// The CORE_IN attr contains an ib_uverbs_reg_mr struct with start/length.
func (fd *uverbsFD) prepareMRRegInvokeWrite(t *kernel.Task, buf []byte, numAttrs int, rewrites []AttrRewrite) (*MirroredPages, error) {
	rw := FindRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
	if rw == nil {
		log.Warningf("rdmaproxy: MR REG INVOKE_WRITE but no CORE_IN attr found")
		return nil, nil
	}
	if len(rw.Sentry) < regMROffHcaVA+8 {
		log.Warningf("rdmaproxy: MR REG CORE_IN too short: %d bytes", len(rw.Sentry))
		return nil, nil
	}

	sandboxVA := binary.LittleEndian.Uint64(rw.Sentry[regMROffStart : regMROffStart+8])
	length := binary.LittleEndian.Uint64(rw.Sentry[regMROffLength : regMROffLength+8])

	if length == 0 {
		return nil, nil
	}

	mp, sentryVA, err := MirrorSandboxPages(t, sandboxVA, length)
	if err != nil {
		return nil, fmt.Errorf("MirrorSandboxPages: %w", err)
	}

	oldHCAVA := binary.LittleEndian.Uint64(rw.Sentry[regMROffHcaVA : regMROffHcaVA+8])

	binary.LittleEndian.PutUint64(rw.Sentry[regMROffStart:regMROffStart+8], uint64(sentryVA))
	if mp != nil {
		mp.mrSummary = formatMRSummary(t, sandboxVA, length, sentryVA, oldHCAVA, oldHCAVA, 0, 0)
	}

	return mp, nil
}

// prepareMRRegModern handles MR REG via the modern UVERBS_METHOD_REG_MR path.
// The ADDR and LENGTH attrs carry the values.
func (fd *uverbsFD) prepareMRRegModern(t *kernel.Task, buf []byte, numAttrs int, rewrites []AttrRewrite) (*MirroredPages, error) {
	addrRW := FindRewrite(buf, numAttrs, rewrites, uverbsAttrRegMRAddr)
	lengthRW := FindRewrite(buf, numAttrs, rewrites, uverbsAttrRegMRLength)
	if addrRW == nil || lengthRW == nil {
		// ADDR and LENGTH might be inline for small values.
		// Try reading them as inline values from the raw buffer.
		addrInline := findInlineAttr(buf, numAttrs, uverbsAttrRegMRAddr)
		lengthInline := findInlineAttr(buf, numAttrs, uverbsAttrRegMRLength)
		log.Warningf("rdmaproxy: MR REG (modern) ADDR/LENGTH not rewritten (addrRW=%v lenRW=%v inline addr=%#x len=%d) — forwarding without mirroring",
			addrRW != nil, lengthRW != nil, addrInline, lengthInline)
		return nil, nil
	}
	if len(addrRW.Sentry) < 8 || len(lengthRW.Sentry) < 8 {
		return nil, nil
	}

	sandboxVA := binary.LittleEndian.Uint64(addrRW.Sentry[0:8])
	length := binary.LittleEndian.Uint64(lengthRW.Sentry[0:8])

	if length == 0 {
		return nil, nil
	}

	mp, sentryVA, err := MirrorSandboxPages(t, sandboxVA, length)
	if err != nil {
		return nil, fmt.Errorf("MirrorSandboxPages: %w", err)
	}

	binary.LittleEndian.PutUint64(addrRW.Sentry[0:8], uint64(sentryVA))
	if mp != nil {
		mp.mrSummary = formatMRSummary(t, sandboxVA, length, sentryVA, 0, 0, sandboxVA, sandboxVA)
	}

	return mp, nil
}

// extractMRHandle reads the MR handle from the ioctl response after
// a successful MR REG.
func (fd *uverbsFD) extractMRHandle(buf []byte, numAttrs int, objectID uint16, rewrites []AttrRewrite, writeCmdVal uint64) uint32 {
	if objectID == uverbsObjectDevice {
		// INVOKE_WRITE: response in CORE_OUT attr.
		rw := FindRewrite(buf, numAttrs, rewrites, uverbsAttrCoreOut)
		if rw == nil || len(rw.Sentry) < regMRRespOffHandle+4 {
			log.Warningf("rdmaproxy: MR REG success but no CORE_OUT to read handle")
			return 0
		}
		return binary.LittleEndian.Uint32(rw.Sentry[regMRRespOffHandle : regMRRespOffHandle+4])
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
func (fd *uverbsFD) extractDeregMRHandle(buf []byte, numAttrs int, objectID uint16, rewrites []AttrRewrite, writeCmdVal uint64) uint32 {
	if objectID == uverbsObjectDevice {
		// INVOKE_WRITE: mr_handle in CORE_IN attr.
		rw := FindRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
		if rw == nil || len(rw.Sentry) < deregMROffHandle+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.Sentry[deregMROffHandle : deregMROffHandle+4])
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

// extractCQQPHandle reads the CQ or QP handle from the ioctl response after
// a successful CREATE. action picks the per-method handle attr ID — both
// happen to be 0 by ABI, but routing through named constants keeps the call
// site self-documenting and avoids relying on "first attr with ID 0".
func (fd *uverbsFD) extractCQQPHandle(buf []byte, numAttrs int, objectID uint16, rewrites []AttrRewrite, action IoctlAction) uint32 {
	if objectID == uverbsObjectDevice {
		// INVOKE_WRITE: handle is first __u32 of CORE_OUT for both CREATE_CQ
		// (struct ib_uverbs_create_cq_resp.cq_handle) and CREATE_QP (struct
		// ib_uverbs_create_qp_resp.qp_handle).
		rw := FindRewrite(buf, numAttrs, rewrites, uverbsAttrCoreOut)
		if rw == nil || len(rw.Sentry) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.Sentry[0:4])
	}
	var attrID uint16
	switch action {
	case ActionCQCreate:
		attrID = uverbsAttrCreateCQHandle
	case ActionQPCreate:
		attrID = uverbsAttrCreateQPHandle
	default:
		return 0
	}
	return findOutputHandle(buf, numAttrs, attrID)
}

// extractCQQPDestroyHandle reads the CQ or QP handle from a DESTROY ioctl.
// INVOKE_WRITE path: handle is first __u32 of CORE_IN.
// Modern path: per-method DESTROY handle attr (both happen to be id 0).
func (fd *uverbsFD) extractCQQPDestroyHandle(buf []byte, numAttrs int, objectID uint16, rewrites []AttrRewrite, action IoctlAction) uint32 {
	if objectID == uverbsObjectDevice {
		rw := FindRewrite(buf, numAttrs, rewrites, uverbsAttrCoreIn)
		if rw == nil || len(rw.Sentry) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(rw.Sentry[0:4])
	}
	var attrID uint16
	switch action {
	case ActionCQDestroy:
		attrID = uverbsAttrDestroyCQHandle
	case ActionQPDestroy:
		attrID = uverbsAttrDestroyQPHandle
	default:
		return 0
	}
	return findOutputHandle(buf, numAttrs, attrID)
}

// findOutputHandle returns the data field (truncated to uint32) of the first
// attr with the given ID. Used to extract IDR-output handles from CREATE
// responses and DESTROY inputs.
func findOutputHandle(buf []byte, numAttrs int, targetID uint16) uint32 {
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID == targetID {
			return uint32(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		}
	}
	return 0
}

// proxyAsyncEventFD extracts the host FD from a successful
// ASYNC_EVENT_ALLOC response, wraps it in a sentry FileDescription, installs
// it in the task's FD table, and rewrites the ioctl buffer so the sandbox
// receives the proxy FD number.
//
// Returns (sentryFD, undo, nil) on success. undo, when called, removes the
// sentry FD from the task's FD table; the caller MUST invoke undo if the
// final CopyOut to the sandbox argPtr fails (otherwise the sandbox would
// hold a referenceable FD it never sees the number for). On the success
// path the caller throws away undo.
func (fd *uverbsFD) proxyAsyncEventFD(t *kernel.Task, buf []byte, numAttrs int) (int32, func(), error) {
	for i := 0; i < numAttrs; i++ {
		off := ibUverbsIoctlHdrSize + i*ibUverbsAttrSize
		attrID := binary.LittleEndian.Uint16(buf[off : off+2])
		if attrID != uverbsAttrAsyncEventAllocFD {
			continue
		}
		hostFD := int(binary.LittleEndian.Uint64(buf[off+8 : off+16]))
		if hostFD < 0 {
			return -1, nil, fmt.Errorf("kernel returned invalid async event fd %d", hostFD)
		}
		sentryFD, err := newAsyncEventFD(t, hostFD)
		if err != nil {
			unix.Close(hostFD)
			return -1, nil, fmt.Errorf("newAsyncEventFD: %w", err)
		}
		// No global map needed — the FD rewrite loop now resolves
		// sandbox FDs through the task's FD table at ioctl time.
		binary.LittleEndian.PutUint64(buf[off+8:off+16], uint64(sentryFD))
		undo := func() {
			if file := t.FDTable().Remove(t, sentryFD); file != nil {
				file.DecRef(t)
			}
		}
		return sentryFD, undo, nil
	}
	return -1, nil, fmt.Errorf("ASYNC_EVENT_ALLOC response missing FD attr")
}

// Read implements vfs.FileDescriptionImpl.Read.
// Forwards reads to the host fd (used for async event notifications).
func (fd *uverbsFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	buf, release := borrowReadBuf(int(dst.NumBytes()))
	defer release()
	n, errno := readHostFDNonblocking(fd.hostFD, buf)
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

// Write rejects direct writes to /dev/infiniband/uverbs*. The legacy
// uverbs write() command interface is not implemented; modern rdma-core
// uses RDMA_VERBS_IOCTL exclusively. Logged at Debug level because some
// probes/diagnostics will speculatively try write(2) and we don't want
// to spam Warning on every probe.
func (fd *uverbsFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if log.IsLogging(log.Debug) {
		log.Debugf("rdmaproxy: direct write() on uverbs fd is unsupported size=%d hostFD=%d %s",
			src.NumBytes(), fd.hostFD, taskLogFields(kernel.TaskFromContext(ctx)))
	}
	return 0, linuxerr.EINVAL
}

// Read implements vfs.FileDescriptionImpl.Read for asyncEventFD.
// Uses fdnotifier to check readiness before reading, so we never
// issue a blocking read() syscall on the host FD.
func (fd *asyncEventFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if fdnotifier.NonBlockingPoll(fd.hostFD, waiter.ReadableEvents) == 0 {
		return 0, linuxerr.ErrWouldBlock
	}
	buf, release := borrowReadBuf(int(dst.NumBytes()))
	defer release()
	n, errno := readHostFDNonblocking(fd.hostFD, buf)
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
