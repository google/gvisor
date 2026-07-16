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
	"fmt"
	"runtime"

	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// maxNumAttrs bounds the attribute count. No modeled method carries more than
// ~20 attributes; the cap keeps a malicious header from driving large
// allocations and guarantees the whole request fits in a page.
const maxNumAttrs = 64

// xlat records one attribute the proxy rewrote in the forwarded request, so the
// original value can be restored (and any output copied back) after the call.
type xlat struct {
	// attr points into the request's attrs slice.
	attr *ib.UverbsAttr
	// orig is the original guest value of the data field, restored before the
	// buffer is copied back so the guest never observes a sentry pointer,
	// host fd, or relocated address.
	orig uint64
	// outBuf, when non-nil, is a sentry PTR_OUT staging buffer whose contents
	// are copied back to the guest pointer (orig) after a successful call.
	outBuf []byte
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *uverbsFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	argPtr := args[2].Pointer()

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("rdmaproxy: ioctl called without task context")
		return 0, linuxerr.EINVAL
	}

	if cmd != ib.RDMAVerbsIoctl {
		log.Warningf("rdmaproxy: unsupported ioctl cmd=%#x", cmd)
		return 0, linuxerr.ENOTTY
	}
	return fd.handleRDMAVerbsIoctl(t, argPtr)
}

// handleRDMAVerbsIoctl translates and forwards a single RDMA_VERBS_IOCTL
// request. The request is validated against the schema; every attribute is
// translated strictly by its declared type; DMA buffers are mirrored; the
// request is forwarded to the host uverbs FD; and outputs are copied back.
func (fd *uverbsFD) handleRDMAVerbsIoctl(t *kernel.Task, argPtr hostarch.Addr) (uintptr, error) {
	var hdr ib.UverbsIoctlHdr
	if _, err := hdr.CopyIn(t, argPtr); err != nil {
		return 0, err
	}

	// Validate length using int arithmetic to avoid the u16 overflow that
	// would let a large NumAttrs wrap back to a small "valid" length.
	if hdr.NumAttrs > maxNumAttrs {
		log.Warningf("rdmaproxy: too many attrs: %d (max %d)", hdr.NumAttrs, maxNumAttrs)
		return 0, linuxerr.EINVAL
	}
	expectedLen := int(ib.SizeofUverbsIoctlHdr) + int(hdr.NumAttrs)*int(ib.SizeofUverbsAttr)
	if int(hdr.Length) != expectedLen {
		log.Warningf("rdmaproxy: bad ioctl length=%d expected=%d (numAttrs=%d)", hdr.Length, expectedLen, hdr.NumAttrs)
		return 0, linuxerr.EINVAL
	}

	schema := lookupSchema(hdr.ObjectID, hdr.MethodID)
	if schema == nil {
		log.Warningf("rdmaproxy: unsupported ioctl object=%d method=%d", hdr.ObjectID, hdr.MethodID)
		return 0, linuxerr.EINVAL
	}

	attrsAddr := argPtr + hostarch.Addr(ib.SizeofUverbsIoctlHdr)
	attrs := make([]ib.UverbsAttr, hdr.NumAttrs)
	if _, err := ib.CopyUverbsAttrSliceIn(t, attrsAddr, attrs); err != nil {
		return 0, err
	}

	// staged maps a staged (len>8) attribute's ID to its sentry buffer: a
	// runtime.KeepAlive pins them across the syscall, and DMA handlers recover
	// a buffer by attr ID.
	staged := make(map[uint16][]byte)
	// xlats records every rewritten data field for restore / copy-back.
	var xlats []xlat

	// Translate each attribute strictly by its schema-declared type.
	for i := range attrs {
		a := &attrs[i]
		typ, ok := schema.Attrs[a.AttrID]
		if !ok {
			log.Warningf("rdmaproxy: unsupported attr id=%#x on object=%d method=%d", a.AttrID, hdr.ObjectID, hdr.MethodID)
			return 0, linuxerr.EINVAL
		}

		switch typ {
		case AttrPtrIn:
			// Inline when len<=8 (forward untouched); otherwise a guest
			// pointer whose contents are staged in the sentry.
			if a.Len > 8 {
				sb, err := fd.copyInPtr(t, a.Data, a.Len)
				if err != nil {
					return 0, err
				}
				xlats = append(xlats, xlat{attr: a, orig: a.Data})
				a.Data = sentryDataPtr(sb)
				staged[a.AttrID] = sb
			}

		case AttrPtrOut:
			// Always a guest pointer; stage an output buffer of the declared
			// length and copy it back after the call.
			if a.Len == 0 {
				// No output buffer: forward a null pointer rather than the
				// guest's raw data value, restored on copy-out.
				xlats = append(xlats, xlat{attr: a, orig: a.Data})
				a.Data = 0
				break
			}
			// Note that Len is uint16, so the slice allocation below is
			// bounded to 64 KiB.
			sb := make([]byte, a.Len)
			xlats = append(xlats, xlat{attr: a, orig: a.Data, outBuf: sb})
			a.Data = sentryDataPtr(sb)
			staged[a.AttrID] = sb

		case AttrInline:
			// Left in place for a method-specific handler; must be inline so
			// the handler reads the real value, not a staged sentry pointer.
			if a.Len > 8 {
				return 0, linuxerr.EINVAL
			}

		case AttrIdr:
			// Object handle: len must be 0, data passed through unchanged.
			// For UVERBS_ACCESS_NEW the kernel writes the fresh handle into
			// this field of the forwarded buffer; it reaches the guest via
			// the copy-out below.
			if a.Len != 0 {
				return 0, linuxerr.EINVAL
			}

		case AttrFdIn:
			if a.Len != 0 {
				return 0, linuxerr.EINVAL
			}
			hostFD, file, err := fd.translateInputFD(t, int32(a.Data))
			if err != nil {
				return 0, err
			}
			defer file.DecRef(t)
			xlats = append(xlats, xlat{attr: a, orig: a.Data})
			a.Data = uint64(uint32(hostFD))

		case AttrFdNew:
			// Output fd: the kernel installs a host fd in the sentry and
			// writes its number here; wrapped after a successful call.
			if a.Len != 0 {
				return 0, linuxerr.EINVAL
			}

		case AttrRawFd:
			if a.Len != 0 {
				return 0, linuxerr.EINVAL
			}
			// data_s64; negative means "no fd", forwarded unchanged.
			if int64(a.Data) >= 0 {
				hostFD, file, err := fd.translateHostBackedFD(t, int32(a.Data))
				if err != nil {
					return 0, err
				}
				defer file.DecRef(t)
				xlats = append(xlats, xlat{attr: a, orig: a.Data})
				a.Data = uint64(uint32(hostFD))
			}

		case AttrUnsupported:
			log.Warningf("rdmaproxy: unsupported attr id=%#x on object=%d method=%d", a.AttrID, hdr.ObjectID, hdr.MethodID)
			return 0, linuxerr.EINVAL

		default:
			log.Warningf("rdmaproxy: unsupported attr type %d for id=%#x on object=%d method=%d", typ, a.AttrID, hdr.ObjectID, hdr.MethodID)
			return 0, linuxerr.EINVAL
		}
	}

	// Method-specific DMA / fd pre-processing that operates on inline values
	// (which the generic loop leaves untouched).
	var mrMirror *MirroredPages
	var cqqpMirror *PinnedDMABufs
	var dmaCleanup cleanup.Cleanup
	defer dmaCleanup.Clean()

	switch schema.Dma {
	case DmaMRReg:
		mp, err := fd.prepareMRReg(t, attrs, &xlats)
		if err != nil {
			log.Warningf("rdmaproxy: REG_MR page mirroring: %v", err)
			return 0, err
		}
		if mp != nil {
			mrMirror = mp
			dmaCleanup.Add(func() { mp.Release(t) })
		}

	case DmaMRRegDMABuf:
		fdRelease, err := fd.prepareDMABufFD(t, attrs, &xlats)
		if err != nil {
			log.Warningf("rdmaproxy: REG_DMABUF_MR fd translation: %v", err)
			return 0, err
		}
		defer fdRelease()

	case DmaCQCreate, DmaQPCreate:
		mp, err := fd.prepareCreateDMA(t, staged)
		if err != nil {
			log.Warningf("rdmaproxy: CQ/QP CREATE page mirroring: %v", err)
			return 0, err
		}
		if mp != nil {
			cqqpMirror = mp
			dmaCleanup.Add(func() { mp.Release(t) })
		}

	case DmaInvokeWrite:
		// Legacy write-path REG_MR carries the guest MR address in its CORE_IN
		// blob; mirror it just like the modern REG_MR method. Other write
		// commands need no DMA handling and are forwarded opaquely.
		mp, err := fd.prepareInvokeWriteRegMR(t, attrs, staged)
		if err != nil {
			log.Warningf("rdmaproxy: INVOKE_WRITE REG_MR page mirroring: %v", err)
			return 0, err
		}
		if mp != nil {
			mrMirror = mp
			dmaCleanup.Add(func() { mp.Release(t) })
		}
	}

	// Serialize the header and translated attrs back into one contiguous
	// buffer, the layout the kernel expects, and forward it. RDMA_VERBS_IOCTL
	// is _IOWR: the kernel writes outputs (new IDR handles, fds) back into the
	// attr data fields, so the attrs are re-unmarshaled from buf after the call.
	buf := make([]byte, hdr.Length)
	ib.MarshalUnsafeUverbsAttrSlice(attrs, hdr.MarshalUnsafe(buf))
	n, errno := invokeUverbsIoctl(fd.hostFD, buf)
	// Keep the staged buffers alive until the host syscall returns: their
	// addresses were laundered through a uintptr into buf, so the GC cannot
	// otherwise see that the in-flight ioctl still references them.
	runtime.KeepAlive(staged)
	ib.UnmarshalUnsafeUverbsAttrSlice(attrs, buf[ib.SizeofUverbsIoctlHdr:])

	// asyncFDCleanup is armed if an async-event fd was installed below; it
	// fires if the final copy-out fails (the guest never learned the number).
	var asyncFDCleanup cleanup.Cleanup
	defer asyncFDCleanup.Clean()

	if errno == 0 {
		handleAttr := findAttr(attrs, schema.HandleAttr)
		haveHandle := handleAttr != nil
		var handle uint32
		if haveHandle {
			// uverbs object handles are u32 (ib_uobject.id / __u32 mr_handle),
			// zero-extended into the 8-byte data field.
			handle = uint32(handleAttr.Data)
		}
		switch schema.Dma {
		case DmaMRReg:
			if mrMirror != nil {
				// The object was created and the hardware now references the
				// mirrored pages, so the mirror must outlive this call. Keep
				// it whether or not the handle was found; if it wasn't, the
				// mirror is untracked and unpins only at process teardown.
				dmaCleanup.Release()
				if haveHandle {
					fd.pinned.addMR(handle, mrMirror)
				} else {
					log.Warningf("rdmaproxy: REG_MR succeeded but handle attr missing; leaking mirror")
				}
			}
		case DmaMRRegDMABuf:
			if haveHandle {
				// No pages to mirror; track a sentinel so DEREG matches.
				fd.pinned.addMR(handle, &MirroredPages{})
			}
		case DmaMRDestroy:
			if haveHandle {
				if mp := fd.pinned.removeMR(handle); mp != nil {
					mp.Release(t)
				}
			}
		case DmaCQCreate, DmaQPCreate:
			if cqqpMirror != nil {
				dmaCleanup.Release()
				if haveHandle {
					fd.pinned.addDMABufs(handle, cqqpMirror)
				} else {
					log.Warningf("rdmaproxy: CQ/QP CREATE succeeded but handle attr missing; leaking mirror")
				}
			}
		case DmaCQDestroy, DmaQPDestroy:
			if haveHandle {
				if bufs := fd.pinned.removeDMABufs(handle); bufs != nil {
					bufs.Release(t)
				}
			}
		case DmaAsyncAlloc:
			undo, err := fd.wrapAsyncEventFD(t, handleAttr)
			if err != nil {
				log.Warningf("rdmaproxy: async event fd wrap: %v", err)
			} else if undo != nil {
				asyncFDCleanup.Add(undo)
			}
		case DmaInvokeWrite:
			switch invokeWriteCmd(attrs) {
			case ib.IB_USER_VERBS_CMD_REG_MR:
				if mrMirror != nil {
					// The MR was created and the hardware now references the
					// mirrored pages, so keep the mirror regardless.
					dmaCleanup.Release()
					var resp ib.UverbsRegMRResp
					if coreOut := staged[ib.UVERBS_ATTR_CORE_OUT]; coreOut != nil && len(coreOut) >= resp.SizeBytes() {
						resp.UnmarshalBytes(coreOut)
						fd.pinned.addMR(resp.MRHandle, mrMirror)
					} else {
						log.Warningf("rdmaproxy: write REG_MR succeeded but no CORE_OUT handle; leaking mirror")
					}
				}
			case ib.IB_USER_VERBS_CMD_DEREG_MR:
				// ib_uverbs_dereg_mr is {u32 mr_handle}: carried inline when
				// CORE_IN is <=8 bytes, else the first u32 of the staged buffer.
				// Read it either way so the mirror is released regardless of how
				// the guest encoded CORE_IN.
				if a := findAttr(attrs, ib.UVERBS_ATTR_CORE_IN); a != nil {
					mrHandle, ok := uint32(a.Data), a.Len <= 8
					if a.Len > 8 {
						if sb := staged[ib.UVERBS_ATTR_CORE_IN]; len(sb) >= 4 {
							mrHandle, ok = hostarch.ByteOrder.Uint32(sb), true
						}
					}
					if ok {
						if mp := fd.pinned.removeMR(mrHandle); mp != nil {
							mp.Release(t)
						}
					}
				}
			}
		}
	}

	// Copy PTR_OUT staging buffers back to their guest pointers and restore
	// every rewritten data field so the guest observes only its own values.
	for i := range xlats {
		x := &xlats[i]
		if errno == 0 && x.outBuf != nil {
			// Best-effort: the guest pointer was validated on the way in.
			t.CopyOutBytes(hostarch.Addr(x.orig), x.outBuf)
		}
		x.attr.Data = x.orig
	}
	// Only the attrs are copied back: the kernel never modifies the header.
	if _, err := ib.CopyUverbsAttrSliceOut(t, attrsAddr, attrs); err != nil {
		// The guest never received an installed async-event fd number.
		return 0, err
	}
	asyncFDCleanup.Release()

	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// copyInPtr stages a guest PTR_IN payload of len bytes into a fresh sentry
// buffer. length is the attribute's u16 wire length, so sb is at most 64 KiB.
func (fd *uverbsFD) copyInPtr(t *kernel.Task, guestPtr uint64, length uint16) ([]byte, error) {
	sb := make([]byte, length)
	if _, err := t.CopyInBytes(hostarch.Addr(guestPtr), sb); err != nil {
		return nil, err
	}
	return sb, nil
}

// translateInputFD resolves an app fd referencing a proxied async-event FD to
// its underlying host fd. The caller takes a ref on the returned file, which
// must be released once the host fd is no longer needed.
func (fd *uverbsFD) translateInputFD(t *kernel.Task, appFD int32) (int, *vfs.FileDescription, error) {
	if appFD < 0 {
		return 0, nil, linuxerr.EINVAL
	}
	file := t.GetFile(appFD)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	afd, ok := file.Impl().(*asyncEventFD)
	if !ok {
		log.Warningf("rdmaproxy: unsupported input fd=%d type %T (not a proxied RDMA fd)", appFD, file.Impl())
		file.DecRef(t)
		return 0, nil, linuxerr.EINVAL
	}
	return int(afd.hostFD), file, nil
}

// translateHostBackedFD resolves an app fd backed by a host fd (e.g. an
// nvproxy dma-buf export) to its host fd via vfs.HostFDProvider. The caller
// takes a ref on the returned file, which must be released once the host fd is
// no longer needed.
func (fd *uverbsFD) translateHostBackedFD(t *kernel.Task, appFD int32) (int, *vfs.FileDescription, error) {
	if appFD < 0 {
		return 0, nil, linuxerr.EINVAL
	}
	file := t.GetFile(appFD)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	hp, ok := file.Impl().(vfs.HostFDProvider)
	if !ok {
		log.Warningf("rdmaproxy: unsupported fd=%d type %T (not a vfs.HostFDProvider)", appFD, file.Impl())
		file.DecRef(t)
		return 0, nil, linuxerr.EINVAL
	}
	return hp.HostFD(), file, nil
}

// findAttr returns the attribute with the given id, or nil.
func findAttr(attrs []ib.UverbsAttr, id uint16) *ib.UverbsAttr {
	for i := range attrs {
		if attrs[i].AttrID == id {
			return &attrs[i]
		}
	}
	return nil
}

// invokeWriteCmd returns the legacy write command number carried inline in the
// INVOKE_WRITE WRITE_CMD attribute, or math.MaxUint32 if absent.
func invokeWriteCmd(attrs []ib.UverbsAttr) uint32 {
	a := findAttr(attrs, ib.UVERBS_ATTR_WRITE_CMD)
	if a == nil {
		return ^uint32(0)
	}
	return uint32(a.Data)
}

// prepareInvokeWriteRegMR mirrors the guest MR pages for a legacy write-path
// REG_MR (the guest start/length live in the CORE_IN ib_uverbs_reg_mr blob,
// which the generic loop already copied into a sentry buffer). It rewrites the
// start field in that buffer to the sentry-side address. Returns nil for any
// non-REG_MR write command or a zero-length registration.
func (fd *uverbsFD) prepareInvokeWriteRegMR(t *kernel.Task, attrs []ib.UverbsAttr, staged map[uint16][]byte) (*MirroredPages, error) {
	if invokeWriteCmd(attrs) != ib.IB_USER_VERBS_CMD_REG_MR {
		return nil, nil
	}
	var cmd ib.UverbsRegMR
	coreIn := staged[ib.UVERBS_ATTR_CORE_IN]
	if coreIn == nil || len(coreIn) < cmd.SizeBytes() {
		return nil, nil
	}
	cmd.UnmarshalBytes(coreIn)
	if cmd.Length == 0 {
		return nil, nil
	}
	mp, sentryVA, err := MirrorAppPages(t, cmd.Start, cmd.Length)
	if err != nil {
		return nil, err
	}
	cmd.Start = uint64(sentryVA)
	cmd.MarshalBytes(coreIn)
	return mp, nil
}

// prepareMRReg mirrors the guest pages referenced by the REG_MR ADDR/LENGTH
// attributes (both inline u64 values) into the sentry and rewrites the inline
// ADDR to the sentry-side address. Returns nil if the request carried no
// address (e.g. an on-demand-paging or fd-backed registration).
func (fd *uverbsFD) prepareMRReg(t *kernel.Task, attrs []ib.UverbsAttr, xlats *[]xlat) (*MirroredPages, error) {
	addr := findAttr(attrs, ib.UVERBS_ATTR_REG_MR_ADDR)
	length := findAttr(attrs, ib.UVERBS_ATTR_REG_MR_LENGTH)
	if addr == nil || addr.Len == 0 || length == nil || length.Len == 0 || length.Data == 0 {
		return nil, nil
	}
	mp, sentryVA, err := MirrorAppPages(t, addr.Data, length.Data)
	if err != nil {
		return nil, err
	}
	*xlats = append(*xlats, xlat{attr: addr, orig: addr.Data})
	addr.Data = uint64(sentryVA)
	return mp, nil
}

// prepareDMABufFD translates the DMABUF fd carried inline in REG_DMABUF_MR's FD
// attribute (a PTR_IN u32) from an app fd to a host fd.
func (fd *uverbsFD) prepareDMABufFD(t *kernel.Task, attrs []ib.UverbsAttr, xlats *[]xlat) (func(), error) {
	a := findAttr(attrs, ib.UVERBS_ATTR_REG_DMABUF_MR_FD)
	if a == nil {
		return nil, linuxerr.EINVAL
	}
	hostFD, file, err := fd.translateHostBackedFD(t, int32(a.Data))
	if err != nil {
		return nil, err
	}
	*xlats = append(*xlats, xlat{attr: a, orig: a.Data})
	a.Data = uint64(uint32(hostFD))
	return func() { file.DecRef(t) }, nil
}

// prepareCreateDMA hands the copied-in UHW_IN driver payload to the vendor
// driver so it can mirror the CQ/QP work-queue and doorbell buffers and rewrite
// the embedded addresses in place.
func (fd *uverbsFD) prepareCreateDMA(t *kernel.Task, staged map[uint16][]byte) (*PinnedDMABufs, error) {
	uhw := staged[ib.UVERBS_ATTR_UHW_IN]
	if uhw == nil {
		// No driver payload (absent, or inline with no buffer pointers).
		return nil, nil
	}
	return fd.driver.PrepareCreateDMA(t, uhw)
}

// wrapAsyncEventFD wraps the host async-event fd the kernel wrote into the FD
// attribute a, installs a sentry FD, and rewrites a to the app fd number.
// Returns an undo closure to be run only if the subsequent copy-out to the
// guest fails.
func (fd *uverbsFD) wrapAsyncEventFD(t *kernel.Task, a *ib.UverbsAttr) (func(), error) {
	if a == nil {
		return nil, fmt.Errorf("ASYNC_EVENT_ALLOC response missing fd attr")
	}
	hostFD := int(int32(a.Data))
	if hostFD < 0 {
		return nil, fmt.Errorf("kernel returned invalid async event fd %d", hostFD)
	}
	sentryFD, err := newAsyncEventFD(t, hostFD) // takes ownership of hostFD.
	if err != nil {
		return nil, err
	}
	a.Data = uint64(uint32(sentryFD))
	log.Infof("rdmaproxy: installed async event fd -> app fd %d", sentryFD)
	return func() {
		if f := t.FDTable().Remove(t, sentryFD); f != nil {
			f.DecRef(t)
		}
	}, nil
}

// Read implements vfs.FileDescriptionImpl.Read, forwarding async-event reads to
// the host fd.
func (fd *uverbsFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return readProxiedEventFD(ctx, fd.hostFD, dst)
}

// Write rejects direct writes: the legacy uverbs write() command interface is
// not implemented; modern rdma-core uses RDMA_VERBS_IOCTL exclusively.
func (fd *uverbsFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	log.Warningf("rdmaproxy: unsupported legacy write(2) verbs interface")
	return 0, linuxerr.EINVAL
}

// Read implements vfs.FileDescriptionImpl.Read for asyncEventFD.
func (fd *asyncEventFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return readProxiedEventFD(ctx, fd.hostFD, dst)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *uverbsFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, fd, opts); err != nil {
		log.Warningf("rdmaproxy: mmap hostFD=%d: %v", fd.hostFD, err)
		return err
	}
	return nil
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
