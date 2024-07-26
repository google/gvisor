// Copyright 2023 The gVisor Authors.
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

package nvproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// frontendDevice implements vfs.Device for /dev/nvidia# and /dev/nvidiactl.
//
// +stateify savable
type frontendDevice struct {
	nvp   *nvproxy
	minor uint32
}

func (dev *frontendDevice) basename() string {
	if dev.minor == nvgpu.NV_CONTROL_DEVICE_MINOR {
		return "nvidiactl"
	}
	return fmt.Sprintf("nvidia%d", dev.minor)
}

// Open implements vfs.Device.Open.
func (dev *frontendDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devClient := devutil.GoferClientFromContext(ctx)
	if devClient == nil {
		log.Warningf("devutil.CtxDevGoferClient is not set")
		return nil, linuxerr.ENOENT
	}
	basename := dev.basename()
	hostFD, err := devClient.OpenAt(ctx, basename, opts.Flags)
	if err != nil {
		ctx.Warningf("nvproxy: failed to open host %s: %v", basename, err)
		return nil, err
	}
	fd := &frontendFD{
		dev:           dev,
		containerName: devClient.ContainerName(),
		hostFD:        int32(hostFD),
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.internalEntry.Init(fd, waiter.AllEvents)
	fd.internalQueue.EventRegister(&fd.internalEntry)
	if err := fdnotifier.AddFD(int32(hostFD), &fd.internalQueue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.fd = fd
	fd.dev.nvp.fdsMu.Lock()
	defer fd.dev.nvp.fdsMu.Unlock()
	fd.dev.nvp.frontendFDs[fd] = struct{}{}
	return &fd.vfsfd, nil
}

// frontendFD implements vfs.FileDescriptionImpl for /dev/nvidia# and
// /dev/nvidiactl.
//
// +stateify savable
type frontendFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev           *frontendDevice
	containerName string
	hostFD        int32
	memmapFile    frontendFDMemmapFile

	// The driver's implementation of poll() for these files,
	// kernel-open/nvidia/nv.c:nvidia_poll(), unsets
	// nv_linux_file_private_t::dataless_event_pending if it's set. This makes
	// notifications from dataless_event_pending edge-triggered; a host poll()
	// or epoll_wait() that returns the notification consumes it, preventing
	// future calls to poll() or epoll_wait() from observing the same
	// notification again.
	//
	// This is problematic in gVisor: fdnotifier, which epoll_wait()s on an
	// epoll instance that includes our hostFD, will forward notifications to
	// registered waiters, but this typically only wakes up blocked task
	// goroutines which will later call vfs.FileDescription.Readiness() to get
	// the FD's most up-to-date state. If our implementation of Readiness()
	// just polls the underlying host FD, it will no longer observe the
	// consumed notification.
	//
	// To work around this, intercept all events from fdnotifier and cache them
	// for the first following call to Readiness(), essentially replicating the
	// driver's behavior.
	internalQueue waiter.Queue
	internalEntry waiter.Entry
	cachedEvents  atomicbitops.Uint64
	appQueue      waiter.Queue

	haveMmapContext atomicbitops.Bool `state:"nosave"`

	// clients are handles of clients owned by this frontendFD. clients is
	// protected by dev.nvp.objsMu.
	clients map[nvgpu.Handle]struct{}
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *frontendFD) Release(ctx context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.appQueue.Notify(waiter.EventHUp)

	fd.dev.nvp.fdsMu.Lock()
	delete(fd.dev.nvp.frontendFDs, fd)
	fd.dev.nvp.fdsMu.Unlock()

	fd.dev.nvp.objsLock()
	defer fd.dev.nvp.objsUnlock()
	unix.Close(int(fd.hostFD))
	// src/nvidia/arch/nvalloc/unix/src/osapi.c:rm_cleanup_file_private() =>
	// RmFreeUnusedClients()
	for h := range fd.clients {
		fd.dev.nvp.objFree(ctx, h, h)
	}
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *frontendFD) EventRegister(e *waiter.Entry) error {
	fd.appQueue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *frontendFD) EventUnregister(e *waiter.Entry) {
	fd.appQueue.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *frontendFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	for {
		cachedEvents := waiter.EventMask(fd.cachedEvents.Load())
		maskedEvents := cachedEvents & mask
		if maskedEvents == 0 {
			// Poll for all events and cache any not consumed by this call.
			events := fdnotifier.NonBlockingPoll(fd.hostFD, waiter.AllEvents)
			if unmaskedEvents := events &^ mask; unmaskedEvents != 0 {
				fd.cacheEvents(unmaskedEvents)
			}
			return events & mask
		}
		if fd.cachedEvents.CompareAndSwap(uint64(cachedEvents), uint64(cachedEvents&^maskedEvents)) {
			return maskedEvents
		}
	}
}

func (fd *frontendFD) cacheEvents(mask waiter.EventMask) {
	for {
		oldEvents := waiter.EventMask(fd.cachedEvents.Load())
		newEvents := oldEvents | mask
		if oldEvents == newEvents {
			break
		}
		if fd.cachedEvents.CompareAndSwap(uint64(oldEvents), uint64(newEvents)) {
			break
		}
	}
}

// NotifyEvent implements waiter.EventListener.NotifyEvent.
func (fd *frontendFD) NotifyEvent(mask waiter.EventMask) {
	// Events must be cached before notifying fd.appQueue, in order to ensure
	// that the first notified waiter to call fd.Readiness() sees the
	// newly-cached events.
	fd.cacheEvents(mask)
	fd.appQueue.Notify(mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *frontendFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *frontendFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	nr := linux.IOC_NR(cmd)
	argPtr := args[2].Pointer()
	argSize := linux.IOC_SIZE(cmd)

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}

	if ctx.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: frontend ioctl: nr = %d = %#x, argSize = %d", nr, nr, argSize)
	}

	fi := frontendIoctlState{
		fd:              fd,
		ctx:             ctx,
		t:               t,
		nr:              nr,
		ioctlParamsAddr: argPtr,
		ioctlParamsSize: argSize,
	}

	// nr determines the argument type.
	// Implementors:
	// - To map nr to a symbol, look in
	// src/nvidia/arch/nvalloc/unix/include/nv_escape.h,
	// kernel-open/common/inc/nv-ioctl-numbers.h, and
	// kernel-open/common/inc/nv-ioctl-numa.h.
	// - To determine the parameter type, find the implementation in
	// kernel-open/nvidia/nv.c:nvidia_ioctl() or
	// src/nvidia/arch/nvalloc/unix/src/escape.c:RmIoctl().
	// - Add symbol and parameter type definitions to //pkg/abi/nvgpu.
	// - Add filter to seccomp_filters.go.
	// - Add handling below.
	handler := fd.dev.nvp.abi.frontendIoctl[nr]
	if handler == nil {
		ctx.Warningf("nvproxy: unknown frontend ioctl %d == %#x (argSize=%d, cmd=%#x)", nr, nr, argSize, cmd)
		return 0, linuxerr.EINVAL
	}
	return handler(&fi)
}

// IsNvidiaDeviceFD implements NvidiaDeviceFD.IsNvidiaDeviceFD.
func (fd *frontendFD) IsNvidiaDeviceFD() {}

func frontendIoctlCmd(nr, argSize uint32) uintptr {
	return uintptr(linux.IOWR(nvgpu.NV_IOCTL_MAGIC, nr, argSize))
}

// frontendIoctlState holds the state of a call to frontendFD.Ioctl().
type frontendIoctlState struct {
	fd              *frontendFD
	ctx             context.Context
	t               *kernel.Task
	nr              uint32
	ioctlParamsAddr hostarch.Addr
	ioctlParamsSize uint32
}

// frontendIoctlSimple implements a frontend ioctl whose parameters don't
// contain any pointers requiring translation, file descriptors, or special
// cases or effects, and consequently don't need to be typed by the sentry.
func frontendIoctlSimple(fi *frontendIoctlState) (uintptr, error) {
	if fi.ioctlParamsSize == 0 {
		return frontendIoctlInvoke[byte](fi, nil)
	}

	ioctlParams := make([]byte, fi.ioctlParamsSize)
	if _, err := fi.t.CopyInBytes(fi.ioctlParamsAddr, ioctlParams); err != nil {
		return 0, err
	}
	n, err := frontendIoctlInvoke(fi, &ioctlParams[0])
	if err != nil {
		return n, err
	}
	if _, err := fi.t.CopyOutBytes(fi.ioctlParamsAddr, ioctlParams); err != nil {
		return n, err
	}
	return n, nil
}

func rmNumaInfo(fi *frontendIoctlState) (uintptr, error) {
	// The CPU topology seen by the host driver differs from the CPU
	// topology presented by the sentry to the application, so reject this
	// ioctl; doing so is non-fatal.
	log.Debugf("nvproxy: ignoring NV_ESC_NUMA_INFO")
	return 0, linuxerr.EINVAL
}

func frontendRegisterFD(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.IoctlRegisterFD
	if fi.ioctlParamsSize != nvgpu.SizeofIoctlRegisterFD {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	ctlFileGeneric, _ := fi.t.FDTable().Get(ioctlParams.CtlFD)
	if ctlFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer ctlFileGeneric.DecRef(fi.ctx)
	ctlFile, ok := ctlFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	ioctlParams.CtlFD = ctlFile.hostFD
	// The returned ctl_fd can't change, so skip copying out.
	return frontendIoctlInvoke(fi, &ioctlParams)
}

func frontendIoctHasFD[Params any, PtrParams hasFrontendFDPtr[Params]](fi *frontendIoctlState) (uintptr, error) {
	var ioctlParamsValue Params
	ioctlParams := PtrParams(&ioctlParamsValue)
	if int(fi.ioctlParamsSize) != ioctlParams.SizeBytes() {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}

	origFD := ioctlParams.GetFrontendFD()
	eventFileGeneric, _ := fi.t.FDTable().Get(origFD)
	if eventFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer eventFileGeneric.DecRef(fi.ctx)
	eventFile, ok := eventFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	ioctlParams.SetFrontendFD(eventFile.hostFD)
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	ioctlParams.SetFrontendFD(origFD)
	if err != nil {
		return n, err
	}
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func rmAllocMemory(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.IoctlNVOS02ParametersWithFD
	if fi.ioctlParamsSize != nvgpu.SizeofIoctlNVOS02ParametersWithFD {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}

	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: NV_ESC_RM_ALLOC_MEMORY class %v", ioctlParams.Params.HClass)
	}
	// See src/nvidia/arch/nvalloc/unix/src/escape.c:RmIoctl() and
	// src/nvidia/interface/deprecated/rmapi_deprecated_allocmemory.c:rmAllocMemoryTable
	// for implementation.
	switch ioctlParams.Params.HClass {
	case nvgpu.NV01_MEMORY_SYSTEM_OS_DESCRIPTOR:
		return rmAllocOSDescriptor(fi, &ioctlParams)
	default:
		fi.ctx.Warningf("nvproxy: unknown NV_ESC_RM_ALLOC_MEMORY class %v", ioctlParams.Params.HClass)
		return 0, linuxerr.EINVAL
	}
}

func rmAllocOSDescriptor(fi *frontendIoctlState, ioctlParams *nvgpu.IoctlNVOS02ParametersWithFD) (uintptr, error) {
	// Compare src/nvidia/arch/nvalloc/unix/src/escape.c:RmAllocOsDescriptor()
	// => RmCreateOsDescriptor().
	failWithStatus := func(status uint32) error {
		ioctlParams.Params.Status = status
		_, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr)
		return err
	}
	appAddr := addrFromP64(ioctlParams.Params.PMemory)
	if !appAddr.IsPageAligned() {
		return 0, failWithStatus(nvgpu.NV_ERR_NOT_SUPPORTED)
	}
	arLen := ioctlParams.Params.Limit + 1
	if arLen == 0 { // integer overflow
		return 0, failWithStatus(nvgpu.NV_ERR_INVALID_LIMIT)
	}
	var ok bool
	arLen, ok = hostarch.PageRoundUp(arLen)
	if !ok {
		return 0, failWithStatus(nvgpu.NV_ERR_INVALID_ADDRESS)
	}
	appAR, ok := appAddr.ToRange(arLen)
	if !ok {
		return 0, failWithStatus(nvgpu.NV_ERR_INVALID_ADDRESS)
	}

	// The host driver will collect pages from our address space starting at
	// PMemory, so we must assemble a contiguous mapping equivalent to the
	// application's.
	at := hostarch.Read
	if ((ioctlParams.Params.Flags >> 21) & 0x1) == 0 /* NVOS02_FLAGS_ALLOC_USER_READ_ONLY_NO */ {
		at.Write = true
	}
	// Reserve a range in our address space.
	m, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0 /* addr */, uintptr(arLen), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uintptr(0) /* fd */, 0 /* offset */)
	if errno != 0 {
		return 0, errno
	}
	defer unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(arLen), 0)
	// Mirror application mappings into the reserved range.
	prs, err := fi.t.MemoryManager().Pin(fi.ctx, appAR, at, false /* ignorePermissions */)
	unpinCleanup := cleanup.Make(func() {
		mm.Unpin(prs)
	})
	defer unpinCleanup.Clean()
	if err != nil {
		return 0, err
	}
	sentryAddr := uintptr(m)
	for _, pr := range prs {
		ims, err := pr.File.MapInternal(memmap.FileRange{pr.Offset, pr.Offset + uint64(pr.Source.Length())}, at)
		if err != nil {
			return 0, err
		}
		for !ims.IsEmpty() {
			im := ims.Head()
			if _, _, errno := unix.RawSyscall6(unix.SYS_MREMAP, im.Addr(), 0 /* old_size */, uintptr(im.Len()), linux.MREMAP_MAYMOVE|linux.MREMAP_FIXED, sentryAddr, 0); errno != 0 {
				return 0, errno
			}
			sentryAddr += uintptr(im.Len())
			ims = ims.Tail()
		}
	}
	origPMemory := ioctlParams.Params.PMemory
	ioctlParams.Params.PMemory = nvgpu.P64(uint64(m))
	// NV01_MEMORY_SYSTEM_OS_DESCRIPTOR shouldn't use ioctlParams.FD; clobber
	// it to be sure.
	origFD := ioctlParams.FD
	ioctlParams.FD = -1

	fi.fd.dev.nvp.objsLock()
	n, err := frontendIoctlInvoke(fi, ioctlParams)
	if err == nil && ioctlParams.Params.Status == nvgpu.NV_OK {
		// Transfer ownership of pinned pages to an osDescMem object, to be
		// unpinned when the driver OsDescMem is freed.
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.Params.HRoot, ioctlParams.Params.HObjectNew, nvgpu.NV01_MEMORY_SYSTEM_OS_DESCRIPTOR, &osDescMem{
			pinnedRanges: prs,
		}, ioctlParams.Params.HObjectParent)
		unpinCleanup.Release()
		if fi.ctx.IsLogging(log.Debug) {
			fi.ctx.Debugf("nvproxy: pinned %d bytes for OS descriptor with handle %v", arLen, ioctlParams.Params.HObjectNew)
		}
	}
	fi.fd.dev.nvp.objsUnlock()
	ioctlParams.Params.PMemory = origPMemory
	ioctlParams.FD = origFD
	if err != nil {
		return n, err
	}

	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}

func rmFree(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.NVOS00Parameters
	if fi.ioctlParamsSize != nvgpu.SizeofNVOS00Parameters {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}

	fi.fd.dev.nvp.objsLock()
	n, err := frontendIoctlInvoke(fi, &ioctlParams)
	if err == nil && ioctlParams.Status == nvgpu.NV_OK {
		fi.fd.dev.nvp.objFree(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectOld)
	}
	fi.fd.dev.nvp.objsUnlock()
	if err != nil {
		return n, err
	}

	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}
	return n, nil
}

func rmControl(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.NVOS54Parameters
	if fi.ioctlParamsSize != nvgpu.SizeofNVOS54Parameters {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}

	// Cmd determines the type of Params.
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: control command %#x, object %#x", ioctlParams.Cmd, ioctlParams.HObject.Val)
	}
	if ioctlParams.Cmd&nvgpu.RM_GSS_LEGACY_MASK != 0 {
		// This is a "legacy GSS control" that is implemented by the GPU System
		// Processor (GSP). Conseqeuently, its parameters cannot reasonably
		// contain application pointers, and the control is in any case
		// undocumented.
		// See
		// src/nvidia/src/kernel/rmapi/entry_points.c:_nv04ControlWithSecInfo()
		// =>
		// src/nvidia/interface/deprecated/rmapi_deprecated_control.c:RmDeprecatedGetControlHandler()
		// =>
		// src/nvidia/interface/deprecated/rmapi_gss_legacy_control.c:RmGssLegacyRpcCmd().
		return rmControlSimple(fi, &ioctlParams)
	}
	// Implementors:
	// - Top two bytes of Cmd specifies class; third byte specifies category;
	// fourth byte specifies "message ID" (command within class/category).
	//   e.g. 0x800288:
	//   - Class 0x0080 => look in
	//   src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080base.h for categories.
	//   - Category 0x02 => NV0080_CTRL_GPU => look in
	//   src/common/sdk/nvidia/inc/ctrl/ctrl0080/ctrl0080gpu.h for
	//   `#define NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE (0x800288)`
	//   and accompanying documentation, parameter type.
	// - If this fails, or to find implementation, grep for `methodId=.*0x<Cmd
	// in lowercase hex without leading 0s>` to find entry in g_*_nvoc.c;
	// implementing function is is "pFunc".
	// - Add symbol definition to //pkg/abi/nvgpu. Parameter type definition is
	// only required for non-simple commands.
	// - Add handling below.
	handler := fi.fd.dev.nvp.abi.controlCmd[ioctlParams.Cmd]
	if handler == nil {
		fi.ctx.Warningf("nvproxy: unknown control command %#x (paramsSize=%d)", ioctlParams.Cmd, ioctlParams.ParamsSize)
		return 0, linuxerr.EINVAL
	}
	return handler(fi, &ioctlParams)
}

func rmControlSimple(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	if ioctlParams.ParamsSize == 0 {
		if ioctlParams.Params != 0 {
			return 0, linuxerr.EINVAL
		}
		return rmControlInvoke[byte](fi, ioctlParams, nil)
	}
	if ioctlParams.Params == 0 {
		return 0, linuxerr.EINVAL
	}

	ctrlParams := make([]byte, ioctlParams.ParamsSize)
	if _, err := fi.t.CopyInBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return 0, err
	}
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams[0])
	if err != nil {
		return n, err
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ioctlParams.Params), ctrlParams); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlCmdFailWithStatus(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters, status uint32) error {
	ioctlParams.Status = status
	_, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr)
	return err
}

func ctrlHasFrontendFD[Params any, PtrParams hasFrontendFDPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParamsValue Params
	ctrlParams := PtrParams(&ctrlParamsValue)
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	origFD := ctrlParams.GetFrontendFD()
	ctlFileGeneric, _ := fi.t.FDTable().Get(origFD)
	if ctlFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer ctlFileGeneric.DecRef(fi.ctx)
	ctlFile, ok := ctlFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	ctrlParams.SetFrontendFD(ctlFile.hostFD)
	n, err := rmControlInvoke(fi, ioctlParams, ctrlParams)
	ctrlParams.SetFrontendFD(origFD)
	if err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlMemoryMulticastFabricAttachGPU(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV00FD_CTRL_ATTACH_GPU_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	origDevDescriptor := ctrlParams.DevDescriptor
	devDescriptor, _ := fi.t.FDTable().Get(int32(origDevDescriptor))
	if devDescriptor == nil {
		return 0, linuxerr.EINVAL
	}
	defer devDescriptor.DecRef(fi.ctx)
	devDesc, ok := devDescriptor.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}

	ctrlParams.DevDescriptor = uint64(devDesc.hostFD)
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	ctrlParams.DevDescriptor = origDevDescriptor
	// Note that ctrlParams.CopyOut() is not called here because
	// NV00FD_CTRL_ATTACH_GPU_PARAMS is an input-only parameter.
	return n, err
}

func ctrlClientSystemGetBuildVersion(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	if ctrlParams.PDriverVersionBuffer == 0 || ctrlParams.PVersionBuffer == 0 || ctrlParams.PTitleBuffer == 0 {
		// No strings are written if any are null. See
		// src/nvidia/interface/deprecated/rmapi_deprecated_control.c:V2_CONVERTER(_NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION).
		return ctrlClientSystemGetBuildVersionInvoke(fi, ioctlParams, &ctrlParams, nil, nil, nil)
	}

	// Need to buffer strings for copy-out.
	if ctrlParams.SizeOfStrings == 0 {
		return 0, linuxerr.EINVAL
	}
	driverVersionBuf := make([]byte, ctrlParams.SizeOfStrings)
	versionBuf := make([]byte, ctrlParams.SizeOfStrings)
	titleBuf := make([]byte, ctrlParams.SizeOfStrings)
	n, err := ctrlClientSystemGetBuildVersionInvoke(fi, ioctlParams, &ctrlParams, &driverVersionBuf[0], &versionBuf[0], &titleBuf[0])
	if err != nil {
		return n, err
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ctrlParams.PDriverVersionBuffer), driverVersionBuf); err != nil {
		return n, err
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ctrlParams.PVersionBuffer), versionBuf); err != nil {
		return n, err
	}
	if _, err := fi.t.CopyOutBytes(addrFromP64(ctrlParams.PTitleBuffer), titleBuf); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlDevGpuGetClasslist(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV0080_CTRL_GPU_GET_CLASSLIST_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}

	// This command has two modes. If the classList pointer is NULL, only simple command handling
	// is required; see src/common/sdk/nvidia/inc/ctrl/ctrl0080gpu.h.
	if ctrlParams.ClassList == 0 {
		return rmControlSimple(fi, ioctlParams)
	}

	// classList pointer is not NULL. Check classList size against limit. See
	// src/nvidia/src/kernel/rmapi/embedded_param_copy.c:embeddedParamCopyIn() =>
	// case NV0080_CTRL_CMD_GPU_GET_CLASSLIST => RMAPI_PARAM_COPY_INIT().
	// paramCopy.paramsSize is initialized as numClasses * sizeof(NvU32).
	if ctrlParams.NumClasses*4 > nvgpu.RMAPI_PARAM_COPY_MAX_PARAMS_SIZE {
		return 0, ctrlCmdFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_ARGUMENT)
	}

	classList := make([]uint32, ctrlParams.NumClasses)
	n, err := ctrlDevGpuGetClasslistInvoke(fi, ioctlParams, &ctrlParams, classList)
	if err != nil {
		return n, err
	}
	return n, nil
}

func ctrlRegisterVASpace(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV503C_CTRL_REGISTER_VA_SPACE_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	fi.fd.dev.nvp.objsLock()
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	if err == nil && ioctlParams.Status == nvgpu.NV_OK {
		// src/nvidia/src/kernel/gpu/bus/third_party_p2p.c:CliAddThirdPartyP2PVASpace()
		// => refAddDependant()
		fi.fd.dev.nvp.objAddDep(ioctlParams.HClient, ioctlParams.HObject, ctrlParams.HVASpace)
	}
	fi.fd.dev.nvp.objsUnlock()
	if err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func ctrlSubdevFIFODisableChannels(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error) {
	var ctrlParams nvgpu.NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	// This pointer must be NULL; see
	// src/nvidia/src/kernel/gpu/fifo/kernel_fifo_ctrl.c:subdeviceCtrlCmdFifoDisableChannels_IMPL().
	// Consequently, we don't need to translate it, but we do want to ensure
	// that it actually is NULL.
	if ctrlParams.PRunlistPreemptEvent != 0 {
		return 0, linuxerr.EINVAL
	}
	n, err := rmControlInvoke(fi, ioctlParams, &ctrlParams)
	if err != nil {
		return n, err
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return n, err
	}
	return n, nil
}

func rmAlloc(fi *frontendIoctlState) (uintptr, error) {
	var isNVOS64 bool
	switch fi.ioctlParamsSize {
	case nvgpu.SizeofNVOS21Parameters:
	case nvgpu.SizeofNVOS64Parameters:
		isNVOS64 = true
	default:
		return 0, linuxerr.EINVAL
	}
	// Copy in parameters and convert to NVOS64Parameters, which is a super
	// set of all parameter types we support.
	buf := nvgpu.GetRmAllocParamObj(isNVOS64)
	if _, err := buf.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	ioctlParams := buf.ToOS64()

	// hClass determines the type of pAllocParms.
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: allocation class %v", ioctlParams.HClass)
	}
	// Implementors:
	// - To map hClass to a symbol, look in
	// src/nvidia/generated/g_allclasses.h.
	// - See src/nvidia/src/kernel/rmapi/resource_list.h for table mapping class
	// ("External Class") to the type of pAllocParms ("Alloc Param Info") and
	// the class whose constructor interprets it ("Internal Class").
	// - Add symbol and parameter type definitions to //pkg/abi/nvgpu.
	// - Check constructor for calls to refAddDependant(),
	// sessionAddDependant(), or sessionAddDependency(), which need to be
	// mirrored by dependencies in the call to nvproxy.objAddLocked().
	// - Add handling below.
	handler := fi.fd.dev.nvp.abi.allocationClass[ioctlParams.HClass]
	if handler == nil {
		fi.ctx.Warningf("nvproxy: unknown allocation class %v", ioctlParams.HClass)
		// Compare
		// src/nvidia/src/kernel/rmapi/alloc_free.c:serverAllocResourceUnderLock(),
		// when RsResInfoByExternalClassId() is null.
		ioctlParams.Status = nvgpu.NV_ERR_INVALID_CLASS
		outIoctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
		outIoctlParams.FromOS64(ioctlParams)
		// Any copy-out error from
		// src/nvidia/src/kernel/rmapi/alloc_free.c:serverAllocApiCopyOut() is
		// discarded.
		outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr)
		return 0, nil
	}
	return handler(fi, &ioctlParams, isNVOS64)
}

// rmAllocSimple implements NV_ESC_RM_ALLOC for classes whose parameters don't
// contain any pointers or file descriptors requiring translation, and whose
// objects require no special handling and depend only on their parents.
//
// Unlike frontendIoctlSimple and rmControlSimple, rmAllocSimple requires the
// parameter type since the parameter's size is otherwise unknown.
func rmAllocSimple[Params any, PtrParams marshalPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams[Params, PtrParams](fi, ioctlParams, isNVOS64, addSimpleObjDepParentLocked)
}

// addSimpleObjDepParentLocked implements rmAllocInvoke.addObjLocked for
// classes that require no special handling and depend only on their parents.
func addSimpleObjDepParentLocked[Params any](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) {
	fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRmAllocObject(fi.fd, ioctlParams, rightsRequested, allocParams), ioctlParams.HObjectParent)
}

func rmAllocSimpleParams[Params any, PtrParams marshalPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool, objAddLocked func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params)) (uintptr, error) {
	if ioctlParams.PAllocParms == 0 {
		return rmAllocInvoke[Params](fi, ioctlParams, nil, isNVOS64, objAddLocked)
	}

	var allocParamsValue Params
	allocParams := PtrParams(&allocParamsValue)
	if _, err := allocParams.CopyIn(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return 0, err
	}
	n, err := rmAllocInvoke(fi, ioctlParams, allocParams, isNVOS64, objAddLocked)
	if err != nil {
		return n, err
	}
	if _, err := allocParams.CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return n, err
	}
	return n, nil
}

func rmAllocNoParams(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocInvoke[byte](fi, ioctlParams, nil, isNVOS64, addSimpleObjDepParentLocked)
}

func rmAllocRootClient(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams(fi, ioctlParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.Handle) {
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRootClient(fi.fd, ioctlParams, rightsRequested, allocParams))
		if fi.fd.clients == nil {
			fi.fd.clients = make(map[nvgpu.Handle]struct{})
		}
		fi.fd.clients[ioctlParams.HObjectNew] = struct{}{}
	})
}

func rmAllocEventOSEvent(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	var allocParams nvgpu.NV0005_ALLOC_PARAMETERS
	if _, err := allocParams.CopyIn(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return 0, err
	}
	eventFileGeneric, _ := fi.t.FDTable().Get(int32(allocParams.Data))
	if eventFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer eventFileGeneric.DecRef(fi.ctx)
	eventFile, ok := eventFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	origData := allocParams.Data
	allocParams.Data = nvgpu.P64(uint64(eventFile.hostFD))

	n, err := rmAllocInvoke(fi, ioctlParams, &allocParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.NV0005_ALLOC_PARAMETERS) {
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, &osEvent{}, ioctlParams.HObjectParent)
	})
	if err != nil {
		return n, err
	}

	allocParams.Data = origData
	if _, err := allocParams.CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return n, err
	}
	return n, nil
}

func rmAllocSMDebuggerSession(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams(fi, ioctlParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.NV83DE_ALLOC_PARAMETERS) {
		// Compare
		// src/nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c:ksmdbgssnConstruct_IMPL()
		// => _ShareDebugger() => sessionAddDependency/sessionAddDependant();
		// the driver indirects through a per-KernelGraphicsObject
		// RmDebuggerSession, which we elide for dependency tracking.
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRmAllocObject(fi.fd, ioctlParams, rightsRequested, allocParams), ioctlParams.HObjectParent, allocParams.HClass3DObject)
	})
}

func rmAllocChannelGroup(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams(fi, ioctlParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) {
		// See
		// src/nvidia/src/kernel/gpu/fifo/kernel_channel_group_api.c:kchangrpapiConstruct_IMPL()
		// => refAddDependant().
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRmAllocObject(fi.fd, ioctlParams, rightsRequested, allocParams), ioctlParams.HObjectParent, allocParams.HVASpace)
		// Note: When the channel group's engine type is GR, which is always
		// true unless MIG is enabled, kchangrpapiConstruct_IMPL() constructs a
		// KERNEL_GRAPHICS_CONTEXT whose lifetime is the same as the channel
		// group's (the graphics context is freed when the channel group is).
		// Channels, context shares, and graphics objects depend on this
		// graphics context rather than the channel group. Consequently, if MIG
		// is enabled, these might not depend on the channel group at all.
		// Since nvproxy currently does not support MIG, we represent these
		// dependencies as unconditionally on the channel group instead.
	})
}

func rmAllocChannel(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams(fi, ioctlParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.NV_CHANNEL_ALLOC_PARAMS) {
		// See
		// src/nvidia/src/kernel/gpu/fifo/kernel_channel.c:kchannelConstruct_IMPL()
		// => refAddDependant(). The channel's parent may be a device or
		// channel group; if it is a channel group then the channel depends on
		// it via the parent relationship, and if it is not a channel group
		// then kchannelConstruct_IMPL() constructs one internally and frees it
		// when the channel is destroyed, so either way no separate dependency
		// is required.
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRmAllocObject(fi.fd, ioctlParams, rightsRequested, allocParams), ioctlParams.HObjectParent, allocParams.HVASpace, allocParams.HContextShare)
	})
}

func rmAllocContextShare(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocSimpleParams(fi, ioctlParams, isNVOS64, func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS) {
		// See
		// src/nvidia/src/kernel/gpu/fifo/kernel_ctxshare.c:kctxshareapiConstruct_IMPL()
		// => refAddDependant(). The context share's parent is the channel
		// group, so (given that we are representing graphics context
		// dependencies as channel group dependencies) no separate dependency
		// is required.
		fi.fd.dev.nvp.objAdd(fi.ctx, ioctlParams.HRoot, ioctlParams.HObjectNew, ioctlParams.HClass, newRmAllocObject(fi.fd, ioctlParams, rightsRequested, allocParams), ioctlParams.HObjectParent, allocParams.HVASpace)
	})
}

func rmVidHeapControl(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.NVOS32Parameters
	if fi.ioctlParamsSize != nvgpu.SizeofNVOS32Parameters {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}

	// Function determines the type of Data.
	if fi.ctx.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: VID_HEAP_CONTROL function %d", ioctlParams.Function)
	}
	// See
	// src/nvidia/interface/deprecated/rmapi_deprecated_vidheapctrl.c:rmVidHeapControlTable
	// for implementation.
	switch ioctlParams.Function {
	case nvgpu.NVOS32_FUNCTION_ALLOC_SIZE:
		return rmVidHeapControlAllocSize(fi, &ioctlParams)
	default:
		fi.ctx.Warningf("nvproxy: unknown VID_HEAP_CONTROL function %d", ioctlParams.Function)
		return 0, linuxerr.EINVAL
	}
}

func rmMapMemory(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.IoctlNVOS33ParametersWithFD
	if fi.ioctlParamsSize != nvgpu.SizeofIoctlNVOS33ParametersWithFD {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	mapFileGeneric, _ := fi.t.FDTable().Get(ioctlParams.FD)
	if mapFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer mapFileGeneric.DecRef(fi.ctx)
	mapFile, ok := mapFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	if mapFile.haveMmapContext.Load() || !mapFile.haveMmapContext.CompareAndSwap(false, true) {
		fi.ctx.Warningf("nvproxy: attempted to reuse FD %d for NV_ESC_RM_MAP_MEMORY", ioctlParams.FD)
		return 0, linuxerr.EINVAL
	}
	origFD := ioctlParams.FD
	ioctlParams.FD = mapFile.hostFD

	n, err := frontendIoctlInvoke(fi, &ioctlParams)
	if err != nil {
		return n, err
	}

	ioctlParams.FD = origFD
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}
