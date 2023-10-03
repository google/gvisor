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
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
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

// Open implements vfs.Device.Open.
func (dev *frontendDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	var hostPath string
	if dev.minor == nvgpu.NV_CONTROL_DEVICE_MINOR {
		hostPath = "/dev/nvidiactl"
	} else {
		hostPath = fmt.Sprintf("/dev/nvidia%d", dev.minor)
	}
	hostFD, err := unix.Openat(-1, hostPath, int((opts.Flags&unix.O_ACCMODE)|unix.O_NOFOLLOW), 0)
	if err != nil {
		ctx.Warningf("nvproxy: failed to open host %s: %v", hostPath, err)
		return nil, err
	}
	fd := &frontendFD{
		nvp:       dev.nvp,
		hostFD:    int32(hostFD),
		isControl: dev.minor == nvgpu.NV_CONTROL_DEVICE_MINOR,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	if err := fdnotifier.AddFD(int32(hostFD), &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.fd = fd
	return &fd.vfsfd, nil
}

// frontendFD implements vfs.FileDescriptionImpl for /dev/nvidia# and
// /dev/nvidiactl.
//
// frontendFD is not savable; we do not implement save/restore of host GPU
// state.
type frontendFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	nvp        *nvproxy
	hostFD     int32
	isControl  bool
	memmapFile frontendFDMemmapFile

	queue waiter.Queue

	haveMmapContext atomic.Bool
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *frontendFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *frontendFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *frontendFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *frontendFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
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

	fi := frontendIoctlState{
		fd:              fd,
		ctx:             ctx,
		t:               t,
		nr:              nr,
		ioctlParamsAddr: argPtr,
		ioctlParamsSize: argSize,
	}

	// nr determines the argument type.
	// Don't log nr since it's already visible as the last byte of cmd in
	// strace logging.
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
	switch nr {
	case
		nvgpu.NV_ESC_CARD_INFO,                     // nv_ioctl_card_info_t
		nvgpu.NV_ESC_CHECK_VERSION_STR,             // nv_rm_api_version_t
		nvgpu.NV_ESC_SYS_PARAMS,                    // nv_ioctl_sys_params_t
		nvgpu.NV_ESC_RM_DUP_OBJECT,                 // NVOS55_PARAMETERS
		nvgpu.NV_ESC_RM_SHARE,                      // NVOS57_PARAMETERS
		nvgpu.NV_ESC_RM_UNMAP_MEMORY,               // NVOS34_PARAMETERS
		nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: // NVOS56_PARAMETERS
		return frontendIoctlSimple(&fi)
	case nvgpu.NV_ESC_REGISTER_FD:
		return frontendRegisterFD(&fi)
	case nvgpu.NV_ESC_ALLOC_OS_EVENT:
		return rmAllocOSEvent(&fi)
	case nvgpu.NV_ESC_FREE_OS_EVENT:
		return rmFreeOSEvent(&fi)
	case nvgpu.NV_ESC_NUMA_INFO:
		// The CPU topology seen by the host driver differs from the CPU
		// topology presented by the sentry to the application, so reject this
		// ioctl; doing so is non-fatal.
		ctx.Debugf("nvproxy: ignoring NV_ESC_NUMA_INFO")
		return 0, linuxerr.EINVAL
	case nvgpu.NV_ESC_RM_ALLOC_MEMORY:
		return rmAllocMemory(&fi)
	case nvgpu.NV_ESC_RM_FREE:
		return rmFree(&fi)
	case nvgpu.NV_ESC_RM_CONTROL:
		return rmControl(&fi)
	case nvgpu.NV_ESC_RM_ALLOC:
		return rmAlloc(&fi)
	case nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:
		return rmVidHeapControl(&fi)
	case nvgpu.NV_ESC_RM_MAP_MEMORY:
		return rmMapMemory(&fi)
	default:
		ctx.Warningf("nvproxy: unknown frontend ioctl %d == %#x (argSize=%d, cmd=%#x)", nr, nr, argSize, cmd)
		return 0, linuxerr.EINVAL
	}
}

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
	sentryIoctlParams := nvgpu.IoctlRegisterFD{
		CtlFD: ctlFile.hostFD,
	}
	// The returned ctl_fd can't change, so skip copying out.
	return frontendIoctlInvoke(fi, &sentryIoctlParams)
}

func rmAllocOSEvent(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.IoctlAllocOSEvent
	if fi.ioctlParamsSize != nvgpu.SizeofIoctlAllocOSEvent {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	eventFileGeneric, _ := fi.t.FDTable().Get(int32(ioctlParams.FD))
	if eventFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer eventFileGeneric.DecRef(fi.ctx)
	eventFile, ok := eventFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	sentryIoctlParams := ioctlParams
	sentryIoctlParams.FD = uint32(eventFile.hostFD)

	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	outIoctlParams.FD = ioctlParams.FD
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}

func rmFreeOSEvent(fi *frontendIoctlState) (uintptr, error) {
	var ioctlParams nvgpu.IoctlFreeOSEvent
	if fi.ioctlParamsSize != nvgpu.SizeofIoctlFreeOSEvent {
		return 0, linuxerr.EINVAL
	}
	if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	eventFileGeneric, _ := fi.t.FDTable().Get(int32(ioctlParams.FD))
	if eventFileGeneric == nil {
		return 0, linuxerr.EINVAL
	}
	defer eventFileGeneric.DecRef(fi.ctx)
	eventFile, ok := eventFileGeneric.Impl().(*frontendFD)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	sentryIoctlParams := ioctlParams
	sentryIoctlParams.FD = uint32(eventFile.hostFD)

	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	outIoctlParams.FD = ioctlParams.FD
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
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
		fi.ctx.Debugf("nvproxy: NV_ESC_RM_ALLOC_MEMORY class %#08x", ioctlParams.Params.HClass)
	}
	// See src/nvidia/arch/nvalloc/unix/src/escape.c:RmIoctl() and
	// src/nvidia/interface/deprecated/rmapi_deprecated_allocmemory.c:rmAllocMemoryTable
	// for implementation.
	switch ioctlParams.Params.HClass {
	case nvgpu.NV01_MEMORY_SYSTEM_OS_DESCRIPTOR:
		return rmAllocOSDescriptor(fi, &ioctlParams)
	default:
		fi.ctx.Warningf("nvproxy: unknown NV_ESC_RM_ALLOC_MEMORY class %#08x", ioctlParams.Params.HClass)
		return 0, linuxerr.EINVAL
	}
}

func rmAllocOSDescriptor(fi *frontendIoctlState, ioctlParams *nvgpu.IoctlNVOS02ParametersWithFD) (uintptr, error) {
	// Compare src/nvidia/arch/nvalloc/unix/src/escape.c:RmAllocOsDescriptor()
	// => RmCreateOsDescriptor().
	failWithStatus := func(status uint32) error {
		outIoctlParams := *ioctlParams
		outIoctlParams.Params.Status = status
		_, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr)
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
	cu := cleanup.Make(func() {
		unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(arLen), 0)
	})
	defer cu.Clean()
	// Mirror application mappings into the reserved range.
	prs, err := fi.t.MemoryManager().Pin(fi.ctx, appAR, at, false /* ignorePermissions */)
	cu.Add(func() {
		mm.Unpin(prs)
	})
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
	sentryIoctlParams := *ioctlParams
	sentryIoctlParams.Params.PMemory = nvgpu.P64(uint64(m))
	// NV01_MEMORY_SYSTEM_OS_DESCRIPTOR shouldn't use ioctlParams.FD; clobber
	// it to be sure.
	sentryIoctlParams.FD = -1

	fi.fd.nvp.objsMu.Lock()
	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		fi.fd.nvp.objsMu.Unlock()
		return n, err
	}
	// Transfer ownership of pinned pages to an osDescMem object, to be
	// unpinned when the driver OsDescMem is freed.
	o := &osDescMem{
		pinnedRanges: prs,
	}
	o.object.init(o)
	fi.fd.nvp.objsLive[sentryIoctlParams.Params.HObjectNew] = &o.object
	fi.fd.nvp.objsMu.Unlock()
	cu.Release()
	fi.ctx.Infof("nvproxy: pinned pages for OS descriptor with handle %#x", sentryIoctlParams.Params.HObjectNew)
	// Unmap the reserved range, which is no longer required.
	unix.RawSyscall(unix.SYS_MUNMAP, m, uintptr(arLen), 0)

	outIoctlParams := sentryIoctlParams
	outIoctlParams.Params.PMemory = ioctlParams.Params.PMemory
	outIoctlParams.FD = ioctlParams.FD
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
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

	fi.fd.nvp.objsMu.Lock()
	n, err := frontendIoctlInvoke(fi, &ioctlParams)
	if err != nil {
		fi.fd.nvp.objsMu.Unlock()
		return n, err
	}
	o, ok := fi.fd.nvp.objsLive[ioctlParams.HObjectOld]
	if ok {
		delete(fi.fd.nvp.objsLive, ioctlParams.HObjectOld)
	}
	fi.fd.nvp.objsMu.Unlock()
	if ok {
		o.Release(fi.ctx)
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
		fi.ctx.Debugf("nvproxy: control command %#x", ioctlParams.Cmd)
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
	switch ioctlParams.Cmd {
	case
		nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE,
		nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS,
		nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS,
		nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO,
		nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE,
		nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE,
		nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,
		nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS,
		nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS,
		nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX,
		nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2,
		nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES,
		nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE,
		nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE,
		0x80028b, // unknown, paramsSize == 1
		nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2,
		nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2,
		nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO,
		nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO,
		nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2,
		nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS,
		nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS,
		nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO,
		nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS,
		nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES,
		nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION,
		nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS,
		nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG,
		nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO,
		nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE,
		nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE,
		nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER,
		nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2,
		nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK,
		nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK,
		nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES,
		nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO,
		nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS,
		nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS,
		nvgpu.NV2080_CTRL_CMD_PERF_BOOST,
		nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO,
		nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS,
		nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG,
		nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO,
		nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE,
		nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM,
		nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM,
		nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
		nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES,
		nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES,
		nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL,
		nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK,
		nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID,
		nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN,
		nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE,
		nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE,
		nvgpu.NVA06C_CTRL_CMD_PREEMPT:
		return rmControlSimple(fi, &ioctlParams)

	case nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:
		return ctrlClientSystemGetBuildVersion(fi, &ioctlParams)

	case nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:
		return ctrlDevFIFOGetChannelList(fi, &ioctlParams)

	case nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:
		return ctrlSubdevFIFODisableChannels(fi, &ioctlParams)

	case nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:
		return ctrlSubdevGRGetInfo(fi, &ioctlParams)

	default:
		fi.ctx.Warningf("nvproxy: unknown control command %#x (paramsSize=%d)", ioctlParams.Cmd, ioctlParams.ParamsSize)
		return 0, linuxerr.EINVAL
	}
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
	// Copy in parameters and convert to NVOS64Parameters.
	var (
		ioctlParams nvgpu.NVOS64Parameters
		isNVOS64    bool
	)
	switch fi.ioctlParamsSize {
	case nvgpu.SizeofNVOS21Parameters:
		var buf nvgpu.NVOS21Parameters
		if _, err := buf.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
			return 0, err
		}
		ioctlParams = nvgpu.NVOS64Parameters{
			HRoot:         buf.HRoot,
			HObjectParent: buf.HObjectParent,
			HObjectNew:    buf.HObjectNew,
			HClass:        buf.HClass,
			PAllocParms:   buf.PAllocParms,
			Status:        buf.Status,
		}
	case nvgpu.SizeofNVOS64Parameters:
		if _, err := ioctlParams.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
			return 0, err
		}
		isNVOS64 = true
	default:
		return 0, linuxerr.EINVAL
	}

	// hClass determines the type of pAllocParms.
	if log.IsLogging(log.Debug) {
		fi.ctx.Debugf("nvproxy: allocation class %#08x", ioctlParams.HClass)
	}
	// Implementors:
	// - To map hClass to a symbol, look in
	// src/nvidia/generated/g_allclasses.h.
	// - See src/nvidia/src/kernel/rmapi/resource_list.h for table mapping class
	// ("External Class") to the type of pAllocParms ("Alloc Param Info") and
	// the class whose constructor interprets it ("Internal Class").
	// - Add symbol and parameter type definitions to //pkg/abi/nvgpu.
	// - Add handling below.
	switch ioctlParams.HClass {
	case nvgpu.NV01_ROOT, nvgpu.NV01_ROOT_NON_PRIV, nvgpu.NV01_ROOT_CLIENT:
		return rmAllocSimple[nvgpu.Handle](fi, &ioctlParams, isNVOS64)
	case nvgpu.NV01_EVENT_OS_EVENT:
		return rmAllocEventOSEvent(fi, &ioctlParams, isNVOS64)
	case nvgpu.NV01_DEVICE_0:
		return rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.NV20_SUBDEVICE_0:
		return rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.NV50_THIRD_PARTY_P2P:
		return rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.GT200_DEBUGGER:
		return rmAllocSimple[nvgpu.NV83DE_ALLOC_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.FERMI_CONTEXT_SHARE_A:
		return rmAllocSimple[nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.FERMI_VASPACE_A:
		return rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.KEPLER_CHANNEL_GROUP_A:
		return rmAllocSimple[nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.TURING_CHANNEL_GPFIFO_A, nvgpu.AMPERE_CHANNEL_GPFIFO_A:
		return rmAllocSimple[nvgpu.NV_CHANNEL_ALLOC_PARAMS](fi, &ioctlParams, isNVOS64)
	case nvgpu.TURING_DMA_COPY_A, nvgpu.AMPERE_DMA_COPY_A, nvgpu.AMPERE_DMA_COPY_B, nvgpu.HOPPER_DMA_COPY_A:
		return rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.TURING_COMPUTE_A, nvgpu.AMPERE_COMPUTE_A, nvgpu.AMPERE_COMPUTE_B, nvgpu.ADA_COMPUTE_A, nvgpu.HOPPER_COMPUTE_A:
		return rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	case nvgpu.HOPPER_USERMODE_A:
		return rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS](fi, &ioctlParams, isNVOS64)
	case nvgpu.GF100_SUBDEVICE_MASTER, nvgpu.TURING_USERMODE_A:
		return rmAllocNoParams(fi, &ioctlParams, isNVOS64)
	case nvgpu.NV_MEMORY_FABRIC:
		return rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS](fi, &ioctlParams, isNVOS64)
	default:
		fi.ctx.Warningf("nvproxy: unknown allocation class %#08x", ioctlParams.HClass)
		return 0, linuxerr.EINVAL
	}
}

// Unlike frontendIoctlSimple and rmControlSimple, rmAllocSimple requires the
// parameter type since the parameter's size is otherwise unknown.
func rmAllocSimple[Params any, PParams marshalPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	if ioctlParams.PAllocParms == 0 {
		return rmAllocInvoke[byte](fi, ioctlParams, nil, isNVOS64)
	}

	var allocParams Params
	if _, err := (PParams)(&allocParams).CopyIn(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return 0, err
	}
	n, err := rmAllocInvoke(fi, ioctlParams, &allocParams, isNVOS64)
	if err != nil {
		return n, err
	}
	if _, err := (PParams)(&allocParams).CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return n, err
	}
	return n, nil
}

func rmAllocNoParams(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	return rmAllocInvoke[byte](fi, ioctlParams, nil, isNVOS64)
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
	sentryAllocParams := allocParams
	sentryAllocParams.Data = nvgpu.P64(uint64(eventFile.hostFD))

	n, err := rmAllocInvoke(fi, ioctlParams, &sentryAllocParams, isNVOS64)
	if err != nil {
		return n, err
	}

	outAllocParams := sentryAllocParams
	outAllocParams.Data = allocParams.Data
	if _, err := outAllocParams.CopyOut(fi.t, addrFromP64(ioctlParams.PAllocParms)); err != nil {
		return n, err
	}
	return n, nil
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
	if log.IsLogging(log.Debug) {
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
	sentryIoctlParams := ioctlParams
	sentryIoctlParams.FD = mapFile.hostFD

	n, err := frontendIoctlInvoke(fi, &sentryIoctlParams)
	if err != nil {
		return n, err
	}

	outIoctlParams := sentryIoctlParams
	outIoctlParams.FD = ioctlParams.FD
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return n, err
	}

	return n, nil
}
