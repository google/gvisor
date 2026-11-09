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

package nvproxy

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// nvidia-drm render nodes, /dev/dri/renderD<minor>. NVIDIA's OpenGL, Vulkan,
// EGL and NvFBC libraries open one to identify the GPU behind it. nvproxy
// exposes them only with the display driver capability, opens only those of
// nvidia-drm, and makes nvidia-drm's own ioctls behave as when nvidia-drm is
// loaded with modeset=0, a configuration that NVIDIA's userspace drivers
// support. Queries reach the host, and nvproxy reports fences and dma-bufs as
// unsupported. No ioctl that makes nvidia-drm or NVKMS allocate host objects
// reaches the host.
const (
	drmMajor           = 226
	drmRenderMinorBase = 128
	drmRenderMinorMax  = 191

	// Ioctl numbers from include/uapi/drm/drm.h and, for nvidia-drm's own
	// ioctls (from DRM_COMMAND_BASE), kernel-open/nvidia-drm/nvidia-drm-ioctl.h
	// or nv_drm_common_ioctl.h. DRM_NVIDIA_GET_DEV_INFO's number depends on the
	// driver version; see drmABI.
	drmIoctlVersion         = 0xc0406400 // DRM_IOCTL_VERSION, struct drm_version
	drmIoctlGetCap          = 0xc010640c // DRM_IOCTL_GET_CAP, struct drm_get_cap
	drmIoctlSetClientCap    = 0x4010640d // DRM_IOCTL_SET_CLIENT_CAP, struct drm_set_client_cap
	drmNvGetDevInfoNr       = 0x43       // DRM_COMMAND_BASE + DRM_NVIDIA_GET_DEV_INFO
	drmNvFenceSupported     = 0x00006444 // DRM_IOCTL_NVIDIA_FENCE_SUPPORTED, no argument
	drmNvDmabufSupported    = 0x0000644f // DRM_IOCTL_NVIDIA_DMABUF_SUPPORTED, no argument
	drmNvGetDRMFileUniqueID = 0xc0086458 // DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID, struct drm_nvidia_get_drm_file_unique_id_params

	// drmVersionStringMaxBytes is the most that nvproxy copies of each string
	// that DRM_IOCTL_VERSION returns.
	drmVersionStringMaxBytes = 4096
)

// drmNvidiaDriverName is the driver name that nvidia-drm reports in
// DRM_IOCTL_VERSION.
const drmNvidiaDriverName = "nvidia-drm"

// isNvidiaDRMDriver returns true if name, the copied part of a driver name
// whose full length is nameLen, as DRM_IOCTL_VERSION returns them, is
// nvidia-drm.
func isNvidiaDRMDriver(name []byte, nameLen uint64) bool {
	if nameLen != uint64(len(drmNvidiaDriverName)) || uint64(len(name)) < nameLen {
		return false
	}
	return string(name[:nameLen]) == drmNvidiaDriverName
}

// drmABI describes the nvidia-drm render node ioctls of a driver version.
type drmABI struct {
	// devInfoSize is the size of struct drm_nvidia_get_dev_info_params,
	// which DRM_IOCTL_NVIDIA_GET_DEV_INFO encodes.
	devInfoSize uint32

	// devInfoModesetOnly is the offset of the first field of struct
	// drm_nvidia_get_dev_info_params that nvidia-drm sets only with
	// modeset=1. All fields from it on are such fields. See
	// kernel-open/nvidia-drm/nvidia-drm-drv.c:nv_drm_get_dev_info_ioctl().
	devInfoModesetOnly uint32

	// fileUniqueID is true if the driver has
	// DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID.
	fileUniqueID bool
}

// getDevInfoCmd returns the number of DRM_IOCTL_NVIDIA_GET_DEV_INFO.
func (a *drmABI) getDevInfoCmd() uint32 {
	return drmIOWR(drmNvGetDevInfoNr, a.devInfoSize)
}

// DRMDevInfoLayout is the layout of struct drm_nvidia_get_dev_info_params in a
// driver version.
type DRMDevInfoLayout struct {
	// Size is the size of the struct, which DRM_IOCTL_NVIDIA_GET_DEV_INFO
	// encodes.
	Size uint32

	// ModesetOnlyOffset is the offset of the first field that nvidia-drm sets
	// only with modeset=1. All fields from it on are such fields.
	ModesetOnlyOffset uint32
}

// DRMDevInfoLayoutOf returns the layout of struct
// drm_nvidia_get_dev_info_params in the given driver version, and false if
// nvproxy has no ABI for the version. Init must be called first.
func DRMDevInfoLayoutOf(version nvconf.DriverVersion) (DRMDevInfoLayout, bool) {
	abiEntry, ok := abis[version]
	if !ok {
		return DRMDevInfoLayout{}, false
	}
	abi := abiEntry.cons()
	return DRMDevInfoLayout{
		Size:              abi.drm.devInfoSize,
		ModesetOnlyOffset: abi.drm.devInfoModesetOnly,
	}, true
}

// drmIOWR returns the number of a DRM ioctl that reads and writes size bytes,
// like DRM_IOWR(nr, type) in include/uapi/drm/drm.h.
func drmIOWR(nr, size uint32) uint32 {
	return linux.IOWR('d', nr, size)
}

// drmDevInfoSizes lists every size of struct drm_nvidia_get_dev_info_params in
// the supported drivers.
var drmDevInfoSizes = []uint32{20, 28, 32, 36}

// drmHostIoctls returns the render node ioctls that nvproxy sends to the host,
// for the seccomp filters. Each takes a fixed-size argument with no pointers,
// except DRM_IOCTL_VERSION, whose string buffers nvproxy replaces with its
// own. None makes nvidia-drm allocate host objects.
func drmHostIoctls() []uintptr {
	ioctls := []uintptr{
		drmIoctlVersion,
		drmIoctlGetCap,
		drmIoctlSetClientCap,
	}
	for _, size := range drmDevInfoSizes {
		ioctls = append(ioctls, uintptr(drmIOWR(drmNvGetDevInfoNr, size)))
	}
	return ioctls
}

// drmRenderDevice implements vfs.Device for /dev/dri/renderD<minor>.
//
// +stateify savable
type drmRenderDevice struct {
	nvp   *nvproxy
	minor uint32
}

// Open implements vfs.Device.Open.
func (dev *drmRenderDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if dev.nvp.capsEnabled&nvconf.CapDisplay == 0 {
		return nil, linuxerr.ENXIO
	}
	fd := &drmRenderFD{dev: dev, uniqueID: dev.nvp.nextDRMFileID()}
	var err error
	fd.hostFD, fd.containerName, err = openHostDevFile(ctx, fmt.Sprintf("dri/renderD%d", dev.minor), dev.nvp.useDevGofer, opts.Flags)
	if err != nil {
		return nil, err
	}
	// The container spec may name render nodes of other DRM drivers, whose
	// ioctls nvproxy does not proxy.
	name, nameLen, err := drmHostDriverName(fd.hostFD, len(drmNvidiaDriverName)+1)
	if err != nil || !isNvidiaDRMDriver(name, nameLen) {
		ctx.Warningf("nvproxy: render node %d is not an nvidia-drm render node", dev.minor)
		unix.Close(int(fd.hostFD))
		return nil, linuxerr.ENXIO
	}
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		fdnotifier.RemoveFD(fd.hostFD)
		unix.Close(int(fd.hostFD))
		return nil, err
	}
	return &fd.vfsfd, nil
}

// drmRenderFD implements vfs.FileDescriptionImpl for a render node. It cannot
// be saved, since the host DRM file it holds has no state that nvproxy can
// recreate on restore.
//
// +stateify savable
type drmRenderFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev           *drmRenderDevice
	containerName string
	hostFD        int32
	queue         waiter.Queue

	// uniqueID is the ID that DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID
	// returns.
	uniqueID uint64
}

// beforeSave is invoked by stateify.
func (fd *drmRenderFD) beforeSave() {
	panic("nvproxy: DRM render node FDs cannot be saved")
}

// IsNvidiaDeviceFD implements NvidiaDeviceFD.IsNvidiaDeviceFD.
func (fd *drmRenderFD) IsNvidiaDeviceFD() {}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *drmRenderFD) Release(context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *drmRenderFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *drmRenderFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *drmRenderFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *drmRenderFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *drmRenderFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := args[1].Uint()
	addr := args[2].Pointer()
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	abi := &fd.dev.nvp.abi.drm
	switch cmd {
	case drmIoctlVersion:
		return drmVersion(t, fd.hostFD, addr)
	case drmIoctlGetCap, drmIoctlSetClientCap:
		return drmIoctlSimple(t, fd.hostFD, cmd, addr)
	case abi.getDevInfoCmd():
		return drmGetDevInfo(t, fd.hostFD, abi, addr)
	case drmNvFenceSupported, drmNvDmabufSupported:
		// nvidia-drm fails both with EINVAL when loaded with modeset=0.
		return 0, linuxerr.EINVAL
	case drmNvGetDRMFileUniqueID:
		if !abi.fileUniqueID {
			break
		}
		// The host numbers the DRM files of all processes on the host, so
		// nvproxy numbers the sandbox's render node files instead. These IDs
		// mean nothing to the host and are never passed to host ioctls.
		var buf [8]byte
		hostarch.ByteOrder.PutUint64(buf[:], fd.uniqueID)
		if _, err := t.CopyOutBytes(addr, buf[:]); err != nil {
			return 0, err
		}
		return 0, nil
	}
	ctx.Warningf("nvproxy: unsupported DRM render node ioctl %#x", cmd)
	return 0, linuxerr.EINVAL
}

// drmVersionSize is the size of struct drm_version.
const drmVersionSize = 64

// drmVersionStrings holds the offsets in struct drm_version of the length and
// the pointer of each of its string buffers, name, date and desc.
var drmVersionStrings = [3]struct{ lenOff, ptrOff int }{{16, 24}, {32, 40}, {48, 56}}

// drmVersion proxies DRM_IOCTL_VERSION. struct drm_version holds three
// application string buffers with their lengths. nvproxy gives the host a
// sentry buffer of at most drmVersionStringMaxBytes in place of each one that
// is not null or empty, and copies what the host wrote to the application's.
func drmVersion(t *kernel.Task, hostFD int32, addr hostarch.Addr) (uintptr, error) {
	buf := make([]byte, drmVersionSize)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return 0, err
	}
	var strs [len(drmVersionStrings)][]byte
	for i, s := range drmVersionStrings {
		appPtr := hostarch.ByteOrder.Uint64(buf[s.ptrOff:])
		length := hostarch.ByteOrder.Uint64(buf[s.lenOff:])
		if appPtr == 0 || length == 0 {
			continue
		}
		strs[i] = make([]byte, min(length, drmVersionStringMaxBytes))
	}
	n, err := drmVersionInvoke(hostFD, buf, &strs)
	if err != nil {
		return n, err
	}
	for i, s := range drmVersionStrings {
		if strs[i] == nil {
			continue
		}
		// The driver reports the full string length and copies at most the
		// buffer length.
		copyLen := min(hostarch.ByteOrder.Uint64(buf[s.lenOff:]), uint64(len(strs[i])))
		appPtr := hostarch.Addr(hostarch.ByteOrder.Uint64(buf[s.ptrOff:]))
		if _, err := t.CopyOutBytes(appPtr, strs[i][:copyLen]); err != nil {
			return n, err
		}
	}
	if _, err := t.CopyOutBytes(addr, buf); err != nil {
		return n, err
	}
	return n, nil
}

// drmGetDevInfo handles DRM_IOCTL_NVIDIA_GET_DEV_INFO. It clears the fields
// that nvidia-drm sets only with modeset=1, so that userspace does not try GEM
// allocation, sync file export or semaphore surface fences.
func drmGetDevInfo(t *kernel.Task, hostFD int32, abi *drmABI, addr hostarch.Addr) (uintptr, error) {
	buf := make([]byte, abi.devInfoSize)
	n, err := drmIoctlInvoke(hostFD, abi.getDevInfoCmd(), buf)
	if err != nil {
		return n, err
	}
	drmDevInfoAsModeset0(abi, buf)
	if _, err := t.CopyOutBytes(addr, buf); err != nil {
		return n, err
	}
	return n, nil
}

// drmDevInfoAsModeset0 clears the fields of a struct
// drm_nvidia_get_dev_info_params that nvidia-drm sets only with modeset=1.
func drmDevInfoAsModeset0(abi *drmABI, buf []byte) {
	clear(buf[abi.devInfoModesetOnly:])
}

// drmIoctlSimple sends an ioctl whose argument is a fixed-size struct with no
// pointers to the host, copying the struct in and out as the ioctl's direction
// bits say.
func drmIoctlSimple(t *kernel.Task, hostFD int32, cmd uint32, addr hostarch.Addr) (uintptr, error) {
	size := (cmd >> linux.IOC_SIZESHIFT) & ((1 << linux.IOC_SIZEBITS) - 1)
	buf := make([]byte, size)
	dir := cmd >> linux.IOC_DIRSHIFT
	if dir&linux.IOC_WRITE != 0 {
		if _, err := t.CopyInBytes(addr, buf); err != nil {
			return 0, err
		}
	}
	n, err := drmIoctlInvoke(hostFD, cmd, buf)
	if err != nil {
		return n, err
	}
	if dir&linux.IOC_READ != 0 {
		if _, err := t.CopyOutBytes(addr, buf); err != nil {
			return n, err
		}
	}
	return n, nil
}
