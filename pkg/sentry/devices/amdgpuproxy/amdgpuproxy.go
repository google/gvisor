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

// Package amdgpuproxy implements /dev/kfd and /dev/dri/renderD* for AMD GPU
// compute (ROCm) on top of the host's AMDGPU/KFD driver.
//
// As in nvproxy, the host driver is trusted to handle whatever an
// unprivileged native process could ask of it. The proxy's job is to keep
// application pointers and descriptors out of the sentry's address space:
// ioctl arguments and their nested buffers are bounced through sentry memory,
// USERPTR registrations pin application pages and register a sentry alias of
// them, and ACQUIRE_VM's render node FD is translated.
//
// KFD binds its per-process state to the host address space that opened
// /dev/kfd, so the sentry opens it itself (OpenKFD) and the proxy serves
// exactly one application address space per sandbox.
//
// KFD hides the GPUs whose render node the device cgroup denies to a process.
// The sentry is not subject to the container's device cgroup, so the proxy
// stands in for it: apertures are filtered to the granted GPUs, and requests
// naming other GPUs fail with EINVAL as they do natively.
package amdgpuproxy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/amdgpu"
	hostamdgpu "gvisor.dev/gvisor/pkg/amdgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// OpenKFD opens the host's /dev/kfd for Register. It must be called by the
// process that runs the sentry, after any re-exec, because the driver binds
// the KFD process to the opener's address space.
func OpenKFD() (int, error) {
	fd, err := unix.Open("/dev/kfd", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	// With XNACK on, GPU page faults are resolved through SVM against the
	// KFD process's address space, i.e. the sentry's. Turn it off before an
	// application can use the GPU; SET_XNACK_MODE refuses to turn it back on.
	v := amdgpu.KFDSetXNACKMode{XNACKEnabled: 0}
	b := make([]byte, v.SizeBytes())
	v.MarshalBytes(b)
	if err := hostIoctl(int32(fd), amdgpu.AMDKFD_IOC_SET_XNACK_MODE, b); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("disabling KFD XNACK: %w", err)
	}
	return fd, nil
}

// Register registers the granted devices. gpuIDs maps DRM render minors to
// their KFD GPU IDs.
func Register(vfsObj *vfs.VirtualFilesystem, kfdFD int, devices []hostamdgpu.Device, gpuIDs map[uint32]uint32) error {
	p := &proxy{kfdFD: int32(kfdFD), gpus: make(map[uint32]bool), allocations: make(map[uint64]*allocation)}
	for _, d := range devices {
		dev := &device{proxy: p, path: strings.TrimPrefix(d.Path, "/dev/"), kfd: d.Path == "/dev/kfd", gpuID: gpuIDs[d.Minor]}
		if !dev.kfd {
			if dev.gpuID == 0 {
				return fmt.Errorf("no KFD GPU ID for %s", d.Path)
			}
			p.gpus[dev.gpuID] = true
		}
		if err := vfsObj.RegisterDevice(vfs.CharDevice, d.Major, d.Minor, dev, &vfs.RegisterDeviceOptions{GroupName: "amdgpuproxy"}); err != nil {
			return err
		}
	}
	return nil
}

// +stateify savable
type proxy struct {
	kfdFD int32 `state:"nosave"`
	// gpus holds the KFD GPU IDs of the granted render nodes.
	gpus map[uint32]bool `state:"nosave"`

	mu sync.Mutex `state:"nosave"`
	// owner is the application address space using the GPUs. KFD keys its
	// process state by the sentry's host address space, so no other
	// application process can get a GPU context of its own.
	owner *mm.MemoryManager `state:"nosave"`
	// allocations maps KFD memory handles to live allocations.
	allocations map[uint64]*allocation `state:"nosave"`
}

func (p *proxy) beforeSave() {
	panic("amdgpuproxy: checkpoint is not supported")
}

type allocation struct {
	// mmapOffset and size locate the allocation's render node mapping; size
	// is that of the backing buffer.
	mmapOffset uint64
	size       uint64
	memType    hostarch.MemoryType
	// userptr is the pinned application memory of a USERPTR allocation.
	userptr *userMemory
}

func (p *proxy) checkOwner(t *kernel.Task) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owner != t.MemoryManager() {
		return linuxerr.EBUSY
	}
	return nil
}

// memoryType returns the CPU memory type that the host driver uses for the
// allocation at render node offset off: write-combined for VRAM and cached
// for GTT (amdgpu_vram_mgr_new, amdgpu_ttm_tt_create).
func (p *proxy) memoryType(off uint64) hostarch.MemoryType {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.allocations {
		if a.mmapOffset <= off && off < a.mmapOffset+a.size {
			return a.memType
		}
	}
	return hostarch.MemoryTypeUncached
}

// +stateify savable
type device struct {
	proxy *proxy
	// path is relative to /dev.
	path string
	kfd  bool
	// gpuID is the KFD GPU ID of a render node.
	gpuID uint32
}

// Open implements vfs.Device.Open.
func (d *device) Open(ctx context.Context, mnt *vfs.Mount, dent *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return nil, linuxerr.EINVAL
	}
	p := d.proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owner != nil && p.owner != t.MemoryManager() {
		return nil, linuxerr.EBUSY
	}
	var hostFD int
	var err error
	if d.kfd {
		hostFD, err = unix.Dup(int(p.kfdFD))
	} else {
		client := devutil.GoferClientFromContext(ctx)
		if client == nil {
			return nil, linuxerr.ENOENT
		}
		hostFD, err = client.OpenAt(ctx, d.path, opts.Flags&unix.O_ACCMODE)
	}
	if err != nil {
		return nil, err
	}
	fd := &deviceFD{dev: d, hostFD: int32(hostFD)}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, dent, &vfs.FileDescriptionOptions{UseDentryMetadata: true, SpecialFile: true}); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.SetFD(hostFD)
	fd.memmapFile.SetMemType(hostarch.MemoryTypeUncached)
	for i := range fd.memTypeFiles {
		fd.memTypeFiles[i] = memTypeFile{&fd.memmapFile, hostarch.MemoryType(i)}
	}
	p.owner = t.MemoryManager()
	return &fd.vfsfd, nil
}

// +stateify savable
type deviceFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	dev    *device
	hostFD int32 `state:"nosave"`
	// memmapFile caches host mappings of the device. Its own memory type,
	// uncached, is used for KFD mappings (doorbells and MMIO); render node
	// mappings use the allocation's type through memTypeFiles.
	memmapFile   fsutil.MmapPreciseFile
	memTypeFiles [hostarch.NumMemoryTypes]memTypeFile `state:"nosave"`
}

// memTypeFile is memmapFile with a different memory type.
type memTypeFile struct {
	*fsutil.MmapPreciseFile
	memType hostarch.MemoryType
}

// MemoryType implements memmap.File.MemoryType.
func (f *memTypeFile) MemoryType() hostarch.MemoryType {
	return f.memType
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *deviceFD) Release(ctx context.Context) {
	fd.memmapFile.MappableRelease()
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *deviceFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		panic("Ioctl should be called from a task context")
	}
	if err := fd.dev.proxy.checkOwner(t); err != nil {
		return 0, err
	}
	cmd, addr := args[1].Uint(), args[2].Pointer()
	var err error
	if fd.dev.kfd {
		err = fd.kfdIoctl(t, cmd, addr)
	} else {
		err = fd.drmIoctl(t, cmd, addr)
	}
	if err != nil {
		ctx.Debugf("amdgpuproxy: %s ioctl %#x: %v", fd.dev.path, cmd, err)
	}
	return 0, err
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *deviceFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return linuxerr.EINVAL
	}
	if err := fd.dev.proxy.checkOwner(t); err != nil {
		return err
	}
	if gpu := uint32((opts.Offset & amdgpu.KFD_MMAP_GPU_ID_MASK) >> amdgpu.KFD_MMAP_GPU_ID_SHIFT); fd.dev.kfd && gpu != 0 && !fd.dev.proxy.gpus[gpu] {
		return linuxerr.EINVAL
	}
	// As vfs.GenericProxyDeviceConfigureMMap, but without its file offset
	// limit: KFD mmap offsets carry the mapping type in bits 62-63.
	if opts.PlatformEffect < memmap.PlatformEffectPopulate {
		opts.PlatformEffect = memmap.PlatformEffectPopulate
	}
	opts.RequirePlatformEffect = true
	opts.Mappable = fd
	opts.MappingIdentity = &fd.vfsfd
	fd.vfsfd.IncRef()
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (fd *deviceFD) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	var f memmap.File = &fd.memmapFile
	if !fd.dev.kfd {
		f = &fd.memTypeFiles[fd.dev.proxy.memoryType(optional.Start)]
	}
	return []memmap.Translation{{Source: optional, File: f, Offset: optional.Start, Perms: hostarch.AnyAccess}}, nil
}
