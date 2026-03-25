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

// Package rdmaproxy implements a passthrough proxy for /dev/infiniband/uverbs*
// devices, enabling RDMA support inside gVisor sandboxes.
package rdmaproxy

import (
	"fmt"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// hostNetnsFD holds a file descriptor to the host's network namespace.
// containerNetnsFD holds the sentry's (container) network namespace.
// RoCE ioctls require the calling thread to be in the host netns so
// the kernel can resolve GIDs to physical NICs. Both FDs are saved
// before seccomp filters are installed so no open() is needed later.
var (
	hostNetnsFD      int32 = -1
	containerNetnsFD int32 = -1
)

// SetHostNetnsFD stores the host network namespace FD and captures the
// current (container) netns for later restoration. Must be called
// before seccomp filters are installed.
func SetHostNetnsFD(fd int) {
	hostNetnsFD = int32(fd)
	curFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		curFD, err = unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		containerNetnsFD = int32(curFD)
	}
	log.Infof("rdmaproxy: host netns FD=%d, container netns FD=%d", hostNetnsFD, containerNetnsFD)
}

// uverbsDevice implements vfs.Device for /dev/infiniband/uverbs*.
type uverbsDevice struct {
	// devName is the device filename, e.g. "uverbs0". This is distinct
	// from the kernel minor number (e.g. 192) used for VFS registration.
	devName string
}

// Open implements vfs.Device.Open.
func (dev *uverbsDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devRelPath := filepath.Join("infiniband", dev.devName)
	log.Infof("rdmaproxy: opening %s (flags=0x%x)", devRelPath, opts.Flags)
	hostFD, err := openHostDevice(ctx, devRelPath, opts.Flags)
	if err != nil {
		log.Warningf("rdmaproxy: open host device %s: %v", devRelPath, err)
		return nil, err
	}
	log.Infof("rdmaproxy: opened %s → hostFD=%d", devRelPath, hostFD)
	fd := &uverbsFD{
		hostFD: int32(hostFD),
	}
	if err := fdnotifier.AddFD(fd.hostFD, &fd.queue); err != nil {
		unix.Close(hostFD)
		return nil, err
	}
	fd.memmapFile.SetFD(int(fd.hostFD))
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		fdnotifier.RemoveFD(fd.hostFD)
		unix.Close(hostFD)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// openHostDevice opens a host device using the dev gofer if available,
// falling back to a direct open. devRelPath is relative to /dev/.
func openHostDevice(ctx context.Context, devRelPath string, flags uint32) (int, error) {
	if client := devutil.GoferClientFromContext(ctx); client != nil {
		log.Infof("rdmaproxy: using dev gofer to open %s", devRelPath)
		return client.OpenAt(ctx, devRelPath, flags)
	}
	log.Infof("rdmaproxy: no dev gofer, falling back to direct open for %s", devRelPath)
	devPath := filepath.Join("/dev", devRelPath)
	openFlags := int(flags&unix.O_ACCMODE | unix.O_NOFOLLOW)
	return unix.Openat(-1, devPath, openFlags, 0)
}

// mirroredPages tracks sandbox pages pinned and mapped into the sentry's
// address space so the host kernel can pin_user_pages on them for DMA.
type mirroredPages struct {
	prs []mm.PinnedRange
	// If m != 0, it's a sentry-side mmap we own and must munmap on release.
	m   uintptr
	len uintptr
}

func (mp *mirroredPages) release(ctx context.Context) {
	if mp.m != 0 {
		if _, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, mp.m, mp.len, 0); errno != 0 {
			log.Warningf("rdmaproxy: munmap %#x-%#x: %v", mp.m, mp.m+mp.len, errno)
		}
	}
	mm.Unpin(mp.prs)
}

// pinnedDMABufs tracks the buf + doorbell mirrors for a single CQ or QP.
type pinnedDMABufs struct {
	buf *mirroredPages
	db  *mirroredPages
}

func (p *pinnedDMABufs) release(ctx context.Context) {
	if p.buf != nil {
		p.buf.release(ctx)
	}
	if p.db != nil {
		p.db.release(ctx)
	}
}

// uverbsFD implements vfs.FileDescriptionImpl for an opened uverbs device.
//
// uverbsFD is not savable; we do not implement save/restore of RDMA state.
type uverbsFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	hostFD     int32
	queue      waiter.Queue
	memmapFile fsutil.MmapNoInternalFile

	// mu protects pinnedMRs, pinnedCQs, and pinnedQPs.
	mu        sync.Mutex
	pinnedMRs map[uint32]*mirroredPages
	pinnedCQs map[uint32]*pinnedDMABufs
	pinnedQPs map[uint32]*pinnedDMABufs
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uverbsFD) Release(ctx context.Context) {
	fd.mu.Lock()
	for handle, mp := range fd.pinnedMRs {
		log.Infof("rdmaproxy: releasing pinned MR handle=%d on fd close", handle)
		mp.release(ctx)
	}
	fd.pinnedMRs = nil
	for handle, p := range fd.pinnedCQs {
		log.Infof("rdmaproxy: releasing pinned CQ handle=%d on fd close", handle)
		p.release(ctx)
	}
	fd.pinnedCQs = nil
	for handle, p := range fd.pinnedQPs {
		log.Infof("rdmaproxy: releasing pinned QP handle=%d on fd close", handle)
		p.release(ctx)
	}
	fd.pinnedQPs = nil
	fd.mu.Unlock()

	log.Infof("rdmaproxy: closing hostFD=%d", fd.hostFD)
	fdnotifier.RemoveFD(fd.hostFD)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *uverbsFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *uverbsFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *uverbsFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Register registers a uverbs device with the VFS and returns the dynamic
// major number. devName is the device filename (e.g. "uverbs0"), minor is
// the kernel device minor number (e.g. 192).
func Register(vfsObj *vfs.VirtualFilesystem, devName string, minor uint32) (uint32, error) {
	major, err := vfsObj.GetDynamicCharDevMajor()
	if err != nil {
		return 0, fmt.Errorf("rdmaproxy: obtaining dynamic major number: %w", err)
	}
	log.Infof("rdmaproxy: registering %s with major=%d minor=%d", devName, major, minor)
	if err := vfsObj.RegisterDevice(vfs.CharDevice, major, minor, &uverbsDevice{devName: devName}, &vfs.RegisterDeviceOptions{
		GroupName: "infiniband",
		Pathname:  filepath.Join("infiniband", devName),
		FilePerms: 0666,
	}); err != nil {
		return 0, err
	}
	return major, nil
}

// MayRegisterDevicePath returns true if path looks like a uverbs device.
func MayRegisterDevicePath(path string) bool {
	matched, _ := filepath.Match("/dev/infiniband/uverbs*", path)
	return matched
}

// ErrNotUverbsDevice is returned when the device path doesn't match.
var ErrNotUverbsDevice = linuxerr.ENODEV
