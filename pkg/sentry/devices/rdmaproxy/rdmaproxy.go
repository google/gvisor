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
//
// # Design
//
// The proxy forwards the modern UVERBS ioctl interface (RDMA_VERBS_IOCTL =
// _IOWR(0x1b, 1, struct ib_uverbs_ioctl_hdr)) to a host uverbs FD, translating
// guest pointers, file descriptors and DMA buffers along the way. Every request
// is validated against an explicit per-(object, method) schema (see schema.go);
// an unmodeled object/method or an unexpected attribute is rejected rather than
// blindly forwarded. The schema — not any probing of guest memory — determines
// how each attribute's data field is interpreted, which is what keeps a
// malicious guest from coercing the proxy into an out-of-bounds copy.
//
// # Host ABI requirements
//
// The proxy targets the UVERBS ioctl object/method/attribute IDs that reached
// mainline in Linux 4.20 (Dec 2018) via include/uapi/rdma/ib_user_ioctl_cmds.h.
// Per upstream policy these IDs are additive only — old IDs are never
// repurposed — so newer kernels remain compatible; older kernels are not
// supported.
//
// At Register time the proxy checks the kernel's IB_USER_VERBS_ABI_VERSION
// (collected host-side from /sys/class/infiniband_verbs/abi_version, since the
// sentry runs chrooted and seccomp-confined and cannot read sysfs itself) and
// refuses to attach on a mismatch. That value has been frozen at 6 in upstream
// Linux for over a decade; the kernel bumps it only on a userspace-breaking
// change.
package rdmaproxy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// expectedUverbsABIVersion is the value of IB_USER_VERBS_ABI_VERSION the proxy
// is built against. Frozen at 6 in upstream Linux for over a decade.
const expectedUverbsABIVersion = 6

// uverbsClassDir is the sysfs class directory for the uverbs subsystem, where
// the host kernel publishes the class-wide abi_version.
const uverbsClassDir = "/sys/class/infiniband_verbs"

// uverbsDevice implements vfs.Device for /dev/infiniband/uverbs*.
type uverbsDevice struct {
	// devName is the device filename, e.g. "uverbs0". Distinct from the
	// kernel minor number (e.g. 192) used for VFS registration.
	devName string
	// driver is the per-vendor plug-in attached to this device, looked up by
	// name at Register time. Always non-nil: Register refuses to register a
	// device whose host PCI driver has no plug-in.
	driver Driver
}

// Open implements vfs.Device.Open.
func (dev *uverbsDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devClient := devutil.GoferClientFromContext(ctx)
	if devClient == nil {
		log.Warningf("devutil.CtxDevGoferClient is not set")
		return nil, linuxerr.ENOENT
	}
	devRelPath := filepath.Join("infiniband", dev.devName)
	hostFD, err := devClient.OpenAt(ctx, devRelPath, opts.Flags)
	if err != nil {
		log.Warningf("rdmaproxy: open host device %s: %v", devRelPath, err)
		return nil, err
	}
	fd := &uverbsFD{
		hostFD: int32(hostFD),
		driver: dev.driver,
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

// MirroredPages tracks application pages pinned and mapped into the sentry's
// address space so the host kernel can pin_user_pages on them for DMA.
type MirroredPages struct {
	prs []mm.PinnedRange
	// If m != 0, it's a sentry-side mmap we own and must munmap on release.
	m   uintptr
	len uintptr
}

// Release tears down the sentry-side mapping and unpins the underlying app
// pages.
func (mp *MirroredPages) Release(ctx context.Context) {
	if mp.m != 0 {
		if _, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, mp.m, mp.len, 0); errno != 0 {
			log.Warningf("rdmaproxy: munmap %#x-%#x: %v", mp.m, mp.m+mp.len, errno)
		}
	}
	mm.Unpin(mp.prs)
}

// PinnedDMABufs tracks the buf + doorbell mirrors for a single CQ or QP. Driver
// plug-ins return this from PrepareCreateDMA; the core stores it against the
// resulting CQ/QP handle until DESTROY.
type PinnedDMABufs struct {
	// Buf is the work-queue buffer mirror, or nil if the driver produced none.
	Buf *MirroredPages
	// DB is the doorbell page mirror, or nil if the driver produced none.
	DB *MirroredPages
}

// Release tears down both buffer mirrors. Safe to call with nil fields.
func (p *PinnedDMABufs) Release(ctx context.Context) {
	if p.Buf != nil {
		p.Buf.Release(ctx)
	}
	if p.DB != nil {
		p.DB.Release(ctx)
	}
}

// pinnedResources tracks the app memory mirrored on behalf of one uverbs
// FD's MRs/CQs/QPs. Handles are scoped to the uverbs context (the underlying
// host FD), so this state lives per-uverbsFD.
type pinnedResources struct {
	mu  sync.Mutex
	mrs map[uint32]*MirroredPages
	// dmaBufs tracks CQ and QP mirrors together: object handles are unique
	// within a uverbs context's IDR namespace, so CQ and QP ids never collide.
	dmaBufs map[uint32]*PinnedDMABufs
}

// addMR records the page mirror for a successful REG_MR.
func (p *pinnedResources) addMR(handle uint32, mp *MirroredPages) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mrs == nil {
		p.mrs = make(map[uint32]*MirroredPages)
	}
	p.mrs[handle] = mp
}

// addDMABufs records the buf+db mirrors for a successful CQ/QP CREATE.
func (p *pinnedResources) addDMABufs(handle uint32, bufs *PinnedDMABufs) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dmaBufs == nil {
		p.dmaBufs = make(map[uint32]*PinnedDMABufs)
	}
	p.dmaBufs[handle] = bufs
}

// removeMR removes and returns the mirror for handle, or nil if absent. The
// caller takes ownership of the returned mirror.
func (p *pinnedResources) removeMR(handle uint32) *MirroredPages {
	p.mu.Lock()
	defer p.mu.Unlock()
	mp, ok := p.mrs[handle]
	if !ok {
		return nil
	}
	delete(p.mrs, handle)
	return mp
}

// removeDMABufs removes and returns the bufs for a CQ/QP handle, or nil if
// absent. The caller takes ownership of the returned bufs.
func (p *pinnedResources) removeDMABufs(handle uint32) *PinnedDMABufs {
	p.mu.Lock()
	defer p.mu.Unlock()
	bufs, ok := p.dmaBufs[handle]
	if !ok {
		return nil
	}
	delete(p.dmaBufs, handle)
	return bufs
}

// releaseAll drains every tracked mirror and releases the underlying pages.
// Used as a safety net at FD close for handles the application neglected to
// DEREG/DESTROY. Subsequent calls are no-ops.
func (p *pinnedResources) releaseAll(ctx context.Context) {
	p.mu.Lock()
	mrs, dmaBufs := p.mrs, p.dmaBufs
	p.mrs, p.dmaBufs = nil, nil
	p.mu.Unlock()
	for _, mp := range mrs {
		mp.Release(ctx)
	}
	for _, bufs := range dmaBufs {
		bufs.Release(ctx)
	}
}

// uverbsFD implements vfs.FileDescriptionImpl for an opened uverbs device.
//
// uverbsFD is not savable; RDMA state is not checkpoint/restored.
type uverbsFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	hostFD     int32
	queue      waiter.Queue
	memmapFile fsutil.MmapNoInternalFile

	// driver is the per-vendor plug-in inherited from the originating
	// uverbsDevice at Open time. Always non-nil; see uverbsDevice.driver.
	driver Driver

	// pinned tracks app memory mirrored on behalf of MRs, CQs, and QPs
	// registered or created through this uverbs FD.
	pinned pinnedResources
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *uverbsFD) Release(ctx context.Context) {
	fd.pinned.releaseAll(ctx)
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

// Register registers a proxied uverbs device with the VFS at the fixed uverbs
// char-device major (ib.IB_UVERBS_MAJOR) and the given minor. devName is the
// device filename (e.g. "uverbs0").
//
// driverName is the host PCI driver name (typically the DRIVER= field of
// /sys/class/infiniband/<ibdev>/device/uevent, e.g. "mlx5_core") used to look
// up the vendor plug-in via LookupDriver. If it is empty or names a driver we
// do not model, registration fails: the plug-in is required to safely mirror
// CQ/QP DMA buffers, so a device without one cannot be proxied.
//
// The host RoCE netdev backing each uverbs device is expected to be moved,
// fully configured, into the sandbox netns before the application connects
// QPs. Upstream ib_core would resolve RoCE addressing in whichever netns the
// netdev lives, but MLNX_OFED's ib_core requires the source GID's netdev to
// be in the ioctl caller's netns (rdma_check_gid_user_access; ENODEV at
// MODIFY_QP otherwise), and the sentry issues the ioctls from the sandbox
// netns. The sentry needs no setns or extra capabilities.
//
// verbsABIVersion is the host's IB_USER_VERBS_ABI_VERSION collected host-side
// before the sandbox started. An empty string means it could not be collected.
func Register(vfsObj *vfs.VirtualFilesystem, devName string, minor uint32, driverName, verbsABIVersion string) error {
	// Validate the kernel uverbs ABI version. A mismatch means the kernel
	// ships an unfamiliar UVERBS interface (refuse rather than risk
	// misinterpreting attribute layouts).
	if v, err := strconv.Atoi(strings.TrimSpace(verbsABIVersion)); err != nil {
		return fmt.Errorf("rdmaproxy: no usable uverbs ABI version (collected %q from %s/abi_version); proceeding without ABI check — expected version %d", verbsABIVersion, uverbsClassDir, expectedUverbsABIVersion)
	} else if v != expectedUverbsABIVersion {
		return fmt.Errorf("rdmaproxy: kernel uverbs ABI version %d does not match expected %d (collected from %s/abi_version) — refusing to register %s", v, expectedUverbsABIVersion, uverbsClassDir, devName)
	}

	driver := LookupDriver(driverName)
	if driver == nil {
		return fmt.Errorf("rdmaproxy: no vendor plug-in for driver %q — refusing to register %s (supported: %v)", driverName, devName, RegisteredDrivers())
	}
	log.Infof("rdmaproxy: registering %s with major=%d minor=%d driver=%s (requested=%q)", devName, ib.IB_UVERBS_MAJOR, minor, driver.Name(), driverName)
	return vfsObj.RegisterDevice(vfs.CharDevice, ib.IB_UVERBS_MAJOR, minor, &uverbsDevice{devName: devName, driver: driver}, &vfs.RegisterDeviceOptions{
		GroupName: "infiniband",
		Pathname:  filepath.Join("infiniband", devName),
		FilePerms: 0666,
	})
}

// asyncEventFD wraps a host FD for RDMA async event delivery. The kernel
// creates this FD via UVERBS_METHOD_ASYNC_EVENT_ALLOC; rdma-core reads async
// events from it via read(2). Input FD attributes referencing an async event
// (CQ/QP EVENT_FD) are translated back to this host FD at ioctl time by
// resolving the app FD through the task's FD table, which correctly handles
// FD-number recycling across application processes.
type asyncEventFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFD int32
	queue  waiter.Queue
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *asyncEventFD) Release(ctx context.Context) {
	fdnotifier.RemoveFD(fd.hostFD)
	unix.Close(int(fd.hostFD))
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *asyncEventFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *asyncEventFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *asyncEventFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// newAsyncEventFD wraps a host async-event FD in a sentry FileDescription and
// installs it in the task's FD table. Returns the app FD number.
// newAsyncEventFD takes ownership of hostFD. On success, hostFD ownership is
// transferred to the asyncEventFD.
func newAsyncEventFD(t *kernel.Task, hostFD int) (int32, error) {
	vfsObj := t.Kernel().VFS()
	vd := vfsObj.NewAnonVirtualDentry("[rdma-async-event]")
	defer vd.DecRef(t)

	if err := unix.SetNonblock(hostFD, true); err != nil {
		unix.Close(hostFD)
		return -1, fmt.Errorf("SetNonblock: %w", err)
	}

	afd := &asyncEventFD{
		hostFD: int32(hostFD),
	}
	if err := fdnotifier.AddFD(afd.hostFD, &afd.queue); err != nil {
		unix.Close(hostFD)
		return -1, err
	}
	if err := afd.vfsfd.Init(afd, linux.O_RDONLY, t.Credentials(), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		fdnotifier.RemoveFD(afd.hostFD)
		unix.Close(hostFD)
		return -1, err
	}
	// From here hostFD ownership is transferred to afd.
	defer afd.vfsfd.DecRef(t)

	appFD, err := t.NewFDFrom(0, &afd.vfsfd, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return -1, err
	}
	return appFD, nil
}
