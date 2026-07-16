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
// # Host ABI requirements
//
// The proxy targets the modern UVERBS ioctl interface (RDMA_VERBS_IOCTL =
// _IOWR(0x1b, 1, struct ib_uverbs_ioctl_hdr)). Minimum supported host
// kernel is Linux 4.20 (released Dec 2018), which is when
// include/uapi/rdma/ib_user_ioctl_cmds.h had reached mainline along with
// the object/method/attribute IDs the proxy hardcodes; older kernels may
// expose a partial or differently-numbered subset and are not supported.
// Per upstream policy these IDs are additive only — old IDs are never
// repurposed — so newer kernels remain compatible.
//
// At Register time the proxy reads the kernel's IB_USER_VERBS_ABI_VERSION
// from /sys/class/infiniband_verbs/abi_version and refuses to attach if it
// does not match the expected value. This file has been part of the stable
// sysfs ABI since v2.6.14 (Sept 2005) and the value has been frozen at 6
// since the early kernel.org era; the kernel only bumps it on a userspace-
// breaking change. Per-device driver-specific ABI versions exposed at
// /sys/class/infiniband_verbs/uverbsN/abi_version are logged for telemetry
// but not gated on (driver plug-ins may impose their own checks).
package rdmaproxy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
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

// expectedUverbsABIVersion is the value of IB_USER_VERBS_ABI_VERSION the
// proxy is built against. The kernel publishes its value at
// /sys/class/infiniband_verbs/abi_version and bumps it only on a
// userspace-breaking change to the uverbs interface. Frozen at 6 in
// upstream Linux for over a decade.
const expectedUverbsABIVersion = 6

// uverbsClassDir is the sysfs class directory for the uverbs subsystem,
// where the host kernel publishes the class-wide abi_version. The sentry
// cannot read it directly (it runs chrooted and seccomp-confined), so the
// value is collected host-side by runsc create (see
// sys.CollectRDMADeviceData) and passed to Register.
const uverbsClassDir = "/sys/class/infiniband_verbs"

// uverbsDevice implements vfs.Device for /dev/infiniband/uverbs*.
type uverbsDevice struct {
	// devName is the device filename, e.g. "uverbs0". This is distinct
	// from the kernel minor number (e.g. 192) used for VFS registration.
	devName string
	// driver is the per-vendor plug-in attached to this device, looked
	// up by name at Register time. May be nil if no driver is registered
	// for the host's PCI driver, in which case CQ/QP CREATE ioctls will
	// be forwarded without DMA buffer mirroring (and a warning is
	// logged).
	driver Driver
}

// Open implements vfs.Device.Open.
func (dev *uverbsDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	devRelPath := filepath.Join("infiniband", dev.devName)
	hostFD, err := openHostDevice(ctx, devRelPath, opts.Flags)
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

// openHostDevice opens a host device using the dev gofer if available,
// falling back to a direct open. devRelPath is relative to /dev/.
func openHostDevice(ctx context.Context, devRelPath string, flags uint32) (int, error) {
	if client := devutil.GoferClientFromContext(ctx); client != nil {
		return client.OpenAt(ctx, devRelPath, flags)
	}
	devPath := filepath.Join("/dev", devRelPath)
	openFlags := int(flags&unix.O_ACCMODE | unix.O_NOFOLLOW)
	return unix.Openat(-1, devPath, openFlags, 0)
}

// MirroredPages tracks sandbox pages pinned and mapped into the sentry's
// address space so the host kernel can pin_user_pages on them for DMA.
//
// Drivers receive this as an opaque return value from MirrorSandboxPages
// and store it in PinnedDMABufs; they do not inspect its fields directly.
type MirroredPages struct {
	prs []mm.PinnedRange
	// If m != 0, it's a sentry-side mmap we own and must munmap on release.
	m   uintptr
	len uintptr
	// mrSummary is an optional compact registration summary emitted once the
	// host returns an MR handle successfully.
	mrSummary string
}

// Release tears down the sentry-side mapping and unpins the underlying
// sandbox pages.
func (mp *MirroredPages) Release(ctx context.Context) {
	if mp.m != 0 {
		if _, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, mp.m, mp.len, 0); errno != 0 {
			log.Warningf("rdmaproxy: munmap %#x-%#x: %v", mp.m, mp.m+mp.len, errno)
		}
	}
	mm.Unpin(mp.prs)
}

// PinnedDMABufs tracks the buf + doorbell mirrors for a single CQ or QP.
// Driver plug-ins return this from PrepareCQQPCreate; the core stores it
// against the resulting CQ/QP IDR handle until DESTROY.
type PinnedDMABufs struct {
	// Buf is the work-queue buffer mirror, or nil if the driver did not
	// produce one.
	Buf *MirroredPages
	// DB is the doorbell page mirror, or nil if the driver did not
	// produce one.
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

// pinnedResources tracks the sandbox memory mirrored on behalf of one
// uverbs FD's MRs/CQs/QPs. Handles are scoped to the uverbs context (the
// underlying host FD), so this state lives per-uverbsFD rather than in a
// global registry — see the package docs for why a registry keyed on
// sandbox FD numbers would race with FD recycling.
type pinnedResources struct {
	mu  sync.Mutex
	mrs map[uint32]*MirroredPages
	cqs map[uint32]*PinnedDMABufs
	qps map[uint32]*PinnedDMABufs
}

// addMR records the page mirror for a successful REG_MR. Overwrites any
// existing entry for the same handle (the kernel does not reuse handles
// without an intervening DEREG, so this is just defensive).
func (p *pinnedResources) addMR(handle uint32, mp *MirroredPages) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mrs == nil {
		p.mrs = make(map[uint32]*MirroredPages)
	}
	p.mrs[handle] = mp
}

// addCQ records the buf+db mirrors for a successful CQ CREATE.
func (p *pinnedResources) addCQ(handle uint32, bufs *PinnedDMABufs) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cqs == nil {
		p.cqs = make(map[uint32]*PinnedDMABufs)
	}
	p.cqs[handle] = bufs
}

// addQP records the buf+db mirrors for a successful QP CREATE.
func (p *pinnedResources) addQP(handle uint32, bufs *PinnedDMABufs) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.qps == nil {
		p.qps = make(map[uint32]*PinnedDMABufs)
	}
	p.qps[handle] = bufs
}

// takeMR removes and returns the mirror for handle, or nil if absent.
// The caller must release the returned mirror outside any lock.
func (p *pinnedResources) takeMR(handle uint32) *MirroredPages {
	p.mu.Lock()
	defer p.mu.Unlock()
	mp, ok := p.mrs[handle]
	if !ok {
		return nil
	}
	delete(p.mrs, handle)
	return mp
}

// takeCQ removes and returns the bufs for handle, or nil if absent.
func (p *pinnedResources) takeCQ(handle uint32) *PinnedDMABufs {
	p.mu.Lock()
	defer p.mu.Unlock()
	bufs, ok := p.cqs[handle]
	if !ok {
		return nil
	}
	delete(p.cqs, handle)
	return bufs
}

// takeQP removes and returns the bufs for handle, or nil if absent.
func (p *pinnedResources) takeQP(handle uint32) *PinnedDMABufs {
	p.mu.Lock()
	defer p.mu.Unlock()
	bufs, ok := p.qps[handle]
	if !ok {
		return nil
	}
	delete(p.qps, handle)
	return bufs
}

// releaseAll drains every tracked mirror and releases the underlying
// pages. Used as a safety net at FD close for handles the application
// neglected to DEREG/DESTROY. Subsequent calls are no-ops.
func (p *pinnedResources) releaseAll(ctx context.Context) {
	p.mu.Lock()
	mrs, cqs, qps := p.mrs, p.cqs, p.qps
	p.mrs, p.cqs, p.qps = nil, nil, nil
	p.mu.Unlock()
	for _, mp := range mrs {
		mp.Release(ctx)
	}
	for _, bufs := range cqs {
		bufs.Release(ctx)
	}
	for _, bufs := range qps {
		bufs.Release(ctx)
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

	// driver is the per-vendor plug-in inherited from the originating
	// uverbsDevice, set at Open time. May be nil; see uverbsDevice.driver.
	driver Driver

	// pinned tracks sandbox memory mirrored on behalf of MRs, CQs, and QPs
	// registered or created through this uverbs FD. Entries are added on
	// successful REG/CREATE ioctls and drained on the matching DEREG/DESTROY,
	// or in Release as a safety net.
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

// Register registers a uverbs device with the VFS and returns the dynamic
// major number. devName is the device filename (e.g. "uverbs0"), minor is
// the kernel device minor number (e.g. 192).
//
// driverName is the host PCI driver name (typically read from
// /sys/class/infiniband/<ibdev>/device/uevent's DRIVER= field, e.g.
// "mlx5_core") used to look up the vendor-specific plug-in via
// LookupDriver. If driverName is empty or unrecognized, CQ/QP CREATE
// ioctls on this device will be forwarded without DMA buffer mirroring
// and a warning will be logged at ioctl time.
//
// The host RoCE netdev that backs each uverbs device is expected to have
// been moved into the sandbox netns by the runsc-create parent process
// (see runsc/sandbox.MoveRDMANetdevsIntoSandbox). With the netdev local to
// the calling task's netns, ibv_modify_qp's GID-to-netdev resolution
// succeeds without any setns or extra capabilities in the sentry.
// verbsABIVersion is the host's IB_USER_VERBS_ABI_VERSION as collected
// host-side from uverbsClassDir/abi_version before the sandbox started
// (the sentry itself cannot read sysfs). An empty string means the value
// could not be collected.
func Register(vfsObj *vfs.VirtualFilesystem, devName string, minor uint32, driverName, verbsABIVersion string) (uint32, error) {
	// Validate the kernel uverbs ABI version against what the proxy was
	// built for. A mismatch here means the kernel either ships an
	// unfamiliar UVERBS interface (we should refuse rather than risk
	// misinterpreting attribute layouts) or the value is missing (we
	// degrade to a warning, not a hard failure, since the file has been
	// stable in sysfs for over a decade and any absence likely means the
	// uverbs subsystem isn't loaded — letting the open succeed and fail
	// later gives a clearer error than refusing here).
	if v, err := strconv.Atoi(strings.TrimSpace(verbsABIVersion)); err != nil {
		log.Warningf("rdmaproxy: no usable uverbs ABI version (collected %q from %s/abi_version); proceeding without ABI check — expected version %d", verbsABIVersion, uverbsClassDir, expectedUverbsABIVersion)
	} else if v != expectedUverbsABIVersion {
		return 0, fmt.Errorf("rdmaproxy: kernel uverbs ABI version %d does not match expected %d (collected from %s/abi_version) — refusing to register %s", v, expectedUverbsABIVersion, uverbsClassDir, devName)
	}

	major, err := vfsObj.GetDynamicCharDevMajor()
	if err != nil {
		return 0, fmt.Errorf("rdmaproxy: obtaining dynamic major number: %w", err)
	}
	driver := LookupDriver(driverName)
	driverDesc := "<none>"
	if driver != nil {
		driverDesc = driver.Name()
	}
	log.Infof("rdmaproxy: registering %s with major=%d minor=%d driver=%s (requested=%q)", devName, major, minor, driverDesc, driverName)
	if err := vfsObj.RegisterDevice(vfs.CharDevice, major, minor, &uverbsDevice{devName: devName, driver: driver}, &vfs.RegisterDeviceOptions{
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

// Async event FD rewriting is done per-task by resolving sandbox FDs
// through the task's FD table at ioctl time (see handleRDMAVerbsIoctl).
// This correctly handles FD number recycling across sandbox processes.

// asyncEventFD wraps a host FD for RDMA async event delivery.
// The kernel creates this FD via UVERBS_METHOD_ASYNC_EVENT_ALLOC;
// rdma-core reads async events from it via read(2).
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

// newAsyncEventFD wraps a host async-event FD in a sentry FileDescription
// and installs it in the task's FD table. Returns the sandbox FD number.
func newAsyncEventFD(t *kernel.Task, hostFD int) (int32, error) {
	vfsObj := t.Kernel().VFS()
	vd := vfsObj.NewAnonVirtualDentry("[rdma-async-event]")
	defer vd.DecRef(t)

	if err := unix.SetNonblock(hostFD, true); err != nil {
		return -1, fmt.Errorf("SetNonblock: %w", err)
	}

	afd := &asyncEventFD{
		hostFD: int32(hostFD),
	}
	if err := fdnotifier.AddFD(afd.hostFD, &afd.queue); err != nil {
		return -1, err
	}
	if err := afd.vfsfd.Init(afd, linux.O_RDONLY, t.Credentials(), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		fdnotifier.RemoveFD(afd.hostFD)
		return -1, err
	}
	sentryFD, err := t.NewFDFrom(0, &afd.vfsfd, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		afd.vfsfd.DecRef(t)
		return -1, err
	}
	return sentryFD, nil
}
