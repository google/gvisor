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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

type rdmaFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
	memmap.MappableNoTrackMappings

	hostFD int32

	device     *rdmaDevice
	queue      waiter.Queue
	memmapFile fsutil.MmapNoInternalFile

	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	mrPins map[uint32][]mm.PinnedRange
}

func (fd *rdmaFD) isRestored() bool {
	return fd.hostFD == -1
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *rdmaFD) Release(context.Context) {
	if fd.isRestored() {
		return
	}
	fd.unpinAll()
	fdnotifier.RemoveFD(fd.hostFD)
	fd.queue.Notify(waiter.EventHUp)
	fd.memmapFile.Closer = &fd.memmapFile
	fd.memmapFile.MappableRelease() // eventually closes fd.hostFD
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *rdmaFD) EventRegister(e *waiter.Entry) error {
	if fd.isRestored() {
		return nil
	}
	fd.queue.EventRegister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		fd.queue.EventUnregister(e)
		return err
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *rdmaFD) EventUnregister(e *waiter.Entry) {
	if fd.isRestored() {
		return
	}
	fd.queue.EventUnregister(e)
	if err := fdnotifier.UpdateFD(fd.hostFD); err != nil {
		panic(fmt.Sprint("UpdateFD:", err))
	}
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *rdmaFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if fd.isRestored() {
		return 0
	}
	return fdnotifier.NonBlockingPoll(fd.hostFD, mask)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *rdmaFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
//
// The ioctl-based uverbs interface is not yet supported. Returning ENOTTY tells
// rdma-core that the ioctl framework is entirely absent, causing it to fall
// back to the legacy write() command ABI for all verbs (see
// _execute_ioctl_fallback() in rdma-core's libibverbs/cmd_fallback.c), which
// is proxied by Write in rdma_fd_write.go.
func (fd *rdmaFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.ENOTTY
}
