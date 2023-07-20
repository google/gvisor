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

// Package accel implements proxying for hardware accelerators.
package accel

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// accelFD implements vfs.FileDescriptionImpl for /dev/accel[0-9]+.
//
// accelFD is not savable; we do not implement save/restore of accelerator
// state.
type accelFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *accelFD) Release(context.Context) {
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *accelFD) EventRegister(e *waiter.Entry) error {
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *accelFD) EventUnregister(e *waiter.Entry) {
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *accelFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return waiter.EventErr
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *accelFD) Epollable() bool {
	return true
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *accelFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.ENOSYS
}
