// Copyright 2021 The gVisor Authors.
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

// Package eventfd wraps Linux's eventfd(2) syscall.
package eventfd

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/safecopy"
)

const sizeofUint64 = 8

// Eventfd represents a Linux eventfd object.
type Eventfd struct {
	fd       int
	mmioAddr uintptr
	mmioCtrl MMIOController
}

// Create returns an initialized eventfd.
func Create() (Eventfd, error) {
	fd, _, err := unix.RawSyscall(unix.SYS_EVENTFD2, 0, 0, 0)
	if err != 0 {
		return Eventfd{}, fmt.Errorf("failed to create eventfd: %v", error(err))
	}
	if err := unix.SetNonblock(int(fd), true); err != nil {
		unix.Close(int(fd))
		return Eventfd{}, err
	}
	return Eventfd{fd: int(fd)}, nil
}

// Wrap returns an initialized Eventfd using the provided fd.
func Wrap(fd int) Eventfd {
	return Eventfd{fd: fd}
}

// Close closes the eventfd, after which it should not be used.
func (ev Eventfd) Close() error {
	if ev.mmioCtrl != nil {
		ev.mmioCtrl.Close(ev)
	}
	return unix.Close(ev.fd)
}

// Dup copies the eventfd, calling dup(2) on the underlying file descriptor.
func (ev Eventfd) Dup() (Eventfd, error) {
	other, err := unix.Dup(ev.fd)
	if err != nil {
		return Eventfd{}, fmt.Errorf("failed to dup: %v", other)
	}
	return Eventfd{fd: other}, nil
}

// Notify alerts other users of the eventfd. Users can receive alerts by
// calling Wait or Read.
func (ev Eventfd) Notify() error {
	return ev.Write(1)
}

// Write writes a specific value to the eventfd.
func (ev Eventfd) Write(val uint64) error {
	var buf [sizeofUint64]byte
	hostarch.ByteOrder.PutUint64(buf[:], val)
	if ev.mmioAddr != 0 && ev.mmioCtrl.Enabled() {
		if _, err := safecopy.CopyOut(ev.mmioPtr(), buf[:]); err == nil {
			return nil
		}
		// Fall back to using a syscall.
	}
	for {
		n, err := nonBlockingWrite(ev.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != sizeofUint64 {
			panic(fmt.Sprintf("bad write to eventfd: got %d bytes, wanted %d with error %v", n, sizeofUint64, err))
		}
		return err
	}
}

// MMIOWrite is equivalent to Write, but returns an error if the write cannot be
// implemented by writing to the address set by EnableMMIO. This is primarily
// useful for testing.
func (ev Eventfd) MMIOWrite(val uint64) error {
	var buf [sizeofUint64]byte
	hostarch.ByteOrder.PutUint64(buf[:], val)
	if ev.mmioAddr == 0 {
		return fmt.Errorf("no MMIO address set")
	}
	if !ev.mmioCtrl.Enabled() {
		return fmt.Errorf("MMIO is temporarily disabled")
	}
	_, err := safecopy.CopyOut(ev.mmioPtr(), buf[:])
	return err
}

// Wait blocks until eventfd is non-zero (i.e. someone calls Notify or Write).
func (ev Eventfd) Wait() error {
	_, err := ev.Read()
	return err
}

// Read blocks until eventfd is non-zero (i.e. someone calls Notify or Write)
// and returns the value read.
func (ev Eventfd) Read() (uint64, error) {
	var tmp [sizeofUint64]byte
	n, errno := rawfile.BlockingRead(ev.fd, tmp[:])
	if errno != 0 {
		return 0, errno
	}
	if n == 0 {
		return 0, io.EOF
	}
	if n != sizeofUint64 {
		panic(fmt.Sprintf("short read from eventfd: got %d bytes, wanted %d", n, sizeofUint64))
	}
	return hostarch.ByteOrder.Uint64(tmp[:]), nil
}

// FD returns the underlying file descriptor. Use with care, as this breaks the
// Eventfd abstraction.
func (ev Eventfd) FD() int {
	return ev.fd
}

// MMIOController controls eventfd memory-mapped I/O.
type MMIOController interface {
	// Enabled returns true if writing to the associated MMIO address can
	// succeed. This is inherently racy, so if the memory-mapped write faults,
	// the eventfd will fall back to writing using a syscall.
	Enabled() bool

	// Close is called when the associated Eventfd is closed.
	Close(ev Eventfd)
}

// EnableMMIO causes future calls to ev.Write() to use memory-mapped writes to
// addr, subject to ctrl. EnableMMIO cannot be called concurrently with Write,
// MMIOWrite, or MMIOAddr.
//
// This feature is used to support KVM ioeventfds. Since this requires that
// addr is mapped read-only or with no permissions in the host virtual address
// space (so that writes in host mode fault), it cannot reasonably be
// Go-managed memory, so it's safe to type as uintptr rather than a pointer.
func (ev *Eventfd) EnableMMIO(addr uintptr, ctrl MMIOController) {
	ev.mmioAddr = addr
	ev.mmioCtrl = ctrl
}

// DisableMMIO undoes the effect of a previous call to EnableMMIO. DisableMMIO
// cannot be called concurrently with Write, MMIOWrite, or MMIOAddr.
func (ev *Eventfd) DisableMMIO() {
	ev.mmioAddr = 0
	ev.mmioCtrl = nil
}

// MMIOAddr returns the address set by the last call to EnableMMIO.
func (ev Eventfd) MMIOAddr() uintptr {
	return ev.mmioAddr
}
