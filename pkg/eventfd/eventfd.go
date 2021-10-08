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
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
)

const sizeofUint64 = 8

// Eventfd represents a Linux eventfd object.
type Eventfd struct {
	fd int
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
	return Eventfd{int(fd)}, nil
}

// Wrap returns an initialized Eventfd using the provided fd.
func Wrap(fd int) Eventfd {
	return Eventfd{fd}
}

// Close closes the eventfd, after which it should not be used.
func (ev Eventfd) Close() error {
	return unix.Close(ev.fd)
}

// Dup copies the eventfd, calling dup(2) on the underlying file descriptor.
func (ev Eventfd) Dup() (Eventfd, error) {
	other, err := unix.Dup(ev.fd)
	if err != nil {
		return Eventfd{}, fmt.Errorf("failed to dup: %v", other)
	}
	return Eventfd{other}, nil
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
	for {
		n, err := unix.Write(ev.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if n != sizeofUint64 {
			panic(fmt.Sprintf("short write to eventfd: got %d bytes, wanted %d", n, sizeofUint64))
		}
		return err
	}
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
	n, err := rawfile.BlockingReadUntranslated(ev.fd, tmp[:])
	if err != 0 {
		return 0, err
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
