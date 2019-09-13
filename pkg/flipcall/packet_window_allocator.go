// Copyright 2019 The gVisor Authors.
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

package flipcall

import (
	"fmt"
	"math/bits"
	"os"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/memutil"
)

var (
	pageSize = os.Getpagesize()
	pageMask = pageSize - 1
)

func init() {
	if bits.OnesCount(uint(pageSize)) != 1 {
		// This is depended on by roundUpToPage().
		panic(fmt.Sprintf("system page size (%d) is not a power of 2", pageSize))
	}
	if uintptr(pageSize) < PacketHeaderBytes {
		// This is required since Endpoint.Init() imposes a minimum packet
		// window size of 1 page.
		panic(fmt.Sprintf("system page size (%d) is less than packet header size (%d)", pageSize, PacketHeaderBytes))
	}
}

// PacketWindowDescriptor represents a packet window, a range of pages in a
// shared memory file that is used to exchange packets between partner
// Endpoints.
type PacketWindowDescriptor struct {
	// FD is the file descriptor representing the shared memory file.
	FD int

	// Offset is the offset into the shared memory file at which the packet
	// window begins.
	Offset int64

	// Length is the size of the packet window in bytes.
	Length int
}

// PacketWindowLengthForDataCap returns the minimum packet window size required
// to accommodate datagrams of the given size in bytes.
func PacketWindowLengthForDataCap(dataCap uint32) int {
	return roundUpToPage(int(dataCap) + int(PacketHeaderBytes))
}

func roundUpToPage(x int) int {
	return (x + pageMask) &^ pageMask
}

// A PacketWindowAllocator owns a shared memory file, and allocates packet
// windows from it.
type PacketWindowAllocator struct {
	fd        int
	nextAlloc int64
	fileSize  int64
}

// Init must be called on zero-value PacketWindowAllocators before first use.
// If it succeeds, Destroy() must be called once the PacketWindowAllocator is
// no longer in use.
func (pwa *PacketWindowAllocator) Init() error {
	fd, err := memutil.CreateMemFD("flipcall_packet_windows", linux.MFD_CLOEXEC|linux.MFD_ALLOW_SEALING)
	if err != nil {
		return fmt.Errorf("failed to create memfd: %v", err)
	}
	// Apply F_SEAL_SHRINK to prevent either party from causing SIGBUS in the
	// other by truncating the file, and F_SEAL_SEAL to prevent either party
	// from applying F_SEAL_GROW or F_SEAL_WRITE.
	if _, _, e := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), linux.F_ADD_SEALS, linux.F_SEAL_SHRINK|linux.F_SEAL_SEAL); e != 0 {
		syscall.Close(fd)
		return fmt.Errorf("failed to apply memfd seals: %v", e)
	}
	pwa.fd = fd
	return nil
}

// NewPacketWindowAllocator is a convenience function that returns an
// initialized PacketWindowAllocator allocated on the heap.
func NewPacketWindowAllocator() (*PacketWindowAllocator, error) {
	var pwa PacketWindowAllocator
	if err := pwa.Init(); err != nil {
		return nil, err
	}
	return &pwa, nil
}

// Destroy releases resources owned by pwa. This invalidates file descriptors
// previously returned by pwa.FD() and pwd.Allocate().
func (pwa *PacketWindowAllocator) Destroy() {
	syscall.Close(pwa.fd)
}

// FD represents the file descriptor of the shared memory file backing pwa.
func (pwa *PacketWindowAllocator) FD() int {
	return pwa.fd
}

// Allocate allocates a new packet window of at least the given size and
// returns a PacketWindowDescriptor representing it.
//
// Preconditions: size > 0.
func (pwa *PacketWindowAllocator) Allocate(size int) (PacketWindowDescriptor, error) {
	if size <= 0 {
		return PacketWindowDescriptor{}, fmt.Errorf("invalid size: %d", size)
	}
	// Page-align size to ensure that pwa.nextAlloc remains page-aligned.
	size = roundUpToPage(size)
	if size <= 0 {
		return PacketWindowDescriptor{}, fmt.Errorf("size %d overflows after rounding up to page size", size)
	}
	end := pwa.nextAlloc + int64(size) // overflow checked by ensureFileSize
	if err := pwa.ensureFileSize(end); err != nil {
		return PacketWindowDescriptor{}, err
	}
	start := pwa.nextAlloc
	pwa.nextAlloc = end
	return PacketWindowDescriptor{
		FD:     pwa.fd,
		Offset: start,
		Length: size,
	}, nil
}

func (pwa *PacketWindowAllocator) ensureFileSize(min int64) error {
	if min <= 0 {
		return fmt.Errorf("file size would overflow")
	}
	if pwa.fileSize >= min {
		return nil
	}
	newSize := 2 * pwa.fileSize
	if newSize == 0 {
		newSize = int64(pageSize)
	}
	for newSize < min {
		newNewSize := newSize * 2
		if newNewSize <= 0 {
			return fmt.Errorf("file size would overflow")
		}
		newSize = newNewSize
	}
	if err := syscall.Ftruncate(pwa.fd, newSize); err != nil {
		return fmt.Errorf("ftruncate failed: %v", err)
	}
	pwa.fileSize = newSize
	return nil
}
