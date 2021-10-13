// Copyright 2018 The gVisor Authors.
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

package sharedmem

import (
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/memutil"
)

// sharedDataPointer converts the shared data slice into a pointer so that it
// can be used in atomic operations.
func sharedDataPointer(sharedData []byte) *uint32 {
	return (*uint32)(unsafe.Pointer(&sharedData[0:4][0]))
}

// getBuffer returns a memory region mapped to the full contents of the given
// file descriptor.
func getBuffer(fd int) ([]byte, error) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return nil, err
	}

	// Check that size doesn't overflow an int.
	if s.Size > int64(^uint(0)>>1) {
		return nil, unix.EDOM
	}

	addr, err := memutil.MapFile(0 /* addr */, uintptr(s.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FILE, uintptr(fd), 0 /*offset*/)
	if err != nil {
		return nil, fmt.Errorf("failed to map memory for buffer fd: %d, error: %s", fd, err)
	}

	// Use unsafe to conver addr into a []byte.
	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	hdr.Data = addr
	hdr.Len = int(s.Size)
	hdr.Cap = int(s.Size)

	return b, nil
}
