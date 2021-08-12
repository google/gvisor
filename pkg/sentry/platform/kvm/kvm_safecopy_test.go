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

// FIXME(gvisor.dev/issue//6629): These tests don't pass on ARM64.
//
//go:build amd64
// +build amd64

package kvm

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safecopy"
)

func testSafecopy(t *testing.T, mapSize uintptr, fileSize uintptr, testFunc func(t *testing.T, c *vCPU, addr uintptr)) {
	memfd, err := memutil.CreateMemFD(fmt.Sprintf("kvm_test_%d", os.Getpid()), 0)
	if err != nil {
		t.Errorf("error creating memfd: %v", err)
	}

	memfile := os.NewFile(uintptr(memfd), "kvm_test")
	memfile.Truncate(int64(fileSize))
	kvmTest(t, nil, func(c *vCPU) bool {
		const n = 10
		mappings := make([]uintptr, n)
		defer func() {
			for i := 0; i < n && mappings[i] != 0; i++ {
				unix.RawSyscall(
					unix.SYS_MUNMAP,
					mappings[i], mapSize, 0)
			}
		}()
		for i := 0; i < n; i++ {
			addr, _, errno := unix.RawSyscall6(
				unix.SYS_MMAP,
				0,
				mapSize,
				unix.PROT_READ|unix.PROT_WRITE,
				unix.MAP_SHARED|unix.MAP_FILE,
				uintptr(memfile.Fd()),
				0)
			if errno != 0 {
				t.Errorf("error mapping file: %v", errno)
			}
			mappings[i] = addr
			testFunc(t, c, addr)
		}
		return false
	})
}

func TestSafecopySigbus(t *testing.T) {
	mapSize := uintptr(faultBlockSize)
	fileSize := mapSize - hostarch.PageSize
	buf := make([]byte, hostarch.PageSize)
	testSafecopy(t, mapSize, fileSize, func(t *testing.T, c *vCPU, addr uintptr) {
		want := safecopy.BusError{addr + fileSize}
		bluepill(c)
		_, err := safecopy.CopyIn(buf, unsafe.Pointer(addr+fileSize))
		if err != want {
			t.Errorf("expected error: got %v, want %v", err, want)
		}
	})
}

func TestSafecopy(t *testing.T) {
	mapSize := uintptr(faultBlockSize)
	fileSize := mapSize
	testSafecopy(t, mapSize, fileSize, func(t *testing.T, c *vCPU, addr uintptr) {
		want := uint32(0x12345678)
		bluepill(c)
		_, err := safecopy.SwapUint32(unsafe.Pointer(addr+fileSize-8), want)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		bluepill(c)
		val, err := safecopy.LoadUint32(unsafe.Pointer(addr + fileSize - 8))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if val != want {
			t.Errorf("incorrect value: got %x, want %x", val, want)
		}
	})
}

