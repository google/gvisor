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

package gohacks

import (
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func randBuf(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// Size of a page in bytes. Cloned from hostarch.PageSize to avoid a circular
// dependency.
const pageSize = 4096

func testCopy(dst, src []byte) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	debug.SetPanicOnFault(true)
	copy(dst, src)
	return panicked
}

func TestSegVOnMemmove(t *testing.T) {
	// Test that SIGSEGVs received by runtime.memmove when *not* doing
	// CopyIn or CopyOut work gets propagated to the runtime.
	const bufLen = pageSize
	a, err := unix.Mmap(-1, 0, bufLen, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)

	}
	defer unix.Munmap(a)
	b := randBuf(bufLen)

	if !testCopy(b, a) {
		t.Fatalf("testCopy didn't panic when it should have")
	}

	if !testCopy(a, b) {
		t.Fatalf("testCopy didn't panic when it should have")
	}
}

func TestSigbusOnMemmove(t *testing.T) {
	// Test that SIGBUS received by runtime.memmove when *not* doing
	// CopyIn or CopyOut work gets propagated to the runtime.
	const bufLen = pageSize
	f, err := ioutil.TempFile("", "sigbus_test")
	if err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}
	os.Remove(f.Name())
	defer f.Close()

	a, err := unix.Mmap(int(f.Fd()), 0, bufLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)

	}
	defer unix.Munmap(a)
	b := randBuf(bufLen)

	if !testCopy(b, a) {
		t.Fatalf("testCopy didn't panic when it should have")
	}

	if !testCopy(a, b) {
		t.Fatalf("testCopy didn't panic when it should have")
	}
}

func TestNanotime(t *testing.T) {
	// Verify that nanotime increases over time.
	nano1 := Nanotime()
	time.Sleep(10 * time.Millisecond)
	nano2 := Nanotime()
	if nano2 <= nano1 {
		t.Errorf("runtime.nanotime() did not increase after 10ms: %d vs %d", nano1, nano2)
	}
}

// +checkescape:heap
//
//go:noinline
func NoescapeAlloc() unsafe.Pointer {
	// This is obviously quite dangerous, and we presumably return a pointer to a
	// 16-byte object that is allocated on the local stack. This pointer should
	// never be used for anything (or saved anywhere). The function is exported
	// and marked as noinline in order to ensure that it is still defined as is.
	var m [16]byte // 16-byte object.
	return Noescape(unsafe.Pointer(&m))
}

// ptrs is used to ensure that when the compiler is analyzing TestNoescape, it
// cannot simply eliminate the entire relevant block of code, realizing that it
// does not have any side effects. This is much harder with a global, unless
// the compiler implements whole program analysis.
var ptrs [1024]uintptr

func TestNoescape(t *testing.T) {
	var (
		beforeStats runtime.MemStats
		afterStats  runtime.MemStats
	)

	// Ensure referenced objects don't escape.
	runtime.ReadMemStats(&beforeStats)
	for i := 0; i < len(ptrs); i++ {
		ptrs[i] = uintptr(NoescapeAlloc())
	}
	runtime.ReadMemStats(&afterStats)

	// Count the mallocs to check if it escaped.
	if afterStats.Mallocs-beforeStats.Mallocs >= uint64(len(ptrs)) {
		t.Errorf("Noescape did not prevent escapes to the heap")
	}

	// Use ptrs to ensure the loop above isn't optimized out. As noted above,
	// this is already quite difficult with the global, but we may as well make
	// it slightly harder by introducing a sanity check for the values here.
	for _, p := range ptrs {
		if p == 0 {
			t.Errorf("got nil ptr, expected non-nil")
		}
	}
}
