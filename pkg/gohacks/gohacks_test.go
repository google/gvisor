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
	"runtime/debug"
	"testing"
	"time"

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
