// Copyright 2018 Google Inc.
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

package safecopy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime/debug"
	"syscall"
	"testing"
	"unsafe"
)

// Size of a page in bytes. Cloned from usermem.PageSize to avoid a circular
// dependency.
const pageSize = 4096

func initRandom(b []byte) {
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
}

func randBuf(size int) []byte {
	b := make([]byte, size)
	initRandom(b)
	return b
}

func TestCopyInSuccess(t *testing.T) {
	// Test that CopyIn does not return an error when all pages are accessible.
	const bufLen = 8192
	a := randBuf(bufLen)
	b := make([]byte, bufLen)

	n, err := CopyIn(b, unsafe.Pointer(&a[0]))
	if n != bufLen {
		t.Errorf("Unexpected copy length, got %v, want %v", n, bufLen)
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Buffers are not equal when they should be: %v %v", a, b)
	}
}

func TestCopyOutSuccess(t *testing.T) {
	// Test that CopyOut does not return an error when all pages are
	// accessible.
	const bufLen = 8192
	a := randBuf(bufLen)
	b := make([]byte, bufLen)

	n, err := CopyOut(unsafe.Pointer(&b[0]), a)
	if n != bufLen {
		t.Errorf("Unexpected copy length, got %v, want %v", n, bufLen)
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Buffers are not equal when they should be: %v %v", a, b)
	}
}

func TestCopySuccess(t *testing.T) {
	// Test that Copy does not return an error when all pages are accessible.
	const bufLen = 8192
	a := randBuf(bufLen)
	b := make([]byte, bufLen)

	n, err := Copy(unsafe.Pointer(&b[0]), unsafe.Pointer(&a[0]), bufLen)
	if n != bufLen {
		t.Errorf("Unexpected copy length, got %v, want %v", n, bufLen)
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Buffers are not equal when they should be: %v %v", a, b)
	}
}

func TestZeroOutSuccess(t *testing.T) {
	// Test that ZeroOut does not return an error when all pages are
	// accessible.
	const bufLen = 8192
	a := make([]byte, bufLen)
	b := randBuf(bufLen)

	n, err := ZeroOut(unsafe.Pointer(&b[0]), bufLen)
	if n != bufLen {
		t.Errorf("Unexpected copy length, got %v, want %v", n, bufLen)
	}
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("Buffers are not equal when they should be: %v %v", a, b)
	}
}

func TestSwapUint32Success(t *testing.T) {
	// Test that SwapUint32 does not return an error when the page is
	// accessible.
	before := uint32(rand.Int31())
	after := uint32(rand.Int31())
	val := before

	old, err := SwapUint32(unsafe.Pointer(&val), after)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if old != before {
		t.Errorf("Unexpected old value: got %v, want %v", old, before)
	}
	if val != after {
		t.Errorf("Unexpected new value: got %v, want %v", val, after)
	}
}

func TestSwapUint32AlignmentError(t *testing.T) {
	// Test that SwapUint32 returns an AlignmentError when passed an unaligned
	// address.
	data := new(struct{ val uint64 })
	addr := uintptr(unsafe.Pointer(&data.val)) + 1
	want := AlignmentError{Addr: addr, Alignment: 4}
	if _, err := SwapUint32(unsafe.Pointer(addr), 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

func TestSwapUint64Success(t *testing.T) {
	// Test that SwapUint64 does not return an error when the page is
	// accessible.
	before := uint64(rand.Int63())
	after := uint64(rand.Int63())
	// "The first word in ... an allocated struct or slice can be relied upon
	// to be 64-bit aligned." - sync/atomic docs
	data := new(struct{ val uint64 })
	data.val = before

	old, err := SwapUint64(unsafe.Pointer(&data.val), after)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if old != before {
		t.Errorf("Unexpected old value: got %v, want %v", old, before)
	}
	if data.val != after {
		t.Errorf("Unexpected new value: got %v, want %v", data.val, after)
	}
}

func TestSwapUint64AlignmentError(t *testing.T) {
	// Test that SwapUint64 returns an AlignmentError when passed an unaligned
	// address.
	data := new(struct{ val1, val2 uint64 })
	addr := uintptr(unsafe.Pointer(&data.val1)) + 1
	want := AlignmentError{Addr: addr, Alignment: 8}
	if _, err := SwapUint64(unsafe.Pointer(addr), 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

func TestCompareAndSwapUint32Success(t *testing.T) {
	// Test that CompareAndSwapUint32 does not return an error when the page is
	// accessible.
	before := uint32(rand.Int31())
	after := uint32(rand.Int31())
	val := before

	old, err := CompareAndSwapUint32(unsafe.Pointer(&val), before, after)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if old != before {
		t.Errorf("Unexpected old value: got %v, want %v", old, before)
	}
	if val != after {
		t.Errorf("Unexpected new value: got %v, want %v", val, after)
	}
}

func TestCompareAndSwapUint32AlignmentError(t *testing.T) {
	// Test that CompareAndSwapUint32 returns an AlignmentError when passed an
	// unaligned address.
	data := new(struct{ val uint64 })
	addr := uintptr(unsafe.Pointer(&data.val)) + 1
	want := AlignmentError{Addr: addr, Alignment: 4}
	if _, err := CompareAndSwapUint32(unsafe.Pointer(addr), 0, 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

// withSegvErrorTestMapping calls fn with a two-page mapping. The first page
// contains random data, and the second page generates SIGSEGV when accessed.
func withSegvErrorTestMapping(t *testing.T, fn func(m []byte)) {
	mapping, err := syscall.Mmap(-1, 0, 2*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	defer syscall.Munmap(mapping)
	if err := syscall.Mprotect(mapping[pageSize:], syscall.PROT_NONE); err != nil {
		t.Fatalf("Mprotect failed: %v", err)
	}
	initRandom(mapping[:pageSize])

	fn(mapping)
}

// withBusErrorTestMapping calls fn with a two-page mapping. The first page
// contains random data, and the second page generates SIGBUS when accessed.
func withBusErrorTestMapping(t *testing.T, fn func(m []byte)) {
	f, err := ioutil.TempFile("", "sigbus_test")
	if err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}
	defer f.Close()
	if err := f.Truncate(pageSize); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}
	mapping, err := syscall.Mmap(int(f.Fd()), 0, 2*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	defer syscall.Munmap(mapping)
	initRandom(mapping[:pageSize])

	fn(mapping)
}

func TestCopyInSegvError(t *testing.T) {
	// Test that CopyIn returns a SegvError when reaching a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				src := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				dst := randBuf(pageSize)
				n, err := CopyIn(dst, src)
				if n != bytesBeforeFault {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (SegvError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := dst[:bytesBeforeFault], mapping[pageSize-bytesBeforeFault:pageSize]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopyInBusError(t *testing.T) {
	// Test that CopyIn returns a BusError when reaching a page that signals
	// SIGBUS.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGBUS", bytesBeforeFault), func(t *testing.T) {
			withBusErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				src := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				dst := randBuf(pageSize)
				n, err := CopyIn(dst, src)
				if n != bytesBeforeFault {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (BusError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := dst[:bytesBeforeFault], mapping[pageSize-bytesBeforeFault:pageSize]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopyOutSegvError(t *testing.T) {
	// Test that CopyOut returns a SegvError when reaching a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				src := randBuf(pageSize)
				n, err := CopyOut(dst, src)
				if n != bytesBeforeFault {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (SegvError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], src[:bytesBeforeFault]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopyOutBusError(t *testing.T) {
	// Test that CopyOut returns a BusError when reaching a page that signals
	// SIGBUS.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withBusErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				src := randBuf(pageSize)
				n, err := CopyOut(dst, src)
				if n != bytesBeforeFault {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (BusError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], src[:bytesBeforeFault]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopySourceSegvError(t *testing.T) {
	// Test that Copy returns a SegvError when copying from a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				src := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				dst := randBuf(pageSize)
				n, err := Copy(unsafe.Pointer(&dst[0]), src, pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (SegvError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := dst[:bytesBeforeFault], mapping[pageSize-bytesBeforeFault:pageSize]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopySourceBusError(t *testing.T) {
	// Test that Copy returns a BusError when copying from a page that signals
	// SIGBUS.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGBUS", bytesBeforeFault), func(t *testing.T) {
			withBusErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				src := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				dst := randBuf(pageSize)
				n, err := Copy(unsafe.Pointer(&dst[0]), src, pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (BusError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := dst[:bytesBeforeFault], mapping[pageSize-bytesBeforeFault:pageSize]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopyDestinationSegvError(t *testing.T) {
	// Test that Copy returns a SegvError when copying to a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				src := randBuf(pageSize)
				n, err := Copy(dst, unsafe.Pointer(&src[0]), pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (SegvError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], src[:bytesBeforeFault]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestCopyDestinationBusError(t *testing.T) {
	// Test that Copy returns a BusError when copying to a page that signals
	// SIGBUS.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGBUS", bytesBeforeFault), func(t *testing.T) {
			withBusErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				src := randBuf(pageSize)
				n, err := Copy(dst, unsafe.Pointer(&src[0]), pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected copy length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (BusError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], src[:bytesBeforeFault]; !bytes.Equal(got, want) {
					t.Errorf("Buffers are not equal when they should be: %v %v", got, want)
				}
			})
		})
	}
}

func TestZeroOutSegvError(t *testing.T) {
	// Test that ZeroOut returns a SegvError when reaching a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting write %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				n, err := ZeroOut(dst, pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected write length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (SegvError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], make([]byte, bytesBeforeFault); !bytes.Equal(got, want) {
					t.Errorf("Non-zero bytes in written part of mapping: %v", got)
				}
			})
		})
	}
}

func TestZeroOutBusError(t *testing.T) {
	// Test that ZeroOut returns a BusError when reaching a page that signals
	// SIGBUS.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting write %d bytes before SIGBUS", bytesBeforeFault), func(t *testing.T) {
			withBusErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
				dst := unsafe.Pointer(secondPage - uintptr(bytesBeforeFault))
				n, err := ZeroOut(dst, pageSize)
				if n != uintptr(bytesBeforeFault) {
					t.Errorf("Unexpected write length: got %v, want %v", n, bytesBeforeFault)
				}
				if want := (BusError{secondPage}); err != want {
					t.Errorf("Unexpected error: got %v, want %v", err, want)
				}
				if got, want := mapping[pageSize-bytesBeforeFault:pageSize], make([]byte, bytesBeforeFault); !bytes.Equal(got, want) {
					t.Errorf("Non-zero bytes in written part of mapping: %v", got)
				}
			})
		})
	}
}

func TestSwapUint32SegvError(t *testing.T) {
	// Test that SwapUint32 returns a SegvError when reaching a page that
	// signals SIGSEGV.
	withSegvErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := SwapUint32(unsafe.Pointer(secondPage), 1)
		if want := (SegvError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestSwapUint32BusError(t *testing.T) {
	// Test that SwapUint32 returns a BusError when reaching a page that
	// signals SIGBUS.
	withBusErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := SwapUint32(unsafe.Pointer(secondPage), 1)
		if want := (BusError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestSwapUint64SegvError(t *testing.T) {
	// Test that SwapUint64 returns a SegvError when reaching a page that
	// signals SIGSEGV.
	withSegvErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := SwapUint64(unsafe.Pointer(secondPage), 1)
		if want := (SegvError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestSwapUint64BusError(t *testing.T) {
	// Test that SwapUint64 returns a BusError when reaching a page that
	// signals SIGBUS.
	withBusErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := SwapUint64(unsafe.Pointer(secondPage), 1)
		if want := (BusError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestCompareAndSwapUint32SegvError(t *testing.T) {
	// Test that CompareAndSwapUint32 returns a SegvError when reaching a page
	// that signals SIGSEGV.
	withSegvErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := CompareAndSwapUint32(unsafe.Pointer(secondPage), 0, 1)
		if want := (SegvError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestCompareAndSwapUint32BusError(t *testing.T) {
	// Test that CompareAndSwapUint32 returns a BusError when reaching a page
	// that signals SIGBUS.
	withBusErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[0])) + pageSize
		_, err := CompareAndSwapUint32(unsafe.Pointer(secondPage), 0, 1)
		if want := (BusError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func testCopy(dst, src []byte) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	debug.SetPanicOnFault(true)
	copy(dst, src)
	return
}

func TestSegVOnMemmove(t *testing.T) {
	// Test that SIGSEGVs received by runtime.memmove when *not* doing
	// CopyIn or CopyOut work gets propagated to the runtime.
	const bufLen = pageSize
	a, err := syscall.Mmap(-1, 0, bufLen, syscall.PROT_NONE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)

	}
	defer syscall.Munmap(a)
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

	a, err := syscall.Mmap(int(f.Fd()), 0, bufLen, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)

	}
	defer syscall.Munmap(a)
	b := randBuf(bufLen)

	if !testCopy(b, a) {
		t.Fatalf("testCopy didn't panic when it should have")
	}

	if !testCopy(a, b) {
		t.Fatalf("testCopy didn't panic when it should have")
	}
}
