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

package safecopy

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Size of a page in bytes. Cloned from hostarch.PageSize to avoid a circular
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
	data := make([]byte, 8) // 2 * sizeof(uint32).
	alignedIndex := uintptr(0)
	if offset := uintptr(unsafe.Pointer(&data[0])) % 4; offset != 0 {
		alignedIndex = 4 - offset
	}
	ptr := unsafe.Pointer(&data[alignedIndex+1])
	want := AlignmentError{Addr: uintptr(ptr), Alignment: 4}
	if _, err := SwapUint32(ptr, 1); err != want {
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
	data := make([]byte, 16) // 2 * sizeof(uint64).
	alignedIndex := uintptr(0)
	if offset := uintptr(unsafe.Pointer(&data[0])) % 8; offset != 0 {
		alignedIndex = 8 - offset
	}
	ptr := unsafe.Pointer(&data[alignedIndex+1])
	want := AlignmentError{Addr: uintptr(ptr), Alignment: 8}
	if _, err := SwapUint64(ptr, 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

func TestStoreUint64Success(t *testing.T) {
	// Test that StoreUint64 does not return an error when the page is
	// accessible.
	after := uint64(rand.Int63())
	// "The first word in ... an allocated struct or slice can be relied upon
	// to be 64-bit aligned." - sync/atomic docs
	data := new(struct{ val uint64 })

	if err := StoreUint64(unsafe.Pointer(&data.val), after); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if data.val != after {
		t.Errorf("Unexpected value: got %v, want %v", data.val, after)
	}
}

func TestStoreUint64AlignmentError(t *testing.T) {
	// Test that StoreUint64 returns an AlignmentError when passed an unaligned
	// address.
	data := make([]byte, 16) // 2 * sizeof(uint64).
	alignedIndex := uintptr(0)
	if offset := uintptr(unsafe.Pointer(&data[0])) % 8; offset != 0 {
		alignedIndex = 8 - offset
	}
	ptr := unsafe.Pointer(&data[alignedIndex+1])
	want := AlignmentError{Addr: uintptr(ptr), Alignment: 8}
	if err := StoreUint64(ptr, 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

func TestStoreUint64SegvError(t *testing.T) {
	// Test that StoreUint64 returns a SegvError when reaching a page that
	// signals SIGSEGV.
	withSegvErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
		err := StoreUint64(unsafe.Pointer(secondPage), 1)
		if want := (SegvError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}

func TestStoreUint64BusError(t *testing.T) {
	// Test that StoreUint64 returns a BusError when reaching a page that
	// signals SIGBUS.
	withBusErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
		err := StoreUint64(unsafe.Pointer(secondPage), 1)
		if want := (BusError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
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
	data := make([]byte, 8) // 2 * sizeof(uint32).
	alignedIndex := uintptr(0)
	if offset := uintptr(unsafe.Pointer(&data[0])) % 4; offset != 0 {
		alignedIndex = 4 - offset
	}
	ptr := unsafe.Pointer(&data[alignedIndex+1])
	want := AlignmentError{Addr: uintptr(ptr), Alignment: 4}
	if _, err := CompareAndSwapUint32(ptr, 0, 1); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

// withSegvErrorTestMapping calls fn with a two-page mapping. The first page
// contains random data, and the second page generates SIGSEGV when accessed.
func withSegvErrorTestMapping(t *testing.T, fn func(m []byte)) {
	mapping, err := unix.Mmap(-1, 0, 2*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	defer unix.Munmap(mapping)
	if err := unix.Mprotect(mapping[pageSize:], unix.PROT_NONE); err != nil {
		t.Fatalf("Mprotect failed: %v", err)
	}
	initRandom(mapping[:pageSize])

	fn(mapping)
}

// withBusErrorTestMapping calls fn with a two-page mapping. The first page
// contains random data, and the second page generates SIGBUS when accessed.
func withBusErrorTestMapping(t *testing.T, fn func(m []byte)) {
	f, err := os.CreateTemp("", "sigbus_test")
	if err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}
	defer f.Close()
	if err := f.Truncate(pageSize); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}
	mapping, err := unix.Mmap(int(f.Fd()), 0, 2*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap failed: %v", err)
	}
	defer unix.Munmap(mapping)
	initRandom(mapping[:pageSize])

	fn(mapping)
}

func TestCopyInSegvError(t *testing.T) {
	// Test that CopyIn returns a SegvError when reaching a page that signals
	// SIGSEGV.
	for bytesBeforeFault := 0; bytesBeforeFault <= 2*maxRegisterSize; bytesBeforeFault++ {
		t.Run(fmt.Sprintf("starting copy %d bytes before SIGSEGV", bytesBeforeFault), func(t *testing.T) {
			withSegvErrorTestMapping(t, func(mapping []byte) {
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				src := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				src := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				src := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				src := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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
				secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
				dst := unsafe.Pointer(&mapping[pageSize-bytesBeforeFault])
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

// zeroOutCases are lengths that memclr zeroes with each of its loops: ordinary
// stores, REP STOSB or DC ZVA if the CPU supports them, and non-temporal stores
// on amd64. faultOffs are offsets at which to test faults, rounded up to the
// page size.
var zeroOutCases = []struct {
	length    int
	faultOffs []int
}{
	{2000, []int{pageSize}},
	{64 << 10, []int{pageSize, 32 << 10}},
	{33 << 20, []int{pageSize, 16 << 20, 32 << 20}},
}

func TestZeroOutLengths(t *testing.T) {
	// Test that ZeroOut zeroes exactly the requested bytes, for various
	// alignments of both ends.
	for _, c := range zeroOutCases {
		b := make([]byte, c.length+64)
		ones := bytes.Repeat([]byte{0xff}, len(b))
		zeros := make([]byte, len(b))
		for _, start := range []int{0, 1, 15, 48, 63} {
			for end := start + c.length - 256; end < start+c.length; end += 8 {
				copy(b, ones)
				n, err := ZeroOut(unsafe.Pointer(&b[start]), uintptr(end-start))
				if n != uintptr(end-start) || err != nil {
					t.Errorf("ZeroOut([%d, %d)): got (%v, %v), want (%v, nil)", start, end, n, err, end-start)
				}
				if !bytes.Equal(b[start:end], zeros[start:end]) {
					t.Errorf("ZeroOut([%d, %d)) left non-zero bytes", start, end)
				}
				if !bytes.Equal(b[:start], ones[:start]) || !bytes.Equal(b[end:], ones[end:]) {
					t.Errorf("ZeroOut([%d, %d)) wrote outside the range", start, end)
				}
			}
		}
	}
}

func TestZeroOutLengthsFault(t *testing.T) {
	// Test that ZeroOut zeroes everything before a SIGSEGV or SIGBUS at
	// various points in a range.
	ps := unix.Getpagesize()
	for _, c := range zeroOutCases {
		size := (2*ps + c.length + ps - 1) &^ (ps - 1)
		ones := bytes.Repeat([]byte{0xff}, size)
		zeros := make([]byte, size)
		for _, sig := range []unix.Signal{unix.SIGSEGV, unix.SIGBUS} {
			for _, off := range c.faultOffs {
				faultOff := (off + ps - 1) &^ (ps - 1)
				for _, start := range []int{0, 1, 15, ps - 1500, ps - 16, ps - 15, ps - 1, ps + 1} {
					faultAt := max(faultOff, start)
					if faultAt-start >= c.length {
						continue
					}
					t.Run(fmt.Sprintf("%v at %#x from %#x in %#x", sig, faultOff, start, c.length), func(t *testing.T) {
						var m []byte
						var err error
						if sig == unix.SIGSEGV {
							m, err = unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
							if err != nil {
								t.Fatalf("Mmap failed: %v", err)
							}
							defer unix.Munmap(m)
							if err := unix.Mprotect(m[faultOff:], unix.PROT_NONE); err != nil {
								t.Fatalf("Mprotect failed: %v", err)
							}
						} else {
							fd, err := unix.MemfdCreate("safecopy_test", 0)
							if err != nil {
								t.Fatalf("MemfdCreate failed: %v", err)
							}
							defer unix.Close(fd)
							if err := unix.Ftruncate(fd, int64(faultOff)); err != nil {
								t.Fatalf("Ftruncate failed: %v", err)
							}
							m, err = unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
							if err != nil {
								t.Fatalf("Mmap failed: %v", err)
							}
							defer unix.Munmap(m)
							// A huge page could extend past EOF. Kernels
							// without THP reject this advice.
							if err := unix.Madvise(m, unix.MADV_NOHUGEPAGE); err != nil && err != unix.EINVAL {
								t.Fatalf("Madvise failed: %v", err)
							}
						}
						dst := uintptr(unsafe.Pointer(&m[start]))
						fault := uintptr(unsafe.Pointer(&m[faultAt]))
						if f, _ := memclr(dst, uintptr(c.length), true); f != fault {
							t.Errorf("memclr: got fault %#x, want %#x", f, fault)
						}
						copy(m[start:faultAt], ones)
						n, err := ZeroOut(unsafe.Pointer(dst), uintptr(c.length))
						if want := uintptr(faultAt - start); n != want {
							t.Errorf("Unexpected write length: got %v, want %v", n, want)
						}
						var want error = SegvError{fault}
						if sig == unix.SIGBUS {
							want = BusError{fault}
						}
						if err != want {
							t.Errorf("Unexpected error: got %v, want %v", err, want)
						}
						if !bytes.Equal(m[start:faultAt], zeros[start:faultAt]) {
							t.Errorf("Non-zero bytes before the fault")
						}
					})
				}
			}
		}
	}
}

func BenchmarkZeroOut(b *testing.B) {
	for _, size := range []int{4 << 10, 64 << 10, 2 << 20, 64 << 20, 128 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			for b.Loop() {
				ZeroOut(unsafe.Pointer(&buf[0]), uintptr(size))
			}
		})
	}
}

func TestSwapUint32SegvError(t *testing.T) {
	// Test that SwapUint32 returns a SegvError when reaching a page that
	// signals SIGSEGV.
	withSegvErrorTestMapping(t, func(mapping []byte) {
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
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
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
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
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
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
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
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
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
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
		secondPage := uintptr(unsafe.Pointer(&mapping[pageSize]))
		_, err := CompareAndSwapUint32(unsafe.Pointer(secondPage), 0, 1)
		if want := (BusError{secondPage}); err != want {
			t.Errorf("Unexpected error: got %v, want %v", err, want)
		}
	})
}
