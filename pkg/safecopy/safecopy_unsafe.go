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
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// maxRegisterSize is the maximum register size used in memcpy and memclr. It
// is used to decide by how much to rewind the copy (for memcpy) or zeroing
// (for memclr) before proceeding.
const maxRegisterSize = 16

// memcpy copies data from src to dst. If a SIGSEGV or SIGBUS signal is received
// during the copy, it returns the address that caused the fault and the number
// of the signal that was received. Otherwise, it returns an unspecified address
// and a signal number of 0.
//
// Data is copied in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully copied.
//
//go:noescape
func memcpy(dst, src uintptr, n uintptr) (fault uintptr, sig int32)

// memclr sets the n bytes following ptr to zeroes. If a SIGSEGV or SIGBUS
// signal is received during the write, it returns the address that caused the
// fault and the number of the signal that was received. Otherwise, it returns
// an unspecified address and a signal number of 0.
//
// Data is written in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully written.
//
//go:noescape
func memclr(ptr uintptr, n uintptr) (fault uintptr, sig int32)

// swapUint32 atomically stores new into *ptr and returns (the previous *ptr
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func swapUint32(ptr unsafe.Pointer, new uint32) (old uint32, sig int32)

// swapUint64 atomically stores new into *ptr and returns (the previous *ptr
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 8-byte boundary.
//
//go:noescape
func swapUint64(ptr unsafe.Pointer, new uint64) (old uint64, sig int32)

// compareAndSwapUint32 is like sync/atomic.CompareAndSwapUint32, but returns
// (the value previously stored at ptr, 0). If a SIGSEGV or SIGBUS signal is
// received during the operation, the value of prev is unspecified, and sig is
// the number of the signal that was received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func compareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (prev uint32, sig int32)

// LoadUint32 is like sync/atomic.LoadUint32, but operates with user memory. It
// may fail with SIGSEGV or SIGBUS if it is received while reading from ptr.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func loadUint32(ptr unsafe.Pointer) (val uint32, sig int32)

// CopyIn copies len(dst) bytes from src to dst. It returns the number of bytes
// copied and an error if SIGSEGV or SIGBUS is received while reading from src.
func CopyIn(dst []byte, src unsafe.Pointer) (int, error) {
	n, err := copyIn(dst, uintptr(src))
	runtime.KeepAlive(src)
	return n, err
}

// copyIn is the underlying definition for CopyIn.
func copyIn(dst []byte, src uintptr) (int, error) {
	toCopy := uintptr(len(dst))
	if len(dst) == 0 {
		return 0, nil
	}

	fault, sig := memcpy(uintptr(unsafe.Pointer(&dst[0])), src, toCopy)
	if sig == 0 {
		return len(dst), nil
	}

	if fault < src || fault >= src+toCopy {
		panic(fmt.Sprintf("CopyIn raised signal %d at %#x, which is outside source [%#x, %#x)", sig, fault, src, src+toCopy))
	}

	// memcpy might have ended the copy up to maxRegisterSize bytes before
	// fault, if an instruction caused a memory access that straddled two
	// pages, and the second one faulted. Try to copy up to the fault.
	var done int
	if fault-src > maxRegisterSize {
		done = int(fault - src - maxRegisterSize)
	}
	n, err := copyIn(dst[done:int(fault-src)], src+uintptr(done))
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

// CopyOut copies len(src) bytes from src to dst. If returns the number of
// bytes done and an error if SIGSEGV or SIGBUS is received while writing to
// dst.
func CopyOut(dst unsafe.Pointer, src []byte) (int, error) {
	n, err := copyOut(uintptr(dst), src)
	runtime.KeepAlive(dst)
	return n, err
}

// copyOut is the underlying definition for CopyOut.
func copyOut(dst uintptr, src []byte) (int, error) {
	toCopy := uintptr(len(src))
	if toCopy == 0 {
		return 0, nil
	}

	fault, sig := memcpy(dst, uintptr(unsafe.Pointer(&src[0])), toCopy)
	if sig == 0 {
		return len(src), nil
	}

	if fault < dst || fault >= dst+toCopy {
		panic(fmt.Sprintf("CopyOut raised signal %d at %#x, which is outside destination [%#x, %#x)", sig, fault, dst, dst+toCopy))
	}

	// memcpy might have ended the copy up to maxRegisterSize bytes before
	// fault, if an instruction caused a memory access that straddled two
	// pages, and the second one faulted. Try to copy up to the fault.
	var done int
	if fault-dst > maxRegisterSize {
		done = int(fault - dst - maxRegisterSize)
	}
	n, err := copyOut(dst+uintptr(done), src[done:int(fault-dst)])
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

// Copy copies toCopy bytes from src to dst. It returns the number of bytes
// copied and an error if SIGSEGV or SIGBUS is received while reading from src
// or writing to dst.
//
// Data is copied in order; if [src, src+toCopy) and [dst, dst+toCopy) overlap,
// the resulting contents of dst are unspecified.
func Copy(dst, src unsafe.Pointer, toCopy uintptr) (uintptr, error) {
	n, err := copyN(uintptr(dst), uintptr(src), toCopy)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(src)
	return n, err
}

// copyN is the underlying definition for Copy.
func copyN(dst, src uintptr, toCopy uintptr) (uintptr, error) {
	if toCopy == 0 {
		return 0, nil
	}

	fault, sig := memcpy(dst, src, toCopy)
	if sig == 0 {
		return toCopy, nil
	}

	// Did the fault occur while reading from src or writing to dst?
	faultAfterSrc := ^uintptr(0)
	if fault >= src {
		faultAfterSrc = fault - src
	}
	faultAfterDst := ^uintptr(0)
	if fault >= dst {
		faultAfterDst = fault - dst
	}
	if faultAfterSrc >= toCopy && faultAfterDst >= toCopy {
		panic(fmt.Sprintf("Copy raised signal %d at %#x, which is outside source [%#x, %#x) and destination [%#x, %#x)", sig, fault, src, src+toCopy, dst, dst+toCopy))
	}
	faultedAfter := faultAfterSrc
	if faultedAfter > faultAfterDst {
		faultedAfter = faultAfterDst
	}

	// memcpy might have ended the copy up to maxRegisterSize bytes before
	// fault, if an instruction caused a memory access that straddled two
	// pages, and the second one faulted. Try to copy up to the fault.
	var done uintptr
	if faultedAfter > maxRegisterSize {
		done = faultedAfter - maxRegisterSize
	}
	n, err := copyN(dst+done, src+done, faultedAfter-done)
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

// ZeroOut writes toZero zero bytes to dst. It returns the number of bytes
// written and an error if SIGSEGV or SIGBUS is received while writing to dst.
func ZeroOut(dst unsafe.Pointer, toZero uintptr) (uintptr, error) {
	n, err := zeroOut(uintptr(dst), toZero)
	runtime.KeepAlive(dst)
	return n, err
}

// zeroOut is the underlying definition for ZeroOut.
func zeroOut(dst uintptr, toZero uintptr) (uintptr, error) {
	if toZero == 0 {
		return 0, nil
	}

	fault, sig := memclr(dst, toZero)
	if sig == 0 {
		return toZero, nil
	}

	if fault < dst || fault >= dst+toZero {
		panic(fmt.Sprintf("ZeroOut raised signal %d at %#x, which is outside destination [%#x, %#x)", sig, fault, dst, dst+toZero))
	}

	// memclr might have ended the write up to maxRegisterSize bytes before
	// fault, if an instruction caused a memory access that straddled two
	// pages, and the second one faulted. Try to write up to the fault.
	var done uintptr
	if fault-dst > maxRegisterSize {
		done = fault - dst - maxRegisterSize
	}
	n, err := zeroOut(dst+done, fault-dst-done)
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

// SwapUint32 is equivalent to sync/atomic.SwapUint32, except that it returns
// an error if SIGSEGV or SIGBUS is received while accessing ptr, or if ptr is
// not aligned to a 4-byte boundary.
func SwapUint32(ptr unsafe.Pointer, new uint32) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	old, sig := swapUint32(ptr, new)
	return old, errorFromFaultSignal(uintptr(ptr), sig)
}

// SwapUint64 is equivalent to sync/atomic.SwapUint64, except that it returns
// an error if SIGSEGV or SIGBUS is received while accessing ptr, or if ptr is
// not aligned to an 8-byte boundary.
func SwapUint64(ptr unsafe.Pointer, new uint64) (uint64, error) {
	if addr := uintptr(ptr); addr&7 != 0 {
		return 0, AlignmentError{addr, 8}
	}
	old, sig := swapUint64(ptr, new)
	return old, errorFromFaultSignal(uintptr(ptr), sig)
}

// CompareAndSwapUint32 is equivalent to atomicbitops.CompareAndSwapUint32,
// except that it returns an error if SIGSEGV or SIGBUS is received while
// accessing ptr, or if ptr is not aligned to a 4-byte boundary.
func CompareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	prev, sig := compareAndSwapUint32(ptr, old, new)
	return prev, errorFromFaultSignal(uintptr(ptr), sig)
}

// LoadUint32 is like sync/atomic.LoadUint32, but operates with user memory. It
// may fail with SIGSEGV or SIGBUS if it is received while reading from ptr.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
func LoadUint32(ptr unsafe.Pointer) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	val, sig := loadUint32(ptr)
	return val, errorFromFaultSignal(uintptr(ptr), sig)
}

func errorFromFaultSignal(addr uintptr, sig int32) error {
	switch sig {
	case 0:
		return nil
	case int32(syscall.SIGSEGV):
		return SegvError{addr}
	case int32(syscall.SIGBUS):
		return BusError{addr}
	default:
		panic(fmt.Sprintf("safecopy got unexpected signal %d at address %#x", sig, addr))
	}
}

// ReplaceSignalHandler replaces the existing signal handler for the provided
// signal with the one that handles faults in safecopy-protected functions.
//
// It stores the value of the previously set handler in previous.
//
// This function will be called on initialization in order to install safecopy
// handlers for appropriate signals. These handlers will call the previous
// handler however, and if this is function is being used externally then the
// same courtesy is expected.
func ReplaceSignalHandler(sig syscall.Signal, handler uintptr, previous *uintptr) error {
	var sa struct {
		handler  uintptr
		flags    uint64
		restorer uintptr
		mask     uint64
	}
	const maskLen = 8

	// Get the existing signal handler information, and save the current
	// handler. Once we replace it, we will use this pointer to fall back to
	// it when we receive other signals.
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), 0, uintptr(unsafe.Pointer(&sa)), maskLen, 0, 0); e != 0 {
		return e
	}

	// Fail if there isn't a previous handler.
	if sa.handler == 0 {
		return fmt.Errorf("previous handler for signal %x isn't set", sig)
	}

	*previous = sa.handler

	// Install our own handler.
	sa.handler = handler
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&sa)), 0, maskLen, 0, 0); e != 0 {
		return e
	}

	return nil
}
