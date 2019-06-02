// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.12
// +build !go1.14

// Check go:linkname function signatures when updating Go version.

// This is mostly copied from the standard library's sync/rwmutex.go.
//
// Happens-before relationships indicated to the race detector:
// - Unlock -> Lock (via writerSem)
// - Unlock -> RLock (via readerSem)
// - RUnlock -> Lock (via writerSem)
// - DowngradeLock -> RLock (via readerSem)

package gvsync

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

//go:linkname runtimeSemacquire sync.runtime_Semacquire
func runtimeSemacquire(s *uint32)

// DowngradableRWMutex is identical to sync.RWMutex, but adds the DowngradeLock
// method.
type DowngradableRWMutex struct {
	w           sync.Mutex // held if there are pending writers
	writerSem   uint32     // semaphore for writers to wait for completing readers
	readerSem   uint32     // semaphore for readers to wait for completing writers
	readerCount int32      // number of pending readers
	readerWait  int32      // number of departing readers
}

const rwmutexMaxReaders = 1 << 30

// RLock locks rw for reading.
func (rw *DowngradableRWMutex) RLock() {
	if RaceEnabled {
		RaceDisable()
	}
	if atomic.AddInt32(&rw.readerCount, 1) < 0 {
		// A writer is pending, wait for it.
		runtimeSemacquire(&rw.readerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.readerSem))
	}
}

// RUnlock undoes a single RLock call.
func (rw *DowngradableRWMutex) RUnlock() {
	if RaceEnabled {
		// TODO(jamieliu): Why does this need to be ReleaseMerge instead of
		// Release? IIUC this establishes Unlock happens-before RUnlock, which
		// seems unnecessary.
		RaceReleaseMerge(unsafe.Pointer(&rw.writerSem))
		RaceDisable()
	}
	if r := atomic.AddInt32(&rw.readerCount, -1); r < 0 {
		if r+1 == 0 || r+1 == -rwmutexMaxReaders {
			panic("RUnlock of unlocked DowngradableRWMutex")
		}
		// A writer is pending.
		if atomic.AddInt32(&rw.readerWait, -1) == 0 {
			// The last reader unblocks the writer.
			runtimeSemrelease(&rw.writerSem, false, 0)
		}
	}
	if RaceEnabled {
		RaceEnable()
	}
}

// Lock locks rw for writing.
func (rw *DowngradableRWMutex) Lock() {
	if RaceEnabled {
		RaceDisable()
	}
	// First, resolve competition with other writers.
	rw.w.Lock()
	// Announce to readers there is a pending writer.
	r := atomic.AddInt32(&rw.readerCount, -rwmutexMaxReaders) + rwmutexMaxReaders
	// Wait for active readers.
	if r != 0 && atomic.AddInt32(&rw.readerWait, r) != 0 {
		runtimeSemacquire(&rw.writerSem)
	}
	if RaceEnabled {
		RaceEnable()
		RaceAcquire(unsafe.Pointer(&rw.writerSem))
	}
}

// Unlock unlocks rw for writing.
func (rw *DowngradableRWMutex) Unlock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.writerSem))
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	// Announce to readers there is no active writer.
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders)
	if r >= rwmutexMaxReaders {
		panic("Unlock of unlocked DowngradableRWMutex")
	}
	// Unblock blocked readers, if any.
	for i := 0; i < int(r); i++ {
		runtimeSemrelease(&rw.readerSem, false, 0)
	}
	// Allow other writers to proceed.
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}

// DowngradeLock atomically unlocks rw for writing and locks it for reading.
func (rw *DowngradableRWMutex) DowngradeLock() {
	if RaceEnabled {
		RaceRelease(unsafe.Pointer(&rw.readerSem))
		RaceDisable()
	}
	// Announce to readers there is no active writer and one additional reader.
	r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders+1)
	if r >= rwmutexMaxReaders+1 {
		panic("DowngradeLock of unlocked DowngradableRWMutex")
	}
	// Unblock blocked readers, if any. Note that this loop starts as 1 since r
	// includes this goroutine.
	for i := 1; i < int(r); i++ {
		runtimeSemrelease(&rw.readerSem, false, 0)
	}
	// Allow other writers to proceed to rw.w.Lock(). Note that they will still
	// block on rw.writerSem since at least this reader exists, such that
	// DowngradeLock() is atomic with the previous write lock.
	rw.w.Unlock()
	if RaceEnabled {
		RaceEnable()
	}
}
