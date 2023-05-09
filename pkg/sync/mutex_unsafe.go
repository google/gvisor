// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"sync"
	"unsafe"
)

// CrossGoroutineMutex is equivalent to Mutex, but it need not be unlocked by a
// the same goroutine that locked the mutex.
type CrossGoroutineMutex struct {
	m sync.Mutex
}

// Lock locks the underlying Mutex.
// +checklocksignore
func (m *CrossGoroutineMutex) Lock() {
	m.m.Lock()
}

// Unlock unlocks the underlying Mutex.
// +checklocksignore
func (m *CrossGoroutineMutex) Unlock() {
	m.m.Unlock()
}

// TryLock tries to acquire the mutex. It returns true if it succeeds and false
// otherwise. TryLock does not block.
func (m *CrossGoroutineMutex) TryLock() bool {
	return m.m.TryLock()
}

// Mutex is a mutual exclusion lock. The zero value for a Mutex is an unlocked
// mutex.
//
// A Mutex must not be copied after first use.
//
// A Mutex must be unlocked by the same goroutine that locked it. This
// invariant is enforced with the 'checklocks' build tag.
type Mutex struct {
	m CrossGoroutineMutex
}

// Lock locks m. If the lock is already in use, the calling goroutine blocks
// until the mutex is available.
// +checklocksignore
func (m *Mutex) Lock() {
	noteLock(unsafe.Pointer(m))
	m.m.Lock()
}

// Unlock unlocks m.
//
// Preconditions:
//   - m is locked.
//   - m was locked by this goroutine.
//
// +checklocksignore
func (m *Mutex) Unlock() {
	noteUnlock(unsafe.Pointer(m))
	m.m.Unlock()
}

// TryLock tries to acquire the mutex. It returns true if it succeeds and false
// otherwise. TryLock does not block.
// +checklocksignore
func (m *Mutex) TryLock() bool {
	// Note lock first to enforce proper locking even if unsuccessful.
	noteLock(unsafe.Pointer(m))
	locked := m.m.TryLock()
	if !locked {
		noteUnlock(unsafe.Pointer(m))
	}
	return locked
}
