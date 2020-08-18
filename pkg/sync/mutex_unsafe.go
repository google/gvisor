// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13
// +build !go1.16

// When updating the build constraint (above), check that syncMutex matches the
// standard library sync.Mutex definition.

package sync

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// Mutex is a try lock.
type Mutex struct {
	sync.Mutex
}

type syncMutex struct {
	state int32
	sema  uint32
}

func (m *Mutex) state() *int32 {
	return &(*syncMutex)(unsafe.Pointer(&m.Mutex)).state
}

const (
	mutexUnlocked = 0
	mutexLocked   = 1
)

// TryLock tries to aquire the mutex. It returns true if it succeeds and false
// otherwise. TryLock does not block.
func (m *Mutex) TryLock() bool {
	if atomic.CompareAndSwapInt32(m.state(), mutexUnlocked, mutexLocked) {
		if RaceEnabled {
			RaceAcquire(unsafe.Pointer(&m.Mutex))
		}
		return true
	}
	return false
}
