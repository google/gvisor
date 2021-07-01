// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"sync"
	"testing"
	"unsafe"
)

// TestStructSize verifies that syncMutex's size hasn't drifted from the
// standard library's version.
//
// The correctness of this package relies on these remaining in sync.
func TestStructSize(t *testing.T) {
	const (
		got  = unsafe.Sizeof(syncMutex{})
		want = unsafe.Sizeof(sync.Mutex{})
	)
	if got != want {
		t.Errorf("got sizeof(syncMutex) = %d, want = sizeof(sync.Mutex) = %d", got, want)
	}
}

// TestFieldValues verifies that the semantics of syncMutex.state from the
// standard library's implementation.
//
// The correctness of this package relies on these remaining in sync.
func TestFieldValues(t *testing.T) {
	var m Mutex
	m.Lock()
	if got := *m.m.state(); got != mutexLocked {
		t.Errorf("got locked sync.Mutex.state = %d, want = %d", got, mutexLocked)
	}
	m.Unlock()
	if got := *m.m.state(); got != mutexUnlocked {
		t.Errorf("got unlocked sync.Mutex.state = %d, want = %d", got, mutexUnlocked)
	}
}

func TestDoubleTryLock(t *testing.T) {
	var m Mutex
	if !m.TryLock() {
		t.Fatal("failed to aquire lock")
	}
	if m.TryLock() {
		t.Fatal("unexpectedly succeeded in aquiring locked mutex")
	}
}

func TestTryLockAfterLock(t *testing.T) {
	var m Mutex
	m.Lock()
	if m.TryLock() {
		t.Fatal("unexpectedly succeeded in aquiring locked mutex")
	}
}

func TestTryLockUnlock(t *testing.T) {
	var m Mutex
	if !m.TryLock() {
		t.Fatal("failed to aquire lock")
	}
	m.Unlock() // +checklocksforce
	if !m.TryLock() {
		t.Fatal("failed to aquire lock after unlock")
	}
}
