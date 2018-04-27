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

package futex

import (
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"
)

const (
	testMutexSize            = 4
	testMutexLocked   uint32 = 1
	testMutexUnlocked uint32 = 0
)

// testData implements the Checker interface, and allows us to
// treat the address passed for futex operations as an index in
// a byte slice for testing simplicity.
type testData []byte

func newTestData(size uint) testData {
	return make([]byte, size)
}

func (t testData) Check(addr uintptr, val uint32) error {
	if val != atomic.LoadUint32((*uint32)(unsafe.Pointer(&t[addr]))) {
		return syscall.EAGAIN
	}
	return nil
}

func (t testData) Op(addr uintptr, val uint32) (bool, error) {
	return val == 0, nil
}

// testMutex ties together a testData slice, an address, and a
// futex manager in order to implement the sync.Locker interface.
// Beyond being used as a Locker, this is a simple mechanism for
// changing the underlying values for simpler tests.
type testMutex struct {
	a uintptr
	d testData
	m *Manager
}

func newTestMutex(addr uintptr, d testData, m *Manager) *testMutex {
	return &testMutex{a: addr, d: d, m: m}
}

// Lock acquires the testMutex.
// This may wait for it to be available via the futex manager.
func (t *testMutex) Lock() {
	for {
		// Attempt to grab the lock.
		if atomic.CompareAndSwapUint32(
			((*uint32)(unsafe.Pointer(&t.d[t.a]))),
			testMutexUnlocked,
			testMutexLocked) {
			// Lock held.
			return
		}

		// Wait for it to be "not locked".
		w := NewWaiter()
		err := t.m.WaitPrepare(w, t.d, t.a, testMutexLocked, ^uint32(0))
		if err == syscall.EAGAIN {
			continue
		}
		if err != nil {
			// Should never happen.
			panic("WaitPrepare returned unexpected error: " + err.Error())
		}
		<-w.C
		t.m.WaitComplete(w)
	}
}

// Unlock releases the testMutex.
// This will notify any waiters via the futex manager.
func (t *testMutex) Unlock() {
	// Unlock.
	atomic.StoreUint32(((*uint32)(unsafe.Pointer(&t.d[t.a]))), testMutexUnlocked)

	// Notify all waiters.
	t.m.Wake(t.a, ^uint32(0), math.MaxInt32)
}

func TestFutexWake(t *testing.T) {
	m := NewManager()
	d := newTestData(testMutexSize)

	// Wait for it to be locked.
	// (This won't trigger the wake in testMutex)
	w := NewWaiter()
	m.WaitPrepare(w, d, 0, testMutexUnlocked, ^uint32(0))

	// Wake the single thread.
	if _, err := m.Wake(0, ^uint32(0), 1); err != nil {
		t.Error("wake error:", err)
	}

	<-w.C
	m.WaitComplete(w)
}

func TestFutexWakeBitmask(t *testing.T) {
	m := NewManager()
	d := newTestData(testMutexSize)

	// Wait for it to be locked.
	// (This won't trigger the wake in testMutex)
	w := NewWaiter()
	m.WaitPrepare(w, d, 0, testMutexUnlocked, 0x0000ffff)

	// Wake the single thread, not using the bitmask.
	if _, err := m.Wake(0, 0xffff0000, 1); err != nil {
		t.Error("wake non-matching bitmask error:", err)
	}

	select {
	case <-w.C:
		t.Error("w is alive?")
	default:
	}

	// Now use a matching bitmask.
	if _, err := m.Wake(0, 0x00000001, 1); err != nil {
		t.Error("wake matching bitmask error:", err)
	}

	<-w.C
	m.WaitComplete(w)
}

func TestFutexWakeTwo(t *testing.T) {
	m := NewManager()
	d := newTestData(testMutexSize)

	// Wait for it to be locked.
	// (This won't trigger the wake in testMutex)
	w1 := NewWaiter()
	w2 := NewWaiter()
	w3 := NewWaiter()
	m.WaitPrepare(w1, d, 0, testMutexUnlocked, ^uint32(0))
	m.WaitPrepare(w2, d, 0, testMutexUnlocked, ^uint32(0))
	m.WaitPrepare(w3, d, 0, testMutexUnlocked, ^uint32(0))

	// Wake exactly two threads.
	if _, err := m.Wake(0, ^uint32(0), 2); err != nil {
		t.Error("wake error:", err)
	}

	// Ensure exactly two are alive.
	// We don't get guarantees about exactly which two,
	// (although we expect them to be w1 and w2).
	awake := 0
	for {
		select {
		case <-w1.C:
			awake++
		case <-w2.C:
			awake++
		case <-w3.C:
			awake++
		default:
			if awake != 2 {
				t.Error("awake != 2?")
			}

			// Success.
			return
		}
	}
}

func TestFutexWakeUnrelated(t *testing.T) {
	m := NewManager()
	d := newTestData(2 * testMutexSize)

	// Wait for it to be locked.
	w1 := NewWaiter()
	w2 := NewWaiter()
	m.WaitPrepare(w1, d, 0*testMutexSize, testMutexUnlocked, ^uint32(0))
	m.WaitPrepare(w2, d, 1*testMutexSize, testMutexUnlocked, ^uint32(0))

	// Wake only the second one.
	if _, err := m.Wake(1*testMutexSize, ^uint32(0), 2); err != nil {
		t.Error("wake error:", err)
	}

	// Ensure only r2 is alive.
	select {
	case <-w1.C:
		t.Error("w1 is alive?")
	default:
	}
	<-w2.C
}

// This function was shamelessly stolen from mutex_test.go.
func HammerMutex(l sync.Locker, loops int, cdone chan bool) {
	for i := 0; i < loops; i++ {
		l.Lock()
		runtime.Gosched()
		l.Unlock()
	}
	cdone <- true
}

func TestFutexStress(t *testing.T) {
	m := NewManager()
	d := newTestData(testMutexSize)
	tm := newTestMutex(0*testMutexSize, d, m)
	c := make(chan bool)

	for i := 0; i < 10; i++ {
		go HammerMutex(tm, 1000, c)
	}

	for i := 0; i < 10; i++ {
		<-c
	}
}

func TestWakeOpEmpty(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	n, err := m.WakeOp(d, 0, 4, 10, 10, 0)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 0 {
		t.Fatalf("Invalid number of wakes: want 0, got %d", n)
	}
}

func TestWakeOpFirstNonEmpty(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add two waiters on address 0.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	// Wake up all waiters on address 0.
	n, err := m.WakeOp(d, 0, 4, 10, 10, 0)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 2 {
		t.Fatalf("Invalid number of wakes: want 2, got %d", n)
	}
}

func TestWakeOpSecondNonEmpty(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add two waiters on address 4.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	// Wake up all waiters on address 4.
	n, err := m.WakeOp(d, 0, 4, 10, 10, 0)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 2 {
		t.Fatalf("Invalid number of wakes: want 2, got %d", n)
	}
}

func TestWakeOpSecondNonEmptyFailingOp(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add two waiters on address 4.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	// Wake up all waiters on address 4.
	n, err := m.WakeOp(d, 0, 4, 10, 10, 1)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 0 {
		t.Fatalf("Invalid number of wakes: want 0, got %d", n)
	}
}

func TestWakeOpAllNonEmpty(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add two waiters on address 0.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	// Add two waiters on address 4.
	w3 := NewWaiter()
	if err := m.WaitPrepare(w3, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w3)

	w4 := NewWaiter()
	if err := m.WaitPrepare(w4, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w4)

	// Wake up all waiters on both addresses.
	n, err := m.WakeOp(d, 0, 4, 10, 10, 0)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 4 {
		t.Fatalf("Invalid number of wakes: want 4, got %d", n)
	}
}

func TestWakeOpAllNonEmptyFailingOp(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add two waiters on address 0.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	// Add two waiters on address 4.
	w3 := NewWaiter()
	if err := m.WaitPrepare(w3, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w3)

	w4 := NewWaiter()
	if err := m.WaitPrepare(w4, d, 4, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w4)

	// Wake up all waiters on both addresses.
	n, err := m.WakeOp(d, 0, 4, 10, 10, 1)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 2 {
		t.Fatalf("Invalid number of wakes: want 2, got %d", n)
	}
}

func TestWakeOpSameAddress(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add four waiters on address 0.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	w3 := NewWaiter()
	if err := m.WaitPrepare(w3, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w3)

	w4 := NewWaiter()
	if err := m.WaitPrepare(w4, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w4)

	// Use the same address, with one at most one waiter from each.
	n, err := m.WakeOp(d, 0, 0, 1, 1, 0)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 2 {
		t.Fatalf("Invalid number of wakes: want 2, got %d", n)
	}
}

func TestWakeOpSameAddressFailingOp(t *testing.T) {
	m := NewManager()
	d := newTestData(8)

	// Add four waiters on address 0.
	w1 := NewWaiter()
	if err := m.WaitPrepare(w1, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w1)

	w2 := NewWaiter()
	if err := m.WaitPrepare(w2, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w2)

	w3 := NewWaiter()
	if err := m.WaitPrepare(w3, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w3)

	w4 := NewWaiter()
	if err := m.WaitPrepare(w4, d, 0, 0, ^uint32(0)); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	defer m.WaitComplete(w4)

	// Use the same address, with one at most one waiter from each.
	n, err := m.WakeOp(d, 0, 0, 1, 1, 1)
	if err != nil {
		t.Fatalf("WakeOp failed: %v", err)
	}

	if n != 1 {
		t.Fatalf("Invalid number of wakes: want 1, got %d", n)
	}
}
