// Copyright 2018 Google LLC
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// testData implements the Target interface, and allows us to
// treat the address passed for futex operations as an index in
// a byte slice for testing simplicity.
type testData []byte

const sizeofInt32 = 4

func newTestData(size uint) testData {
	return make([]byte, size)
}

func (t testData) SwapUint32(addr usermem.Addr, new uint32) (uint32, error) {
	val := atomic.SwapUint32((*uint32)(unsafe.Pointer(&t[addr])), new)
	return val, nil
}

func (t testData) CompareAndSwapUint32(addr usermem.Addr, old, new uint32) (uint32, error) {
	if atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&t[addr])), old, new) {
		return old, nil
	}
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&t[addr]))), nil
}

func (t testData) GetSharedKey(addr usermem.Addr) (Key, error) {
	return Key{
		Kind:   KindSharedMappable,
		Offset: uint64(addr),
	}, nil
}

func futexKind(private bool) string {
	if private {
		return "private"
	}
	return "shared"
}

func newPreparedTestWaiter(t *testing.T, m *Manager, ta Target, addr usermem.Addr, private bool, val uint32, bitmask uint32) *Waiter {
	w := NewWaiter()
	if err := m.WaitPrepare(w, ta, addr, private, val, bitmask); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	return w
}

func TestFutexWake(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start waiting for wakeup.
			w := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w)

			// Perform a wakeup.
			if n, err := m.Wake(d, 0, private, ^uint32(0), 1); err != nil || n != 1 {
				t.Errorf("Wake: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect the waiter to have been woken.
			if !w.woken() {
				t.Error("waiter not woken")
			}
		})
	}
}

func TestFutexWakeBitmask(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start waiting for wakeup.
			w := newPreparedTestWaiter(t, m, d, 0, private, 0, 0x0000ffff)
			defer m.WaitComplete(w)

			// Perform a wakeup using the wrong bitmask.
			if n, err := m.Wake(d, 0, private, 0xffff0000, 1); err != nil || n != 0 {
				t.Errorf("Wake with non-matching bitmask: got (%d, %v), wanted (0, nil)", n, err)
			}

			// Expect the waiter to still be waiting.
			if w.woken() {
				t.Error("waiter woken unexpectedly")
			}

			// Perform a wakeup using the right bitmask.
			if n, err := m.Wake(d, 0, private, 0x00000001, 1); err != nil || n != 1 {
				t.Errorf("Wake with matching bitmask: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect that the waiter was woken.
			if !w.woken() {
				t.Error("waiter not woken")
			}
		})
	}
}

func TestFutexWakeTwo(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start three waiters waiting for wakeup.
			var ws [3]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i])
			}

			// Perform two wakeups.
			const wakeups = 2
			if n, err := m.Wake(d, 0, private, ^uint32(0), 2); err != nil || n != wakeups {
				t.Errorf("Wake: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly two waiters were woken.
			// We don't get guarantees about exactly which two,
			// (although we expect them to be w1 and w2).
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

func TestFutexWakeUnrelated(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(2 * sizeofInt32)

			// Start two waiters waiting for wakeup on different addresses.
			w1 := newPreparedTestWaiter(t, m, d, 0*sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, 1*sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Perform two wakeups on the second address.
			if n, err := m.Wake(d, 1*sizeofInt32, private, ^uint32(0), 2); err != nil || n != 1 {
				t.Errorf("Wake: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect that only the second waiter was woken.
			if w1.woken() {
				t.Error("w1 woken unexpectedly")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(2 * sizeofInt32)

			// Perform wakeups with no waiters.
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 0); err != nil || n != 0 {
				t.Fatalf("WakeOp: got (%d, %v), wanted (0, nil)", n, err)
			}
		})
	}
}

func TestWakeOpFirstNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Perform 10 wakeups on address 0.
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 0, 0); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that both waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpSecondNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address sizeofInt32.
			w1 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Perform 10 wakeups on address sizeofInt32 (contingent on
			// d.Op(0), which should succeed).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 0, 10, 0); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that both waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpSecondNonEmptyFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address sizeofInt32.
			w1 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Perform 10 wakeups on address sizeofInt32 (contingent on
			// d.Op(1), which should fail).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 0, 10, 1); err != nil || n != 0 {
				t.Errorf("WakeOp: got (%d, %v), wanted (0, nil)", n, err)
			}

			// Expect that neither waiter was woken.
			if w1.woken() {
				t.Error("w1 woken unexpectedly")
			}
			if w2.woken() {
				t.Error("w2 woken unexpectedly")
			}
		})
	}
}

func TestWakeOpAllNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Add two waiters on address sizeofInt32.
			w3 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w3)
			w4 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w4)

			// Perform 10 wakeups on address 0 (unconditionally), and 10
			// wakeups on address sizeofInt32 (contingent on d.Op(0), which
			// should succeed).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 0); err != nil || n != 4 {
				t.Errorf("WakeOp: got (%d, %v), wanted (4, nil)", n, err)
			}

			// Expect that all waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
			if !w3.woken() {
				t.Error("w3 not woken")
			}
			if !w4.woken() {
				t.Error("w4 not woken")
			}
		})
	}
}

func TestWakeOpAllNonEmptyFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2)

			// Add two waiters on address sizeofInt32.
			w3 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w3)
			w4 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w4)

			// Perform 10 wakeups on address 0 (unconditionally), and 10
			// wakeups on address sizeofInt32 (contingent on d.Op(1), which
			// should fail).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 1); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that only the first two waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
			if w3.woken() {
				t.Error("w3 woken unexpectedly")
			}
			if w4.woken() {
				t.Error("w4 woken unexpectedly")
			}
		})
	}
}

func TestWakeOpSameAddress(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add four waiters on address 0.
			var ws [4]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i])
			}

			// Perform 1 wakeup on address 0 (unconditionally), and 1 wakeup
			// on address 0 (contingent on d.Op(0), which should succeed).
			const wakeups = 2
			if n, err := m.WakeOp(d, 0, 0, private, 1, 1, 0); err != nil || n != wakeups {
				t.Errorf("WakeOp: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly two waiters were woken.
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

func TestWakeOpSameAddressFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add four waiters on address 0.
			var ws [4]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i])
			}

			// Perform 1 wakeup on address 0 (unconditionally), and 1 wakeup
			// on address 0 (contingent on d.Op(1), which should fail).
			const wakeups = 1
			if n, err := m.WakeOp(d, 0, 0, private, 1, 1, 1); err != nil || n != wakeups {
				t.Errorf("WakeOp: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly one waiter was woken.
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

const (
	testMutexSize            = sizeofInt32
	testMutexLocked   uint32 = 1
	testMutexUnlocked uint32 = 0
)

// testMutex ties together a testData slice, an address, and a
// futex manager in order to implement the sync.Locker interface.
// Beyond being used as a Locker, this is a simple mechanism for
// changing the underlying values for simpler tests.
type testMutex struct {
	a usermem.Addr
	d testData
	m *Manager
}

func newTestMutex(addr usermem.Addr, d testData, m *Manager) *testMutex {
	return &testMutex{a: addr, d: d, m: m}
}

// Lock acquires the testMutex.
// This may wait for it to be available via the futex manager.
func (t *testMutex) Lock() {
	for {
		// Attempt to grab the lock.
		if atomic.CompareAndSwapUint32(
			(*uint32)(unsafe.Pointer(&t.d[t.a])),
			testMutexUnlocked,
			testMutexLocked) {
			// Lock held.
			return
		}

		// Wait for it to be "not locked".
		w := NewWaiter()
		err := t.m.WaitPrepare(w, t.d, t.a, true, testMutexLocked, ^uint32(0))
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
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&t.d[t.a])), testMutexUnlocked)

	// Notify all waiters.
	t.m.Wake(t.d, t.a, true, ^uint32(0), math.MaxInt32)
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

func TestMutexStress(t *testing.T) {
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
