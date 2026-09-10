// Copyright 2020 The gVisor Authors.
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

package test

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

type atomicStruct struct {
	accessedNormally int32

	// +checkatomic
	accessedAtomically int32

	// +checklocksignore
	ignored int32

	wrapper atomic.Int32 // safe without any annotations
	bitops  atomicbitops.Int32

	// +checkatomic
	atomicBitops atomicbitops.Int32

	// +checkatomic
	pointer atomic.Pointer[int32]
}

func testNormalAccess(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- tc.accessedNormally
	p <- &tc.accessedNormally
}

func testAtomicAccess(tc *atomicStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedAtomically)
	_ = tc.pointer.Load()
	tc.pointer.Store(nil)
	defer tc.pointer.Store(nil)
	defer atomic.StoreInt32(&tc.accessedAtomically, 1)
	go tc.pointer.Store(nil)
}

func testAtomicAccessInvalid(tc *atomicStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedNormally)      // +checklocksfail
	defer atomic.StoreInt32(&tc.accessedNormally, 1) // +checklocksfail=unexpected call to atomic function
	go atomic.StoreInt32(&tc.accessedNormally, 1)    // +checklocksfail=unexpected call to atomic function
}

func testNormalAccessInvalid(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- tc.accessedAtomically              // +checklocksfail
	p <- &tc.accessedAtomically             // +checklocksfail
	_ = genericLoad(&tc.accessedAtomically) // +checklocksfail=non-atomic function
	// Keep this return-valued call directly deferred: a wrapper discarding
	// its result would test a closure instead of the operation's SSA Defer.
	defer genericLoad(&tc.accessedAtomically) // +checklocksforce
	// An atomic pointer payload is not the atomic location being accessed.
	var sink atomic.Pointer[int32]
	sink.Store(&tc.accessedAtomically)       // +checklocksfail=illegal use
	defer sink.Store(&tc.accessedAtomically) // +checklocksfail=illegal use
	*sink.Load() = 1
}

func genericLoad[T any](p *T) T {
	return *p
}

func testIgnored(tc *atomicStruct, v chan int32, p chan *int32) {
	v <- atomic.LoadInt32(&tc.ignored)
	v <- tc.ignored
	p <- &tc.ignored
}

type atomicMixedStruct struct {
	mu sync.RWMutex

	// +checkatomic
	// +checklocks:mu
	accessedMixed int32

	// +checkatomic
	// +checklocks:mu
	wrapper atomic.Int32

	// +checkatomic
	// +checklocks:mu
	bitops atomicbitops.Int32

	// +checkatomic
	// +checklocks:mu
	pointer atomic.Pointer[int32]
}

func testAtomicMixedValidRead(tc *atomicMixedStruct, v chan int32) {
	v <- atomic.LoadInt32(&tc.accessedMixed)
	v <- tc.wrapper.Load()
	_ = tc.pointer.Load()
}

func testAtomicMixedInvalidRead(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	v <- tc.accessedMixed  // +checklocksfail
	p <- &tc.accessedMixed // +checklocksfail
}

func testAtomicMixedValidLockedWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.mu.Lock()
	atomic.StoreInt32(&tc.accessedMixed, 1)
	tc.wrapper.Store(1)
	tc.pointer.Store(nil)
	tc.mu.Unlock()
}

func testAtomicMixedReadLocked(tc *atomicMixedStruct) {
	tc.mu.RLock()
	defer tc.pointer.Store(nil) // +checklocksfail=illegal use
	go tc.pointer.Store(nil)    // +checklocksfail=illegal use
	_ = atomic.LoadInt32(&tc.accessedMixed)
	_ = tc.accessedMixed
	_ = tc.wrapper.Load()
	_ = tc.bitops.RacyLoad()
	_ = tc.pointer.Load()
	atomic.StoreInt32(&tc.accessedMixed, 1) // +checklocksfail=write function
	tc.wrapper.Store(1)                     // +checklocksfail=write function
	tc.bitops.Store(1)                      // +checklocksfail=write function
	tc.bitops.RacyStore(1)                  // +checklocksfail=operation RacyStore
	tc.pointer.Store(nil)                   // +checklocksfail=write function
	tc.mu.RUnlock()
}

// Mixed deferred accesses are unsupported even when execution order is safe.
func testAtomicMixedDeferred(tc *atomicMixedStruct, unlockFirst bool) {
	tc.mu.Lock()
	if unlockFirst {
		defer tc.pointer.Store(nil) // +checklocksfail=illegal use
		defer tc.mu.Unlock()
	} else {
		defer tc.mu.Unlock()
		defer tc.pointer.Store(nil) // +checklocksfail=illegal use
	}
}

func testAtomicMixedInvalidLockedWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.mu.Lock()
	tc.accessedMixed = 1 // +checklocksfail=illegal use of atomic-only field|non-atomic write of field accessedMixed
	tc.mu.Unlock()
}

func testAtomicMixedInvalidAtomicWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	atomic.StoreInt32(&tc.accessedMixed, 1) // +checklocksfail
	tc.wrapper.Store(1)                     // +checklocksfail
	tc.pointer.Store(nil)                   // +checklocksfail=write function
}

func testAtomicMixedInvalidWrite(tc *atomicMixedStruct, v chan int32, p chan *int32) {
	tc.accessedMixed = 1 // +checklocksfail=illegal use of atomic-only field|non-atomic write of field accessedMixed
	tc.wrapper.Store(1)  // +checklocksfail
}

func testAtomicWrapper(tc *atomicStruct, v chan int32) {
	v <- tc.wrapper.Load()
	v <- tc.wrapper.Add(33)
	tc.wrapper.Store(44)
	defer tc.wrapper.Store(44)
	v <- tc.bitops.RacyLoad()
	v <- tc.bitops.RacyAdd(33)
	tc.bitops.RacyStore(44)
}

func testAtomicBitops(tc *atomicStruct) {
	// Keep direct defers, including the unused result, to check the SSA Defer
	// path rather than a closure that invokes the operation later.
	defer tc.atomicBitops.RacyLoad()   // +checklocksfail=non-atomic operation
	defer tc.atomicBitops.RacyStore(1) // +checklocksfail=non-atomic operation
	_ = tc.atomicBitops.Load()
	tc.atomicBitops.Store(1)
	_ = tc.atomicBitops.Add(1)
	_ = tc.atomicBitops.RacyLoad() // +checklocksfail=non-atomic operation
	tc.atomicBitops.RacyStore(1)   // +checklocksfail=non-atomic operation
	_ = tc.atomicBitops.RacyAdd(1) // +checklocksfail=non-atomic operation
}

func testAtomicMixedBitops(tc *atomicMixedStruct) {
	_ = tc.bitops.Load()
	tc.bitops.Store(1)       // +checklocksfail=unexpected call to atomic write function
	_ = tc.bitops.Add(1)     // +checklocksfail=unexpected call to atomic write function
	_ = tc.bitops.RacyLoad() // +checklocksfail=non-atomic operation
	tc.bitops.RacyStore(1)   // +checklocksfail=non-atomic operation
	_ = tc.bitops.RacyAdd(1) // +checklocksfail=non-atomic operation

	tc.mu.Lock()
	_ = tc.bitops.Load()
	tc.bitops.Store(1)
	_ = tc.bitops.Add(1)
	_ = tc.bitops.RacyLoad()
	tc.bitops.RacyStore(1)   // +checklocksfail=non-atomic operation
	_ = tc.bitops.RacyAdd(1) // +checklocksfail=non-atomic operation
	tc.mu.Unlock()
}

// atomicReadAnyStruct permits unlocked atomic reads and non-atomic reads
// under either lock. Writes need both locks.
type atomicReadAnyStruct struct {
	mu      sync.Mutex
	otherMu sync.RWMutex

	// +checklocks:mu
	// +checklocks:otherMu
	// +checklocksreadany
	// +checkatomic
	wrapper atomicbitops.Int32

	// +checklocks:mu
	// +checklocks:otherMu
	// +checklocksreadany
	// +checkatomic
	value int32
}

func testAtomicReadAny(tc *atomicReadAnyStruct) {
	_ = tc.wrapper.Load()
	_ = tc.wrapper.RacyLoad() // +checklocksfail=non-atomic operation
	_ = tc.value              // +checklocksfail=illegal use

	tc.mu.Lock()
	_ = tc.wrapper.RacyLoad()
	_ = tc.value
	tc.wrapper.Store(1)    // +checklocksfail=write function
	_ = tc.wrapper.Swap(1) // +checklocksfail=write function
	tc.mu.Unlock()

	tc.otherMu.RLock()
	_ = tc.wrapper.RacyLoad()
	_ = tc.value
	_ = tc.wrapper.Add(1) // +checklocksfail=write function
	tc.mu.Lock()
	tc.wrapper.Store(1) // +checklocksfail=write function
	tc.otherMu.RUnlock()
	tc.otherMu.Lock()
	tc.wrapper.Store(1)
	_ = tc.wrapper.Add(1)
	tc.wrapper.RacyStore(1) // +checklocksfail=non-atomic operation
	tc.otherMu.Unlock()
	tc.mu.Unlock()
}

func testAtomicReadAnyRetained(tc *atomicReadAnyStruct, read bool) {
	tc.mu.Lock()
	p := &tc.wrapper
	tc.mu.Unlock()
	_ = p.RacyLoad() // +checklocksfail=non-atomic operation

	tc.mu.Lock()
	p = &tc.wrapper
	_ = p.RacyLoad() // +checklocksfail=non-atomic operation
	tc.mu.Unlock()
	_ = p.RacyLoad() // +checklocksfail=non-atomic operation

	// Even when the lock remains held, only immediate uses are supported.
	tc.mu.Lock()
	p = &tc.wrapper
	if read {
		_ = p.RacyLoad() // +checklocksfail=non-atomic operation
	}
	tc.mu.Unlock()
}
