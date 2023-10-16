// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"sync/atomic"
)

// SeqCount is a synchronization primitive for optimistic reader/writer
// synchronization in cases where readers can work with stale data and
// therefore do not need to block writers.
//
// Compared to sync/atomic.Value:
//
//   - Mutation of SeqCount-protected data does not require memory allocation,
//     whereas atomic.Value generally does. This is a significant advantage when
//     writes are common.
//
//   - Atomic reads of SeqCount-protected data require copying. This is a
//     disadvantage when atomic reads are common.
//
//   - SeqCount may be more flexible: correct use of SeqCount.ReadOk allows other
//     operations to be made atomic with reads of SeqCount-protected data.
//
//   - SeqCount is more cumbersome to use; atomic reads of SeqCount-protected
//     data require instantiating function templates using go_generics (see
//     seqatomic.go).
type SeqCount struct {
	// epoch is incremented by BeginWrite and EndWrite, such that epoch is odd
	// if a writer critical section is active, and a read from data protected
	// by this SeqCount is atomic iff epoch is the same even value before and
	// after the read.
	epoch uint32
}

// SeqCountEpoch tracks writer critical sections in a SeqCount.
type SeqCountEpoch uint32

// BeginRead indicates the beginning of a reader critical section. Reader
// critical sections DO NOT BLOCK writer critical sections, so operations in a
// reader critical section MAY RACE with writer critical sections. Races are
// detected by ReadOk at the end of the reader critical section. Thus, the
// low-level structure of readers is generally:
//
//	for {
//	    epoch := seq.BeginRead()
//	    // do something idempotent with seq-protected data
//	    if seq.ReadOk(epoch) {
//	        break
//	    }
//	}
//
// However, since reader critical sections may race with writer critical
// sections, the Go race detector will (accurately) flag data races in readers
// using this pattern. Most users of SeqCount will need to use the
// SeqAtomicLoad function template in seqatomic.go.
func (s *SeqCount) BeginRead() SeqCountEpoch {
	if epoch := atomic.LoadUint32(&s.epoch); epoch&1 == 0 {
		return SeqCountEpoch(epoch)
	}
	return s.beginReadSlow()
}

func (s *SeqCount) beginReadSlow() SeqCountEpoch {
	i := 0
	for {
		if canSpin(i) {
			i++
			doSpin()
		} else {
			goyield()
		}
		if epoch := atomic.LoadUint32(&s.epoch); epoch&1 == 0 {
			return SeqCountEpoch(epoch)
		}
	}
}

// ReadOk returns true if the reader critical section initiated by a previous
// call to BeginRead() that returned epoch did not race with any writer critical
// sections.
//
// ReadOk may be called any number of times during a reader critical section.
// Reader critical sections do not need to be explicitly terminated; the last
// call to ReadOk is implicitly the end of the reader critical section.
func (s *SeqCount) ReadOk(epoch SeqCountEpoch) bool {
	MemoryFenceReads()
	return atomic.LoadUint32(&s.epoch) == uint32(epoch)
}

// BeginWrite indicates the beginning of a writer critical section.
//
// SeqCount does not support concurrent writer critical sections; clients with
// concurrent writers must synchronize them using e.g. sync.Mutex.
func (s *SeqCount) BeginWrite() {
	if epoch := atomic.AddUint32(&s.epoch, 1); epoch&1 == 0 {
		panic("SeqCount.BeginWrite during writer critical section")
	}
}

// BeginWriteOk combines the semantics of ReadOk and BeginWrite. If the reader
// critical section initiated by a previous call to BeginRead() that returned
// epoch did not race with any writer critical sections, it begins a writer
// critical section and returns true. Otherwise it does nothing and returns
// false.
func (s *SeqCount) BeginWriteOk(epoch SeqCountEpoch) bool {
	return atomic.CompareAndSwapUint32(&s.epoch, uint32(epoch), uint32(epoch)+1)
}

// EndWrite ends the effect of a preceding BeginWrite or successful
// BeginWriteOk.
func (s *SeqCount) EndWrite() {
	if epoch := atomic.AddUint32(&s.epoch, 1); epoch&1 != 0 {
		panic("SeqCount.EndWrite outside writer critical section")
	}
}
