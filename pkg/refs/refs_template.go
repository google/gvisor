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

// Package refs provides reference counting helpers with leak checking.
package refs

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// These type definitions must have different GC shapes to ensure that
// the Go compiler generates distinct code paths for them.
//
// This is borrowed from `pkg/bpf/input_bytes.go`.
type (
	// loggingDisabled indicates that reference-related events should not be logged.
	// This should be the default, as logging can be extremely noisy and expensive.
	loggingDisabled uint8

	// loggingEnabled indicates that reference-related events should be logged with
	// stack traces. This is intended for debugging only.
	loggingEnabled uint16
)

type loggingPolicy interface {
	loggingDisabled | loggingEnabled
}

type Refs[T any] = RefsBase[T, loggingDisabled]
type LoggedRefs[T any] = RefsBase[T, loggingEnabled]

// RefsBase implements RefCounter. It keeps a reference count using atomic
// operations and calls the destructor when the count reaches zero.
//
// NOTE: Do not introduce additional fields to the RefsBase struct. It is used by
// many filesystem objects, and we want to keep it as small as possible (i.e.,
// the same size as using an int64 directly) to avoid taking up extra cache
// space. In general, this template should not be extended at the cost of
// performance. If it does not offer enough flexibility for a particular object
// (example: b/187877947), we should implement the RefCounter/CheckedObject
// interfaces manually.
//
// +stateify savable
type RefsBase[T any, L loggingPolicy] struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a CompareAndSwap
	// loop. See IncRef, DecRef and TryIncRef for details of how these fields are
	// used.
	refCount atomicbitops.Int64
}

// InitRefs initializes r with one reference and, if enabled, activates leak
// checking.
func (r *RefsBase[T, L]) InitRefs() {
	// We can use RacyStore because the refs can't be shared until after
	// InitRefs is called, and thus it's safe to use non-atomic operations.
	r.refCount.RacyStore(1)
	Register(r)
}

// RefType implements refs.CheckedObject.RefType.
func (r *RefsBase[T, L]) RefType() string {
	var obj *T
	return fmt.Sprintf("%T", obj)[1:]
}

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (r *RefsBase[T, L]) LeakMessage() string {
	return fmt.Sprintf("[%s %p] reference count of %d instead of 0", r.RefType(), r, r.ReadRefs())
}

// LogRefs implements refs.CheckedObject.LogRefs.
func (r *RefsBase[T, L]) LogRefs() bool {
	var l L
	switch any(l).(type) {
	case loggingDisabled:
		return false
	case loggingEnabled:
		return true
	default:
		panic("unreachable")
	}
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *RefsBase[T, L]) ReadRefs() int64 {
	return r.refCount.Load()
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *RefsBase[T, L]) IncRef() {
	v := r.refCount.Add(1)
	if r.LogRefs() {
		LogIncRef(r, v)
	}
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", r, r.RefType()))
	}
}

// TryIncRef implements refs.TryRefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *RefsBase[T, L]) TryIncRef() bool {
	const speculativeRef = 1 << 32
	if v := r.refCount.Add(speculativeRef); int32(v) == 0 {
		// This object has already been freed.
		r.refCount.Add(-speculativeRef)
		return false
	}

	// Turn into a real reference.
	v := r.refCount.Add(-speculativeRef + 1)
	if r.LogRefs() {
		LogTryIncRef(r, v)
	}
	return true
}

// DecRef implements refs.RefCounter.DecRef.
//
// Note that speculative references are counted here. Since they were added
// prior to real references reaching zero, they will successfully convert to
// real references. In other words, we see speculative references only in the
// following case:
//
//	A: TryIncRef [speculative increase => sees non-negative references]
//	B: DecRef [real decrease]
//	A: TryIncRef [transform speculative to real]
//
//go:nosplit
func (r *RefsBase[T, L]) DecRef(destroy func()) {
	v := r.refCount.Add(-1)
	if r.LogRefs() {
		LogDecRef(r, v)
	}
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", r, r.RefType()))

	case v == 0:
		Unregister(r)
		// Call the destructor.
		if destroy != nil {
			destroy()
		}
	}
}

func (r *RefsBase[T, L]) afterLoad(context.Context) {
	if r.ReadRefs() > 0 {
		Register(r)
	}
}
