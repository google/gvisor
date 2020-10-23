package mm

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// ownerType is used to customize logging. Note that we use a pointer to T so
// that we do not copy the entire object when passed as a format parameter.
var SpecialMappableownerType *SpecialMappable

// Refs implements refs.RefCounter. It keeps a reference count using atomic
// operations and calls the destructor when the count reaches zero.
//
// Note that the number of references is actually refCount + 1 so that a default
// zero-value Refs object contains one reference.
//
// +stateify savable
type SpecialMappableRefs struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a CompareAndSwap
	// loop. See IncRef, DecRef and TryIncRef for details of how these fields are
	// used.
	refCount int64
}

// EnableLeakCheck enables reference leak checking on r.
func (r *SpecialMappableRefs) EnableLeakCheck() {
	if refsvfs2.LeakCheckEnabled() {
		refsvfs2.Register(r, fmt.Sprintf("%T", SpecialMappableownerType))
	}
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
func (r *SpecialMappableRefs) LeakMessage() string {
	return fmt.Sprintf("%T %p: reference count of %d instead of 0", SpecialMappableownerType, r, r.ReadRefs())
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *SpecialMappableRefs) ReadRefs() int64 {

	return atomic.LoadInt64(&r.refCount) + 1
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *SpecialMappableRefs) IncRef() {
	if v := atomic.AddInt64(&r.refCount, 1); v <= 0 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %T", r, SpecialMappableownerType))
	}
}

// TryIncRef implements refs.RefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *SpecialMappableRefs) TryIncRef() bool {
	const speculativeRef = 1 << 32
	v := atomic.AddInt64(&r.refCount, speculativeRef)
	if int32(v) < 0 {

		atomic.AddInt64(&r.refCount, -speculativeRef)
		return false
	}

	atomic.AddInt64(&r.refCount, -speculativeRef+1)
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
func (r *SpecialMappableRefs) DecRef(destroy func()) {
	switch v := atomic.AddInt64(&r.refCount, -1); {
	case v < -1:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %T", r, SpecialMappableownerType))

	case v == -1:
		if refsvfs2.LeakCheckEnabled() {
			refsvfs2.Unregister(r, fmt.Sprintf("%T", SpecialMappableownerType))
		}

		if destroy != nil {
			destroy()
		}
	}
}

func (r *SpecialMappableRefs) afterLoad() {
	if refsvfs2.LeakCheckEnabled() && r.ReadRefs() > 0 {
		r.EnableLeakCheck()
	}
}
