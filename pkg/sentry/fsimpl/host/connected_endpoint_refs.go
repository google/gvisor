package host

import (
	"fmt"
	"runtime"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/log"
	refs_vfs1 "gvisor.dev/gvisor/pkg/refs"
)

// ownerType is used to customize logging. Note that we use a pointer to T so
// that we do not copy the entire object when passed as a format parameter.
var ConnectedEndpointownerType *ConnectedEndpoint

// Refs implements refs.RefCounter. It keeps a reference count using atomic
// operations and calls the destructor when the count reaches zero.
//
// Note that the number of references is actually refCount + 1 so that a default
// zero-value Refs object contains one reference.
//
// TODO(gvisor.dev/issue/1486): Store stack traces when leak check is enabled in
// a map with 16-bit hashes, and store the hash in the top 16 bits of refCount.
// This will allow us to add stack trace information to the leak messages
// without growing the size of Refs.
//
// +stateify savable
type ConnectedEndpointRefs struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a CompareAndSwap
	// loop. See IncRef, DecRef and TryIncRef for details of how these fields are
	// used.
	refCount int64
}

func (r *ConnectedEndpointRefs) finalize() {
	var note string
	switch refs_vfs1.GetLeakMode() {
	case refs_vfs1.NoLeakChecking:
		return
	case refs_vfs1.UninitializedLeakChecking:
		note = "(Leak checker uninitialized): "
	}
	if n := r.ReadRefs(); n != 0 {
		log.Warningf("%sRefs %p owned by %T garbage collected with ref count of %d (want 0)", note, r, ConnectedEndpointownerType, n)
	}
}

// EnableLeakCheck checks for reference leaks when Refs gets garbage collected.
func (r *ConnectedEndpointRefs) EnableLeakCheck() {
	if refs_vfs1.GetLeakMode() != refs_vfs1.NoLeakChecking {
		runtime.SetFinalizer(r, (*ConnectedEndpointRefs).finalize)
	}
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *ConnectedEndpointRefs) ReadRefs() int64 {

	return atomic.LoadInt64(&r.refCount) + 1
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *ConnectedEndpointRefs) IncRef() {
	if v := atomic.AddInt64(&r.refCount, 1); v <= 0 {
		panic(fmt.Sprintf("Incrementing non-positive ref count %p owned by %T", r, ConnectedEndpointownerType))
	}
}

// TryIncRef implements refs.RefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *ConnectedEndpointRefs) TryIncRef() bool {
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
func (r *ConnectedEndpointRefs) DecRef(destroy func()) {
	switch v := atomic.AddInt64(&r.refCount, -1); {
	case v < -1:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %T", r, ConnectedEndpointownerType))

	case v == -1:

		if destroy != nil {
			destroy()
		}
	}
}
