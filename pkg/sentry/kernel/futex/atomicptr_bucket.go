package futex

import (
	"sync/atomic"
	"unsafe"
)

// An AtomicPtr is a pointer to a value of type Value that can be atomically
// loaded and stored. The zero value of an AtomicPtr represents nil.
//
// Note that copying AtomicPtr by value performs a non-atomic read of the
// stored pointer, which is unsafe if Store() can be called concurrently; in
// this case, do `dst.Store(src.Load())` instead.
type AtomicPtrBucket struct {
	ptr unsafe.Pointer
}

// Load returns the value set by the most recent Store. It returns nil if there
// has been no previous call to Store.
func (p *AtomicPtrBucket) Load() *bucket {
	return (*bucket)(atomic.LoadPointer(&p.ptr))
}

// Store sets the value returned by Load to x.
func (p *AtomicPtrBucket) Store(x *bucket) {
	atomic.StorePointer(&p.ptr, (unsafe.Pointer)(x))
}
