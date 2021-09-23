package auth

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
//
// +stateify savable
type AtomicPtrCredentials struct {
	ptr unsafe.Pointer `state:".(*Credentials)"`
}

func (p *AtomicPtrCredentials) savePtr() *Credentials {
	return p.Load()
}

func (p *AtomicPtrCredentials) loadPtr(v *Credentials) {
	p.Store(v)
}

// Load returns the value set by the most recent Store. It returns nil if there
// has been no previous call to Store.
//
//go:nosplit
func (p *AtomicPtrCredentials) Load() *Credentials {
	return (*Credentials)(atomic.LoadPointer(&p.ptr))
}

// Store sets the value returned by Load to x.
func (p *AtomicPtrCredentials) Store(x *Credentials) {
	atomic.StorePointer(&p.ptr, (unsafe.Pointer)(x))
}
