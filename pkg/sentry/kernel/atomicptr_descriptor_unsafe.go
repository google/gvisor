package kernel

import (
	"context"
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
type descriptorAtomicPtr struct {
	ptr unsafe.Pointer `state:".(*descriptor)"`
}

func (p *descriptorAtomicPtr) savePtr() *descriptor {
	return p.Load()
}

func (p *descriptorAtomicPtr) loadPtr(_ context.Context, v *descriptor) {
	p.Store(v)
}

// Load returns the value set by the most recent Store. It returns nil if there
// has been no previous call to Store.
//
//go:nosplit
func (p *descriptorAtomicPtr) Load() *descriptor {
	return (*descriptor)(atomic.LoadPointer(&p.ptr))
}

// Store sets the value returned by Load to x.
func (p *descriptorAtomicPtr) Store(x *descriptor) {
	atomic.StorePointer(&p.ptr, (unsafe.Pointer)(x))
}

// Swap atomically stores `x` into *p and returns the previous *p value.
func (p *descriptorAtomicPtr) Swap(x *descriptor) *descriptor {
	return (*descriptor)(atomic.SwapPointer(&p.ptr, (unsafe.Pointer)(x)))
}
