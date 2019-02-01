// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package template doesn't exist. This file must be instantiated using the
// go_template_instance rule in tools/go_generics/defs.bzl.
package template

import (
	"sync/atomic"
	"unsafe"
)

// Value is a required type parameter.
type Value struct{}

// An AtomicPtr is a pointer to a value of type Value that can be atomically
// loaded and stored. The zero value of an AtomicPtr represents nil.
//
// Note that copying AtomicPtr by value performs a non-atomic read of the
// stored pointer, which is unsafe if Store() can be called concurrently; in
// this case, do `dst.Store(src.Load())` instead.
type AtomicPtr struct {
	ptr unsafe.Pointer
}

// Load returns the value set by the most recent Store. It returns nil if there
// has been no previous call to Store.
func (p *AtomicPtr) Load() *Value {
	return (*Value)(atomic.LoadPointer(&p.ptr))
}

// Store sets the value returned by Load to x.
func (p *AtomicPtr) Store(x *Value) {
	atomic.StorePointer(&p.ptr, (unsafe.Pointer)(x))
}
