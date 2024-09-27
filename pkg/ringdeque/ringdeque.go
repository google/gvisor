// Copyright 2024 The gVisor Authors.
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

// Package ringdeque provides the Deque type.
package ringdeque

// A Deque implements a double-ended queue of values of type T using a
// resizable ring buffer.
//
// Deque is not safe to use concurrently from multiple goroutines.
type Deque[T any] struct {
	// Items [off, off+len) modulo len(buf) in buf are valid.
	// Invariants:
	// - len(buf) is 0 or a power of 2.
	// - If len(buf) == 0, off == 0; otherwise off < len(buf).
	off uint64
	len uint64
	buf []T
}

// Preconditions: d.len == len(d.buf).
func (d *Deque[T]) expand() {
	newLen := 2 // arbitrary minimum
	if d.len != 0 {
		newLen = len(d.buf) * 2
	}
	newBuf := make([]T, newLen)
	// By precondition, we need to copy every element in d.buf.
	n := copy(newBuf, d.buf[d.off:])
	copy(newBuf[n:], d.buf[:d.off])
	d.off = 0
	d.buf = newBuf
}

func (d *Deque[T]) mask() uint64 {
	return uint64(len(d.buf)) - 1
}

// Empty returns true if r contains no values.
func (d *Deque[T]) Empty() bool {
	return d.len == 0
}

// Len returns the number of values in d.
func (d *Deque[T]) Len() int {
	return int(d.len)
}

// Clear removes all values from d.
func (d *Deque[T]) Clear() {
	d.len = 0
}

// PushFront inserts x at the front of d.
func (d *Deque[T]) PushFront(x T) {
	if int(d.len) == len(d.buf) {
		d.expand()
	}
	newOff := (d.off - 1) & d.mask()
	d.buf[newOff] = x
	d.off = newOff
	d.len++
}

// PushBack inserts x at the back of d.
func (d *Deque[T]) PushBack(x T) {
	if int(d.len) == len(d.buf) {
		d.expand()
	}
	i := (d.off + d.len) & d.mask()
	d.buf[i] = x
	d.len++
}

// PeekFront returns the value at the front of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PeekFront() T {
	return *d.PeekFrontPtr()
}

// PeekFrontPtr returns a pointer to the value at the front of d. The pointer
// is only valid until the next mutation of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PeekFrontPtr() *T {
	if d.Empty() {
		panic("peek of empty Deque")
	}
	return &d.buf[d.off]
}

// PeekBack returns the value at the back of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PeekBack() T {
	return *d.PeekBackPtr()
}

// PeekBackPtr returns a pointer to the value at the back of d. The pointer is
// only valid until the next mutation of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PeekBackPtr() *T {
	if d.Empty() {
		panic("peek of empty Deque")
	}
	i := (d.off + d.len - 1) & d.mask()
	return &d.buf[i]
}

// RemoveFront removes the value at the front of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) RemoveFront() {
	d.off = (d.off + 1) & d.mask()
	d.len--
}

// RemoveBack removes the value at the back of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) RemoveBack() {
	d.len--
}

// PopFront removes and returns the value at the front of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PopFront() (x T) {
	x = d.PeekFront()
	d.RemoveFront()
	return
}

// PopBack removes and returns the value at the back of d.
//
// Preconditions: !d.Empty().
func (d *Deque[T]) PopBack() (x T) {
	x = d.PeekBack()
	d.RemoveBack()
	return
}
