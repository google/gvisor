// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package atomicptr

import (
	"testing"
)

func newInt(val int) *int {
	return &val
}

func TestAtomicPtr(t *testing.T) {
	var p AtomicPtrInt
	if got := p.Load(); got != nil {
		t.Errorf("initial value is %p (%v), wanted nil", got, got)
	}
	want := newInt(42)
	p.Store(want)
	if got := p.Load(); got != want {
		t.Errorf("wrong value: got %p (%v), wanted %p (%v)", got, got, want, want)
	}
	want = newInt(100)
	p.Store(want)
	if got := p.Load(); got != want {
		t.Errorf("wrong value: got %p (%v), wanted %p (%v)", got, got, want, want)
	}
}
