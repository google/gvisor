// Copyright 2018 Google Inc.
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
