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

package ringdeque

import (
	"testing"
)

const numElems = 100

func TestDeque(t *testing.T) {
	for _, test := range []struct {
		desc     string
		push     func(d *Deque[int], val int)
		pop      func(d *Deque[int]) int
		reversed bool
	}{
		{
			desc:     "PushFrontPopFront",
			push:     (*Deque[int]).PushFront,
			pop:      (*Deque[int]).PopFront,
			reversed: true,
		},
		{
			desc:     "PushFrontPopBack",
			push:     (*Deque[int]).PushFront,
			pop:      (*Deque[int]).PopBack,
			reversed: false,
		},
		{
			desc:     "PushBackPopFront",
			push:     (*Deque[int]).PushBack,
			pop:      (*Deque[int]).PopFront,
			reversed: false,
		},
		{
			desc:     "PushBackPopBack",
			push:     (*Deque[int]).PushBack,
			pop:      (*Deque[int]).PopBack,
			reversed: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			var d Deque[int]
			if !d.Empty() {
				t.Errorf("zero-value Deque non-empty")
			}
			if got := d.Len(); got != 0 {
				t.Errorf("zero-value Deque.Len: got %d, want 0", got)
			}
			for i := 0; i < numElems; i++ {
				test.push(&d, i)
				if d.Empty() {
					t.Errorf("Deque empty after %d pushes", i+1)
				}
				if got, want := d.Len(), i+1; got != want {
					t.Errorf("Len: got %d, want %d", got, want)
				}
			}
			for i := 0; i < numElems; i++ {
				want := i
				if test.reversed {
					want = numElems - 1 - i
				}
				if got := test.pop(&d); got != want {
					t.Errorf("pop %d: got %d, want %d", i, got, want)
				}
			}
			if !d.Empty() {
				t.Errorf("Deque non-empty after all removals")
			}
			if got := d.Len(); got != 0 {
				t.Errorf("Len after all removals: got %d, want 0", got)
			}
		})
	}
}
