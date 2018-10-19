// Copyright 2018 Google LLC
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

package p9

import (
	"testing"
)

func TestPoolUnique(t *testing.T) {
	p := pool{start: 1, limit: 3}
	got := make(map[uint64]bool)

	for {
		n, ok := p.Get()
		if !ok {
			break
		}

		// Check unique.
		if _, ok := got[n]; ok {
			t.Errorf("pool spit out %v multiple times", n)
		}

		// Record.
		got[n] = true
	}
}

func TestExausted(t *testing.T) {
	p := pool{start: 1, limit: 500}
	for i := 0; i < 499; i++ {
		_, ok := p.Get()
		if !ok {
			t.Fatalf("pool exhausted before 499 items")
		}
	}

	_, ok := p.Get()
	if ok {
		t.Errorf("pool not exhausted when it should be")
	}
}

func TestPoolRecycle(t *testing.T) {
	p := pool{start: 1, limit: 500}
	n1, _ := p.Get()
	p.Put(n1)
	n2, _ := p.Get()
	if n1 != n2 {
		t.Errorf("pool not recycling items")
	}
}
