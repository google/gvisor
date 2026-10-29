// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"math/rand"
	"testing"
)

func TestAddrMap(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, initial := range []int{0, 1, 1000} {
		var m addrMap
		if initial > 0 {
			m.init(initial)
		}
		want := make(map[uintptr]int32)
		for round := 0; round < 3; round++ {
			for i := 0; i < 5000; i++ {
				// Use clustered keys, like addresses, and zero.
				k := uintptr(r.Intn(20000)) * 8
				if i%3 == 0 {
					k = uintptr(r.Uint64())
				}
				if k == ^uintptr(0) {
					continue
				}
				v := int32(r.Intn(1 << 30))
				m.set(k, v)
				want[k] = v
			}
			for k, v := range want {
				if got, ok := m.get(k); !ok || got != v {
					t.Fatalf("get(%#x) = %d, %t, want %d, true", k, got, ok, v)
				}
			}
			for i := 0; i < 1000; i++ {
				k := uintptr(r.Intn(40000))*8 + 4
				got, gotOK := m.get(k)
				wantV, wantOK := want[k]
				if got != wantV || gotOK != wantOK {
					t.Fatalf("get(%#x) = (%d, %t), want (%d, %t)", k, got, gotOK, wantV, wantOK)
				}
			}
			if m.n != len(want) {
				t.Fatalf("got %d entries, want %d", m.n, len(want))
			}
			m.reset()
			clear(want)
			if _, ok := m.get(8); ok {
				t.Fatalf("get after reset found a key")
			}
			if _, ok := m.get(^uintptr(0)); ok {
				t.Fatalf("get(max uintptr) unexpectedly succeeded")
			}
		}
	}

	var m addrMap
	m.set(0, 7)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("set(max uintptr) did not fail")
			}
		}()
		m.set(^uintptr(0), 1)
	}()
	if got, ok := m.get(0); !ok || got != 7 {
		t.Fatalf("get(0) = %d, %t, want 7, true", got, ok)
	}
}
