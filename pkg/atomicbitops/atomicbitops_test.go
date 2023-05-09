// Copyright 2018 The gVisor Authors.
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

// +checkalignedignore
package atomicbitops

import (
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
)

const iterations = 100

func detectRaces32(val, target uint32, fn func(*Uint32, uint32)) bool {
	runtime.GOMAXPROCS(100)
	for n := 0; n < iterations; n++ {
		x := FromUint32(val)
		var wg sync.WaitGroup
		for i := uint32(0); i < 32; i++ {
			wg.Add(1)
			go func(a *Uint32, i uint32) {
				defer wg.Done()
				fn(a, uint32(1<<i))
			}(&x, i)
		}
		wg.Wait()
		if x != FromUint32(target) {
			return true
		}
	}
	return false
}

func detectRaces64(val, target uint64, fn func(*Uint64, uint64)) bool {
	runtime.GOMAXPROCS(100)
	for n := 0; n < iterations; n++ {
		x := FromUint64(val)
		var wg sync.WaitGroup
		for i := uint64(0); i < 64; i++ {
			wg.Add(1)
			go func(a *Uint64, i uint64) {
				defer wg.Done()
				fn(a, uint64(1<<i))
			}(&x, i)
		}
		wg.Wait()
		if x != FromUint64(target) {
			return true
		}
	}
	return false
}

func TestOrUint32(t *testing.T) {
	if detectRaces32(0x0, 0xffffffff, OrUint32) {
		t.Error("Data race detected!")
	}
}

func TestAndUint32(t *testing.T) {
	if detectRaces32(0xf0f0f0f0, 0x00000000, AndUint32) {
		t.Error("Data race detected!")
	}
}

func TestXorUint32(t *testing.T) {
	if detectRaces32(0xf0f0f0f0, 0x0f0f0f0f, XorUint32) {
		t.Error("Data race detected!")
	}
}

func TestOrUint64(t *testing.T) {
	if detectRaces64(0x0, 0xffffffffffffffff, OrUint64) {
		t.Error("Data race detected!")
	}
}

func TestAndUint64(t *testing.T) {
	if detectRaces64(0xf0f0f0f0f0f0f0f0, 0x0, AndUint64) {
		t.Error("Data race detected!")
	}
}

func TestXorUint64(t *testing.T) {
	if detectRaces64(0xf0f0f0f0f0f0f0f0, 0x0f0f0f0f0f0f0f0f, XorUint64) {
		t.Error("Data race detected!")
	}
}

func TestCompareAndSwapUint32(t *testing.T) {
	tests := []struct {
		name string
		prev uint32
		old  uint32
		new  uint32
		next uint32
	}{
		{
			name: "Successful compare-and-swap with prev == new",
			prev: 10,
			old:  10,
			new:  10,
			next: 10,
		},
		{
			name: "Successful compare-and-swap with prev != new",
			prev: 20,
			old:  20,
			new:  22,
			next: 22,
		},
		{
			name: "Failed compare-and-swap with prev == new",
			prev: 31,
			old:  30,
			new:  31,
			next: 31,
		},
		{
			name: "Failed compare-and-swap with prev != new",
			prev: 41,
			old:  40,
			new:  42,
			next: 41,
		},
	}
	for _, test := range tests {
		val := FromUint32(test.prev)
		prev := CompareAndSwapUint32(&val, test.old, test.new)
		if got, want := prev, test.prev; got != want {
			t.Errorf("%s: incorrect returned previous value: got %d, expected %d", test.name, got, want)
		}
		if got, want := val.Load(), test.next; got != want {
			t.Errorf("%s: incorrect value stored in val: got %d, expected %d", test.name, got, want)
		}
	}
}

func TestCompareAndSwapUint64(t *testing.T) {
	tests := []struct {
		name string
		prev uint64
		old  uint64
		new  uint64
		next uint64
	}{
		{
			name: "Successful compare-and-swap with prev == new",
			prev: 0x100000000,
			old:  0x100000000,
			new:  0x100000000,
			next: 0x100000000,
		},
		{
			name: "Successful compare-and-swap with prev != new",
			prev: 0x200000000,
			old:  0x200000000,
			new:  0x200000002,
			next: 0x200000002,
		},
		{
			name: "Failed compare-and-swap with prev == new",
			prev: 0x300000001,
			old:  0x300000000,
			new:  0x300000001,
			next: 0x300000001,
		},
		{
			name: "Failed compare-and-swap with prev != new",
			prev: 0x400000001,
			old:  0x400000000,
			new:  0x400000002,
			next: 0x400000001,
		},
	}
	for _, test := range tests {
		val := FromUint64(test.prev)
		prev := CompareAndSwapUint64(&val, test.old, test.new)
		if got, want := prev, test.prev; got != want {
			t.Errorf("%s: incorrect returned previous value: got %d, expected %d", test.name, got, want)
		}
		if got, want := val.Load(), test.next; got != want {
			t.Errorf("%s: incorrect value stored in val: got %d, expected %d", test.name, got, want)
		}
	}
}
