// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"runtime"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

func TestBasic(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	var destroyed bool
	destroy = func(_ PacketBufferPtr) {
		destroyed = true
	}

	pkt2 := pkt.IncRef()
	pkt.DecRef()
	pkt2.DecRef()

	if !destroyed {
		t.Errorf("expected refcount to reach 0, but it did not")
	}
}

func TestDoubleInc(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	var destroyed bool
	destroy = func(_ PacketBufferPtr) {
		destroyed = true
	}

	pkt2 := pkt.IncRef()
	pkt3 := pkt.IncRef()
	pkt.DecRef()
	pkt2.DecRef()
	pkt3.DecRef()

	if !destroyed {
		t.Errorf("expected refcount to reach 0, but it did not")
	}
}

func TestDecImmediately(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	var destroyed bool
	destroy = func(_ PacketBufferPtr) {
		destroyed = true
	}

	pkt.DecRef()

	if !destroyed {
		t.Errorf("expected refcount to reach 0, but it did not")
	}
}

func TestDoubleDecPanics(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	defer func() {
		if rcvr := recover(); rcvr == nil {
			t.Errorf("expected panic, but no panic occurred")
		}
	}()

	pkt.DecRef()
	pkt.DecRef()
}

func TestCopyDoubleDecPanics(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	defer func() {
		if rcvr := recover(); rcvr == nil {
			t.Errorf("expected panic, but no panic occurred")
		}
	}()

	pkt2 := pkt.IncRef()
	pkt2.DecRef()
	pkt2.DecRef()
}

func TestZeroedIncPanics(t *testing.T) {
	pkt := NewPacketBuffer(PacketBufferOptions{})
	defer func() {
		if rcvr := recover(); rcvr == nil {
			t.Errorf("expected panic, but no panic occurred")
		}
	}()

	pkt.DecRef()
	_ = pkt.IncRef()
}

func TestManyIncDec(t *testing.T) {
	var destroyed bool
	destroy = func(_ PacketBufferPtr) {
		destroyed = true
	}

	// The number of iterations must be larger than the size of the bitset (64).
	var pkts []PacketBufferPtr
	pkt := NewPacketBuffer(PacketBufferOptions{})
	for i := 0; i < 100; i++ {
		pkts = append(pkts, pkt.IncRef())
	}
	for _, otherPkt := range pkts {
		otherPkt.DecRef()
	}
	pkt.DecRef()

	if !destroyed {
		t.Errorf("expected refcount to reach 0, but it did not")
	}
}

func TestRace(t *testing.T) {
	const nGoroutines = 100
	const nIncrements = 1000

	var destroyed atomicbitops.Uint32
	destroy = func(_ PacketBufferPtr) {
		destroyed.Store(1)
	}

	pkt := NewPacketBuffer(PacketBufferOptions{})

	// Spawn a bunch of goroutines, have 'em change the ref count a bunch, and
	// suggest they yield the processor every so often.
	var wg sync.WaitGroup
	for i := 0; i < nGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var pkts []PacketBufferPtr
			for j := 0; j < nIncrements; j++ {
				if j%5 == 0 {
					runtime.Gosched()
				}
				pkts = append(pkts, pkt.IncRef())
			}
			for j, otherPkt := range pkts {
				if j%7 == 0 {
					runtime.Gosched()
				}
				otherPkt.DecRef()
			}
		}(i)
	}

	wg.Wait()
	pkt.DecRef()

	if destroyed.Load() != 1 {
		t.Errorf("expected refcount to reach 0, but it did not")
	}
}
