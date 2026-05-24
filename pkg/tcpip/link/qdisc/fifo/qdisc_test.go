// Copyright 2021 The gVisor Authors.
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

package qdisc_test

import (
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkWriter = (*countWriter)(nil)

// countWriter implements LinkWriter.
type countWriter struct {
	mu             sync.Mutex
	packetsWritten int
	packetsWanted  int
	done           chan struct{}
}

func (cw *countWriter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.packetsWritten += pkts.Len()
	// Opt out of using the done channel if packetsWanted is not set.
	if cw.packetsWanted > 0 && cw.packetsWritten == cw.packetsWanted {
		close(cw.done)
	}
	return pkts.Len(), nil
}

// In b/209690936, fast simultaneous writes on qdisc will cause panics. This test
// reproduces the behavior shown in that bug.
func TestFastSimultaneousWrites(t *testing.T) {
	lower := &countWriter{}
	linkEP := fifo.New(lower, 16, 1000)

	v := make([]byte, 1)

	// Simulate many simultaneous writes from various goroutines, similar to TCP's sendTCPBatch().
	nWriters := 100
	nWrites := 100
	var wg sync.WaitGroup
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nWrites; j++ {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(v),
				})
				pkt.Hash = rand.Uint32()
				linkEP.WritePacket(pkt)
				pkt.DecRef()
			}
		}()
	}
	wg.Wait()
	linkEP.Close()
}

func TestWriteRefusedAfterClosed(t *testing.T) {
	linkEp := fifo.New(nil, 1, 2)

	linkEp.Close()
	err := linkEp.WritePacket(nil)
	_, ok := err.(*tcpip.ErrClosedForSend)
	if !ok {
		t.Errorf("got err = %s, want %s", err, &tcpip.ErrClosedForSend{})
	}
}

func TestWriteMorePacketsThanBatchSize(t *testing.T) {
	tc := []int{fifo.BatchSize + 1, fifo.BatchSize*2 + 1}
	v := make([]byte, 1)

	for _, want := range tc {
		done := make(chan struct{})
		lower := &countWriter{done: done, packetsWanted: want}
		linkEp := fifo.New(lower, 1, 1000)
		for i := 0; i < want; i++ {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(v),
			})
			linkEp.WritePacket(pkt)
			pkt.DecRef()
		}
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatalf("expected %d packets, but got only %d", want, lower.packetsWritten)
		}
		linkEp.Close()
	}
}

// TestCloseConcurrentWithWritePacket fires many WritePackets concurrently
// with Close. It exercises the race where WritePacket loads closed=false,
// Close stores closed=true and asserts closeWaker, the dispatcher drains
// the queue and exits, and then WritePacket pushes a packet that nothing
// will drain. The leak check in TestMain catches the surviving ref.
//
// Distinct from TestFastSimultaneousWrites, which closes only after all
// writers have completed.
func TestCloseConcurrentWithWritePacket(t *testing.T) {
	const trials = 2000
	const nWriters = 64
	const nWrites = 50
	v := make([]byte, 1)
	for trial := 0; trial < trials; trial++ {
		lower := &countWriter{}
		linkEP := fifo.New(lower, 16, 1024)
		var wg sync.WaitGroup
		startGate := make(chan struct{})
		for i := 0; i < nWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startGate
				for j := 0; j < nWrites; j++ {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buffer.MakeWithData(v),
					})
					pkt.Hash = rand.Uint32()
					linkEP.WritePacket(pkt)
					pkt.DecRef()
				}
			}()
		}
		close(startGate)
		runtime.Gosched()
		linkEP.Close()
		wg.Wait()
		refs.DoRepeatedLeakCheck()
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
