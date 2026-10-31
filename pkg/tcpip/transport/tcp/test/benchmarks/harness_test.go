// Copyright 2026 The gVisor Authors.
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

package tcp_benchmarks_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var checkBenchmarkLeaks = flag.Bool("check-benchmark-leaks", false, "enable reference-leak tracking during benchmarks (changes timing)")

func TestMain(m *testing.M) {
	flag.Parse()
	if *checkBenchmarkLeaks || flag.Lookup("test.bench").Value.String() == "" {
		refs.SetLeakMode(refs.LeaksPanic)
	}
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}

func TestTransfer(t *testing.T) {
	for _, batch := range []time.Duration{0, 100 * time.Microsecond} {
		for _, rack := range []bool{true, false} {
			t.Run(fmt.Sprintf("batch=%v/rack=%t", batch, rack), func(t *testing.T) {
				n := newTopology(t, rack, batch)
				ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
				defer cancel()
				pair, err := n.connect(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if got := n.stacks[1].Stats().TCP.ListenOverflowSynCookieSent.Value(); got != 0 {
					t.Fatalf("SYN cookies = %d, want 0 (cookies discard SACK/window scaling)", got)
				}
				for _, s := range []socket{pair.client, pair.server} {
					ep := s.ep.(*tcp.Endpoint)
					ep.LockUser()
					sack := ep.SACKPermitted
					ep.UnlockUser()
					if !sack {
						t.Fatal("SACK not negotiated")
					}
				}
				// Force partial writes and readiness waits, then check successive
				// non-chunk-aligned transfers for missing or duplicated bytes.
				pair.client.ep.SocketOptions().SetSendBufferSize(4096, true)
				pair.server.ep.SocketOptions().SetReceiveBufferSize(4096, true)
				data := make([]byte, 16<<10)
				for i := range data {
					data[i] = byte(i*31 + i/251)
				}
				for _, size := range []int{1, 2*len(data) + 37, len(data) - 1} {
					var got bytes.Buffer
					if err := transfer(ctx, pair, data, int64(size), &got); err != nil {
						t.Fatal(err)
					}
					if want := bytes.Repeat(data, size/len(data)+1)[:size]; !bytes.Equal(got.Bytes(), want) {
						t.Fatalf("transfer(%d): received %d bytes with incorrect content", size, got.Len())
					}
				}
				if !pair.client.wq.IsEmpty() || !pair.server.wq.IsEmpty() {
					t.Error("waiter entries remain after transfer")
				}
			})
		}
	}
}

// Exercise failure/cancellation on real endpoints, including a blocked sibling.
func TestTransferFailure(t *testing.T) {
	for _, writer := range []bool{true, false} {
		t.Run(fmt.Sprintf("writer=%t", writer), func(t *testing.T) {
			n := newTopology(t, true, 0)
			pair, err := n.connect(n.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if writer {
				if e := pair.client.ep.Shutdown(tcpip.ShutdownWrite); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := pair.server.ep.Shutdown(tcpip.ShutdownRead); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
			defer cancel()
			if err := transfer(ctx, pair, make([]byte, 128<<10), 64<<20, io.Discard); err == nil {
				t.Fatal("transfer succeeded after shutdown")
			}
			if ctx.Err() != nil {
				t.Fatalf("transfer needed the fallback deadline: %v", ctx.Err())
			}
			if !pair.client.wq.IsEmpty() || !pair.server.wq.IsEmpty() {
				t.Error("failed transfer left waiter entries registered")
			}
		})
	}
}

func TestIOCancellation(t *testing.T) {
	for _, writer := range []bool{true, false} {
		t.Run(fmt.Sprintf("writer=%t", writer), func(t *testing.T) {
			n := newTopology(t, true, 0)
			pair, err := n.connect(n.ctx)
			if err != nil {
				t.Fatal(err)
			}
			pair.client.ep.SocketOptions().SetSendBufferSize(4096, true)
			pair.server.ep.SocketOptions().SetReceiveBufferSize(4096, true)
			ctx, cancel := context.WithTimeout(n.ctx, 20*time.Millisecond)
			defer cancel()
			if writer {
				// No reader drains the receive window.
				err = pair.client.write(ctx, make([]byte, 2<<20))
			} else {
				err = pair.server.read(ctx, io.Discard, 1)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("I/O error = %v, want deadline exceeded", err)
			}
			if !pair.client.wq.IsEmpty() || !pair.server.wq.IsEmpty() {
				t.Error("cancelled I/O left waiter entries registered")
			}
		})
	}
}

func TestConnectCancellation(t *testing.T) {
	n := newTopology(t, true, 0)
	n.links[1].Attach(nil) // Prevent the handshake from completing.
	ctx, cancel := context.WithTimeout(n.ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := n.connect(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connect error = %v, want deadline exceeded", err)
	}
}

func TestTopologyDefaults(t *testing.T) {
	n := newTopology(t, true, 100*time.Microsecond)
	for _, s := range n.stacks {
		var tx tcpip.TCPSendBufferSizeRangeOption
		var rx tcpip.TCPReceiveBufferSizeRangeOption
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &tx); err != nil {
			t.Fatal(err)
		}
		if err := s.TransportProtocolOption(tcp.ProtocolNumber, &rx); err != nil {
			t.Fatal(err)
		}
		if tx.Default != 1<<20 || tx.Max != 6<<20 || rx.Default != 1<<20 || rx.Max != 8<<20 {
			t.Fatalf("unexpected buffer ranges: send=%+v receive=%+v", tx, rx)
		}
	}
	for _, link := range n.links {
		if link.MTU() != 1280 || link.SupportedGSO() != stack.HostGSOSupported || link.Capabilities()&stack.CapabilityRXChecksumOffload == 0 {
			t.Fatalf("unexpected link settings: MTU=%d GSO=%v capabilities=%v", link.MTU(), link.SupportedGSO(), link.Capabilities())
		}
	}
}

type pumpDispatcher func(*stack.PacketBuffer)

func (d pumpDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d(pkt)
}
func (pumpDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func newPump(t *testing.T) *topology {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	n := &topology{ctx: ctx, cancel: cancel, links: [2]*channel.Endpoint{channel.New(8, 1280, ""), channel.New(8, 1280, "")}}
	t.Cleanup(n.close)
	return n
}

func enqueue(link *channel.Endpoint, b byte) tcpip.Error {
	var packets stack.PacketBufferList
	packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{b})}))
	defer packets.DecRef()
	n, err := link.WritePackets(packets)
	if err == nil && n != 1 {
		return &tcpip.ErrNoBufferSpace{}
	}
	return err
}

func TestPumpDrainsBeforeSleeping(t *testing.T) {
	n := newPump(t)
	type result struct {
		data []byte
		err  tcpip.Error
	}
	received := make(chan result, 2)
	n.links[1].Attach(pumpDispatcher(func(pkt *stack.PacketBuffer) {
		v := pkt.ToView()
		r := result{data: bytes.Clone(v.AsSlice())}
		v.Release()
		if bytes.Equal(r.data, []byte{1}) {
			r.err = enqueue(n.links[0], 2)
		}
		select {
		case received <- r:
		case <-n.ctx.Done():
		}
	}))
	if err := enqueue(n.links[0], 1); err != nil {
		t.Fatal(err)
	}
	// The packet queued during delivery must join this drain, not wait an
	// hour for the next batch. This tests ordering, not timer precision.
	n.startPump(n.links[0], n.links[1], time.Hour)
	for _, want := range []byte{1, 2} {
		select {
		case got := <-received:
			if got.err != nil || !bytes.Equal(got.data, []byte{want}) {
				t.Fatalf("delivered %v, error %v; want [%d]", got.data, got.err, want)
			}
		case <-n.ctx.Done():
			t.Fatal("pump slept before draining")
		}
	}
}

func TestPumpShutdown(t *testing.T) {
	n := newPump(t)
	link := n.links[0]
	for i := 0; i < 8; i++ {
		if err := enqueue(link, byte(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Cancellation must release queued packets even if delivery never starts.
	n.cancel()
	n.startPump(link, n.links[1], time.Hour)
	n.close()
	n.close()
	if got := link.NumQueued(); got != 0 {
		t.Errorf("queued packets after close = %d, want 0", got)
	}
}
