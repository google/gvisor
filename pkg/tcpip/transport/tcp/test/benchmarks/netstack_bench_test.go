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
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	clientAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	serverAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 3})
)

// topology owns a client/server stack pair (indices 0/1) and its packet pumps.
// Register cleanup before setup can fail; close also releases resources between
// benchmark iterations. Socket I/O workers must finish before close is called.
type topology struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stacks    [2]*stack.Stack
	links     [2]*channel.Endpoint
	endpoints []tcpip.Endpoint
	pumps     sync.WaitGroup
	once      sync.Once
}

func newTopology(t testing.TB, rack bool, batch time.Duration) *topology {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	n := &topology{ctx: ctx, cancel: cancel}
	t.Cleanup(n.close)
	for i, addr := range []tcpip.Address{clientAddr, serverAddr} {
		link := channel.New(4096, 1280, "")
		n.links[i] = link
		// Inject GSO packets intact to model coalesced reception as frequently
		// happens on loopback or with tight UDP/GRO. Partial checksums require
		// RX checksum offload.
		link.SupportedGSOKind = stack.HostGSOSupported
		link.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
		n.stacks[i] = s
		if err := s.CreateNIC(1, link); err != nil {
			t.Fatal(err)
		}
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
		cc := tcpip.CongestionControlOption("cubic")
		recovery := tcpip.TCPRecovery(0)
		if rack {
			recovery = tcpip.TCPRACKLossDetection
		}
		sack := tcpip.TCPSACKEnabled(true)
		// Keep initial buffers at 1 MiB, not the larger autotuning limits.
		// The initial buffer sizes affect flight sizes and ACK timing.
		rx := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: 8 << 20}
		tx := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: 6 << 20}
		for _, opt := range []tcpip.SettableTransportProtocolOption{&cc, &recovery, &sack, &rx, &tx} {
			if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
				t.Fatalf("SetTransportProtocolOption(%T): %s", opt, err)
			}
		}
	}
	n.startPump(n.links[0], n.links[1], batch)
	n.startPump(n.links[1], n.links[0], batch)
	return n
}

type pumpNotifier chan struct{}

func (ch pumpNotifier) WriteNotify() {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// Drain until empty, then sleep. Per-packet release deadlines or a fixed-size
// drain change ACK burst timing and can mask the premature-PTO problem.
func (n *topology) startPump(from, to *channel.Endpoint, batch time.Duration) {
	n.pumps.Add(1)
	go func() {
		defer n.pumps.Done()
		notify := make(pumpNotifier, 1)
		h := from.AddNotify(notify)
		defer from.RemoveNotify(h)
		for n.ctx.Err() == nil {
			for pkt := from.Read(); pkt != nil; pkt = from.Read() {
				if n.ctx.Err() != nil {
					pkt.DecRef()
					return
				}
				incoming := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(pkt.ToView())})
				to.InjectInbound(ipv4.ProtocolNumber, incoming)
				incoming.DecRef()
				pkt.DecRef()
			}
			if batch > 0 {
				timer := time.NewTimer(batch)
				select {
				case <-n.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			} else {
				select {
				case <-n.ctx.Done():
					return
				case <-notify:
				}
			}
		}
	}()
}

func (n *topology) close() {
	n.once.Do(func() {
		n.cancel()
		n.pumps.Wait()
		for _, ep := range n.endpoints {
			ep.Close()
		}
		for _, s := range n.stacks {
			if s != nil {
				s.Close()
				s.Wait()
			}
		}
		for _, link := range n.links {
			if link != nil {
				link.Close()
			}
		}
		// Cleanup callbacks retain n until the benchmark ends, not its stacks.
		n.endpoints = nil
		n.stacks = [2]*stack.Stack{}
		n.links = [2]*channel.Endpoint{}
	})
}

type socket struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

type socketPair struct{ client, server socket }

func (n *topology) newSocket(s *stack.Stack) (socket, error) {
	wq := &waiter.Queue{}
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		return socket{}, fmt.Errorf("NewEndpoint: %s", err)
	}
	n.endpoints = append(n.endpoints, ep)
	return socket{ep, wq}, nil
}

func (n *topology) connect(ctx context.Context) (socketPair, error) {
	listener, err := n.newSocket(n.stacks[1])
	if err != nil {
		return socketPair{}, err
	}
	defer listener.ep.Close()
	addr := tcpip.FullAddress{Addr: serverAddr, Port: 1234}
	if err := listener.ep.Bind(addr); err != nil {
		return socketPair{}, fmt.Errorf("Bind: %s", err)
	}
	// Listen(1) forces SYN cookies here, losing window scaling and SACK.
	if err := listener.ep.Listen(16); err != nil {
		return socketPair{}, fmt.Errorf("Listen: %s", err)
	}
	client, err := n.newSocket(n.stacks[0])
	if err != nil {
		return socketPair{}, err
	}
	if err := client.ep.Connect(addr); err != nil {
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			return socketPair{}, fmt.Errorf("Connect: %s", err)
		}
		if err := client.wait(ctx, waiter.WritableEvents); err != nil {
			return socketPair{}, err
		}
		if err := client.ep.LastError(); err != nil {
			return socketPair{}, fmt.Errorf("connect completion: %s", err)
		}
	}
	for {
		ep, wq, err := listener.ep.Accept(nil)
		if err == nil {
			n.endpoints = append(n.endpoints, ep)
			if wq == nil {
				return socketPair{}, fmt.Errorf("Accept returned no waiter queue")
			}
			return socketPair{client, socket{ep, wq}}, nil
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return socketPair{}, fmt.Errorf("Accept: %s", err)
		}
		if err := listener.wait(ctx, waiter.ReadableEvents); err != nil {
			return socketPair{}, err
		}
	}
}

// Register before checking readiness so a notification between failed I/O and
// registration cannot be lost. Every wait is cancellable.
func (s socket) wait(ctx context.Context, mask waiter.EventMask) error {
	entry, ch := waiter.NewChannelEntry(mask)
	s.wq.EventRegister(&entry)
	defer s.wq.EventUnregister(&entry)
	if s.ep.Readiness(mask) != 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ch:
		return ctx.Err()
	}
}

func (s socket) write(ctx context.Context, data []byte) error {
	r := bytes.NewReader(data)
	for r.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := s.ep.Write(r, tcpip.WriteOptions{})
		if err == nil {
			if n == 0 {
				return io.ErrNoProgress
			}
			continue
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return fmt.Errorf("Write: %s", err)
		}
		if err := s.wait(ctx, waiter.WritableEvents); err != nil {
			return err
		}
	}
	return nil
}

func (s socket) read(ctx context.Context, dst io.Writer, want int64) error {
	for total := int64(0); total < want; {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := s.ep.Read(dst, tcpip.ReadOptions{})
		if err == nil {
			if res.Count == 0 {
				return io.ErrNoProgress
			}
			total += int64(res.Count)
			if total > want {
				return fmt.Errorf("Read received %d bytes, want %d", total, want)
			}
			continue
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return fmt.Errorf("Read after %d/%d bytes: %s", total, want, err)
		}
		if err := s.wait(ctx, waiter.ReadableEvents); err != nil {
			return err
		}
	}
	return nil
}

// Both directions cancel on failure; always join the reader before returning.
// No worker calls Fatalf. Keep raw endpoint I/O: gonet.Read also calls
// ModerateRecvBuf, which would change this workload's receive-buffer behavior.
func transfer(ctx context.Context, pair socketPair, data []byte, size int64, dst io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	var readErr error
	go func() {
		defer close(done)
		readErr = pair.server.read(ctx, dst, size)
		if readErr != nil {
			cancel()
		}
	}()
	var writeErr error
	for left := size; left > 0; {
		n := min(int64(len(data)), left)
		if n == 0 {
			writeErr = io.ErrNoProgress
			break
		}
		if writeErr = pair.client.write(ctx, data[:n]); writeErr != nil {
			break
		}
		left -= n
	}
	if writeErr != nil {
		cancel()
	}
	<-done
	if writeErr != nil && writeErr != context.Canceled {
		return writeErr
	}
	if readErr != nil {
		return readErr
	}
	return writeErr
}

// Each iteration starts with fresh congestion and RTT state. Only the transfer
// is timed; cleanup must finish before the next iteration starts.
func benchmarkTransfer(b *testing.B, rack bool, batch time.Duration, data []byte) (time.Duration, uint64, uint64) {
	n := newTopology(b, rack, batch)
	defer n.close()
	pair, err := n.connect(n.ctx)
	if err != nil {
		b.Fatal(err)
	}
	stats := n.stacks[0].Stats().TCP
	beforeRxt, beforeRecovery := stats.Retransmits.Value(), stats.SACKRecovery.Value()
	b.StartTimer()
	start := time.Now()
	err = transfer(n.ctx, pair, data, 64<<20, io.Discard)
	elapsed := time.Since(start)
	b.StopTimer()
	if err != nil {
		b.Fatal(err)
	}
	return elapsed, stats.Retransmits.Value() - beforeRxt, stats.SACKRecovery.Value() - beforeRecovery
}

// BenchmarkBulkBatchedLocalhost measures CUBIC throughput with and without
// batching and RACK.
func BenchmarkBulkBatchedLocalhost(b *testing.B) {
	for _, batch := range []time.Duration{0, 100 * time.Microsecond} {
		for _, rack := range []bool{true, false} {
			b.Run(fmt.Sprintf("batchWindow=%v/cc=cubic/rack=%t", batch, rack), func(b *testing.B) {
				b.StopTimer()
				data := make([]byte, 128<<10)
				b.SetBytes(64 << 20)
				b.ResetTimer()
				var retransmits, recoveries uint64
				for i := 0; i < b.N; i++ {
					elapsed, rxt, rec := benchmarkTransfer(b, rack, batch, data)
					retransmits += rxt
					recoveries += rec
					b.Logf("transfer name=%s iterations=%d iteration=%d bytes=%d elapsed_ns=%d retransmits=%d recoveries=%d", b.Name(), b.N, i, 64<<20, elapsed.Nanoseconds(), rxt, rec)
				}
				b.ReportMetric(float64(retransmits)/float64(b.N), "retransmits/op")
				b.ReportMetric(float64(recoveries)/float64(b.N), "sack-recoveries/op")
			})
		}
	}
}
