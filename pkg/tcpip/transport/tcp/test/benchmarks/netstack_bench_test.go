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

// Package tcp_benchmarks_test provides end-to-end throughput and latency
// benchmarks for bulk TCP transfers between two full gvisor netstacks wired
// back-to-back over a channel-based link endpoint.
//
// This models a userspace-TCP datapath in which a TCP connection terminates
// in one netstack and is carried over a localhost transport (zero
// propagation delay) to a second netstack, as in a userspace VPN. The
// benchmarks compare combinations of {cubic, reno} x {rack, no-rack} to
// isolate the per-packet CPU cost and behavioral effects of each:
//
//   - the sender ACK hot path: handleRcvdSegment -> walkSACK / SACK Insert /
//     SetPipe, RACK update / detectReorder / detectLoss, cc.Update (CUBIC +
//     HyStart), and
//   - the receiver path: receive segment list, delayed ACK generation, SACK
//     block generation.
//
// A synthetic loss/delay link (see lossyLink) additionally exercises loss
// recovery (RACK TLP + fast retransmit) with deterministic seeds, so recovery
// behavior — not just throughput on a clean link — can be compared.
package tcp_benchmarks_test

import (
	"bytes"
	"fmt"
	"math/rand"
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

const (
	// benchMTU is a typical ethernet MTU.
	benchMTU = 1500

	serverPort = 1234
)

// Buffer and MTU sizes model a userspace VPN datapath: large socket
// buffers for high-BDP paths, and an inner MTU reduced for encapsulation
// overhead. Large buffers are where the RACK per-ACK O(writeList) scans
// become O(window^2) work.
const (
	benchTXBufMax = 6 << 20
	benchRXBufMax = 8 << 20

	// vpnMTU is a typical inner MTU after wire encapsulation overhead.
	vpnMTU = 1280
)

var (
	addrA = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x02"))
	addrB = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x03"))
)

// ccCombos are the congestion-control/loss-recovery combinations benchmarked.
type ccConfig struct {
	cc   string
	rack bool
}

var benchConfigs = []ccConfig{
	{"cubic", true},  // cubic with RACK loss detection
	{"cubic", false}, // CUBIC without RACK: isolates RACK cost
	{"reno", true},   // RACK without CUBIC: isolates CUBIC cost
	{"reno", false},  // baseline: neither new path
}

// benchStats snapshots the TCPStats fields that reveal pathological behavior
// on a zero-RTT, zero-loss link (e.g. spurious recoveries).
type benchStats struct {
	segmentsSent     uint64
	segmentsRecv     uint64
	retransmits      uint64
	fastRetransmit   uint64
	sackRecovery     uint64
	fastRecovery     uint64
	tlpRecovery      uint64
	timeouts         uint64
	dsack            uint64
	spuriousRecovery uint64
	spuriousRTO      uint64
	invalidSegments  uint64
}

func snapshotTCPStats(s *stack.Stack) benchStats {
	t := s.Stats().TCP
	return benchStats{
		segmentsSent:     t.SegmentsSent.Value(),
		segmentsRecv:     t.ValidSegmentsReceived.Value(),
		retransmits:      t.Retransmits.Value(),
		fastRetransmit:   t.FastRetransmit.Value(),
		sackRecovery:     t.SACKRecovery.Value(),
		fastRecovery:     t.FastRecovery.Value(),
		tlpRecovery:      t.TLPRecovery.Value(),
		timeouts:         t.Timeouts.Value(),
		dsack:            t.SegmentsAckedWithDSACK.Value(),
		spuriousRecovery: t.SpuriousRecovery.Value(),
		spuriousRTO:      t.SpuriousRTORecovery.Value(),
		invalidSegments:  t.InvalidSegmentsReceived.Value(),
	}
}

func (b benchStats) diff(from benchStats) benchStats {
	b.segmentsSent -= from.segmentsSent
	b.segmentsRecv -= from.segmentsRecv
	b.retransmits -= from.retransmits
	b.fastRetransmit -= from.fastRetransmit
	b.sackRecovery -= from.sackRecovery
	b.fastRecovery -= from.fastRecovery
	b.tlpRecovery -= from.tlpRecovery
	b.timeouts -= from.timeouts
	b.dsack -= from.dsack
	b.spuriousRecovery -= from.spuriousRecovery
	b.spuriousRTO -= from.spuriousRTO
	b.invalidSegments -= from.invalidSegments
	return b
}

func (b benchStats) String() string {
	return fmt.Sprintf("sent=%d recv=%d rxt=%d fastRxt=%d sackRec=%d fastRec=%d tlp=%d rto=%d dsack=%d spurious=%d spuriousRTO=%d invalid=%d",
		b.segmentsSent, b.segmentsRecv, b.retransmits, b.fastRetransmit, b.sackRecovery, b.fastRecovery,
		b.tlpRecovery, b.timeouts, b.dsack, b.spuriousRecovery, b.spuriousRTO, b.invalidSegments)
}

// twoStacks holds the benchmark topology.
type twoStacks struct {
	client *stack.Stack
	server *stack.Stack

	// clientLink/serverLink are the channel endpoints attached to the
	// stacks. Outbound packets from the client are pumped to the server's
	// inbound and vice versa.
	clientLink *channel.Endpoint
	serverLink *channel.Endpoint

	// pump fields.
	pumpWG sync.WaitGroup
	quit   chan struct{}

	// rng for synthetic loss; shared, seeded deterministically.
	loss  float64
	rng   *rand.Rand
	rngMu sync.Mutex

	// mtu overrides benchMTU for the link endpoints.
	mtu uint32

	// gso enables host GSO on the link endpoints, so the TCP sender emits
	// segmentation-offload super-packets, as on a VPN link endpoint that
	// advertises GSO support.
	gso bool

	// batchWindow models batched transport delivery: packets accumulate for
	// up to batchWindow and are then delivered as a burst. This emulates
	// per-wake batch processing in a UDP-based VPN transport over a
	// localhost socket with UDP GRO batching reads.
	batchWindow time.Duration

	// pumpDelay adds artificial one-way propagation latency to the link.
	// It is implemented as a pipelined delay queue (packets are released
	// delay-nanoseconds after arrival, in order), so the congestion window
	// can actually fill the bandwidth-delay product. This is distinct from
	// a per-packet serialization delay, which would rate-limit the link.
	pumpDelay time.Duration
}

func newTwoStacks(b *testing.B, cfg ccConfig) *twoStacks {
	return newTwoStacksOpts(b, cfg, bulkOpts{})
}

func newTwoStacksOpts(b *testing.B, cfg ccConfig, opts bulkOpts) *twoStacks {
	ts := &twoStacks{
		quit:        make(chan struct{}),
		rng:         rand.New(rand.NewSource(42)), //nolint:gosec // deterministic benchmark
		loss:        opts.loss,
		pumpDelay:   opts.delay,
		mtu:         opts.mtu,
		gso:         opts.gso,
		batchWindow: opts.batchWindow,
	}

	newOneStack := func(localAddr tcpip.Address) (*stack.Stack, *channel.Endpoint) {
		mtu := uint32(benchMTU)
		if ts.mtu != 0 {
			mtu = ts.mtu
		}
		link := channel.New(4096, mtu, "")
		if ts.gso {
			link.SupportedGSOKind = stack.HostGSOSupported
			// With GSO+checksum offload the sender emits packets with partial
			// (pseudo-header only) TCP checksums, expecting the link/host to
			// finalize them. A transport that provides its own packet
			// integrity (e.g. an encrypted tunnel) can skip TCP checksum
			// validation and advertise RX checksum offload instead.
			link.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
		}
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
		if err := s.CreateNIC(1, link); err != nil {
			b.Fatalf("CreateNIC: %s", err)
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: localAddr.WithPrefix(),
		}
		if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			b.Fatalf("AddProtocolAddress: %s", err)
		}
		s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
		return s, link
	}

	ts.client, ts.clientLink = newOneStack(addrA)
	ts.server, ts.serverLink = newOneStack(addrB)

	for _, s := range []*stack.Stack{ts.client, ts.server} {
		opt := tcpip.CongestionControlOption(cfg.cc)
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			b.Fatalf("SetTransportProtocolOption(CongestionControlOption=%s): %s", cfg.cc, err)
		}
		recovery := tcpip.TCPRecovery(0)
		if cfg.rack {
			recovery = tcpip.TCPRACKLossDetection
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
			b.Fatalf("SetTransportProtocolOption(TCPRecovery=%d): %s", recovery, err)
		}
		// Model the VPN datapath's large socket buffers.
		rxBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: benchRXBufMax}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBufOpt); err != nil {
			b.Fatalf("SetTransportProtocolOption(rxBufOpt): %s", err)
		}
		txBufOpt := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: benchTXBufMax}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &txBufOpt); err != nil {
			b.Fatalf("SetTransportProtocolOption(txBufOpt): %s", err)
		}
	}
	return ts
}

// pumpNotifier implements channel.Notification for the event-driven pump.
type pumpNotifier struct{ ch chan<- struct{} }

func (p pumpNotifier) WriteNotify() {
	select {
	case p.ch <- struct{}{}:
	default:
	}
}

// delayQueue is a FIFO of packets scheduled for release after a delay.
// Packets arrive in release-time order (each stamped now+delay), so the
// head is always the earliest item.
type delayQueue struct {
	mu    sync.Mutex
	items []delayItem
	wake  chan struct{}
}

type delayItem struct {
	pkt     *stack.PacketBuffer
	release time.Time
}

func newDelayQueue() *delayQueue {
	return &delayQueue{wake: make(chan struct{}, 1)}
}

func (d *delayQueue) push(pkt *stack.PacketBuffer, release time.Time) {
	d.mu.Lock()
	d.items = append(d.items, delayItem{pkt: pkt, release: release})
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// startPump wires the two channel endpoints together. Packets read from one
// side's outbound queue are (after optional loss and propagation delay)
// injected into the other side's inbound path.
func (ts *twoStacks) startPump() {
	pump := func(from, to *channel.Endpoint) {
		defer ts.pumpWG.Done()
		notifyCh := make(chan struct{}, 1)
		h := from.AddNotify(pumpNotifier{ch: notifyCh})
		defer from.RemoveNotify(h)
		deliver := func(pkt *stack.PacketBuffer) {
			// Outbound packets keep their network header in
			// pkt.NetworkHeader(), not in Data(). Inbound delivery parses
			// the header out of Data(), so serialize the full wire packet
			// and inject that.
			view := pkt.ToView()
			newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithView(view),
			})
			to.InjectInbound(ipv4.ProtocolNumber, newPkt)
			newPkt.DecRef()
			pkt.DecRef()
		}
		if ts.pumpDelay == 0 {
			// Zero-delay path: deliver inline, event-driven. With batchWindow
			// set, packets accumulate between bursts (batched transport).
			for {
				for pkt := from.Read(); pkt != nil; pkt = from.Read() {
					if ts.drop() {
						pkt.DecRef()
						continue
					}
					deliver(pkt)
				}
				if ts.batchWindow > 0 {
					select {
					case <-ts.quit:
						return
					case <-time.After(ts.batchWindow):
					}
					continue
				}
				select {
				case <-ts.quit:
					return
				case <-notifyCh:
				}
			}
		}
		// Delayed path: reader goroutine enqueues into a pipelined delay
		// queue; releaser goroutine pops when due.
		dq := newDelayQueue()
		var dqWG sync.WaitGroup
		dqWG.Add(2)
		// Releaser: wait until the head of the queue is due, then deliver.
		go func() {
			defer dqWG.Done()
			for {
				dq.mu.Lock()
				if len(dq.items) == 0 {
					dq.mu.Unlock()
					select {
					case <-ts.quit:
						return
					case <-dq.wake:
					}
					continue
				}
				it := dq.items[0]
				dq.mu.Unlock()
				if d := time.Until(it.release); d > 0 {
					t := time.NewTimer(d)
					select {
					case <-ts.quit:
						t.Stop()
						return
					case <-t.C:
					}
				}
				dq.mu.Lock()
				// FIFO order is maintained by push, so items[0] is still it.
				dq.items = dq.items[1:]
				dq.mu.Unlock()
				deliver(it.pkt)
			}
		}()
		// Reader: drain the source endpoint into the delay queue.
		go func() {
			defer dqWG.Done()
			for {
				for pkt := from.Read(); pkt != nil; pkt = from.Read() {
					if ts.drop() {
						pkt.DecRef()
						continue
					}
					dq.push(pkt, time.Now().Add(ts.pumpDelay))
				}
				select {
				case <-ts.quit:
					return
				case <-notifyCh:
				}
			}
		}()
		dqWG.Wait()
	}
	ts.pumpWG.Add(2)
	go pump(ts.clientLink, ts.serverLink)
	go pump(ts.serverLink, ts.clientLink)
}

// drop reports whether a packet should be dropped under the configured loss.
func (ts *twoStacks) drop() bool {
	if ts.loss == 0 {
		return false
	}
	ts.rngMu.Lock()
	drop := ts.rng.Float64() < ts.loss
	ts.rngMu.Unlock()
	return drop
}

func (ts *twoStacks) stop() {
	close(ts.quit)
	ts.pumpWG.Wait()
	ts.client.Close()
	ts.server.Close()
	ts.client.Wait()
	ts.server.Wait()
}

// endpointPair is a connected client/server TCP pair.
type endpointPair struct {
	client   tcpip.Endpoint
	server   tcpip.Endpoint
	clientWQ *waiter.Queue
	serverWQ *waiter.Queue
}

// connectPair establishes one TCP connection through the wire (3WHS via the
// pump) and returns the two endpoints. The accepted endpoint's wait queue is
// the one Accept returned (nil in practice for gvisor) — a fresh queue is
// substituted if so.
func (ts *twoStacks) connectPair(b *testing.B) endpointPair {
	listener, listenerWQ := ts.listen(b)
	defer listener.Close()

	clientWQ := &waiter.Queue{}
	client, err := ts.client.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, clientWQ)
	if err != nil {
		b.Fatalf("NewEndpoint(client): %s", err)
	}
	if err := client.Connect(tcpip.FullAddress{Addr: addrB, Port: serverPort}); err != nil {
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			b.Fatalf("Connect: %s", err)
		}
		// Wait for the handshake to complete.
		waitWritable(b, client, clientWQ)
	}

	// Wait for the accept to complete on the server side.
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	listenerWQ.EventRegister(&we)
	defer listenerWQ.EventUnregister(&we)
	server, serverWQ, err := listener.Accept(nil)
	for {
		if err == nil {
			break
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			b.Fatalf("Accept: %s", err)
		}
		<-ch
		server, serverWQ, err = listener.Accept(nil)
	}
	if serverWQ == nil {
		serverWQ = &waiter.Queue{}
	}
	return endpointPair{client: client, server: server, clientWQ: clientWQ, serverWQ: serverWQ}
}

func (ts *twoStacks) listen(b *testing.B) (tcpip.Endpoint, *waiter.Queue) {
	wq := &waiter.Queue{}
	ep, err := ts.server.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		b.Fatalf("NewEndpoint: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Addr: addrB, Port: serverPort}); err != nil {
		b.Fatalf("Bind: %s", err)
	}
	if err := ep.Listen(16); err != nil {
		b.Fatalf("Listen: %s", err)
	}
	return ep, wq
}

// failf reports a fatal error from a non-test goroutine. testing's b.Fatalf
// only terminates the calling goroutine (via runtime.Goexit), which would
// leave the benchmark's other goroutines deadlocked, or worse, let the
// benchmark silently pass with an incomplete measurement, so panic instead
// to fail the whole binary.
func failf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

// readAll drains exactly want bytes from ep. It is intended to be called
// from a goroutine; use failf rather than b.Fatalf to report errors.
func readAll(ep tcpip.Endpoint, wq *waiter.Queue, want int64) {
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	sink := discard{}
	var total int64
	for total < want {
		res, err := ep.Read(sink, tcpip.ReadOptions{})
		if err == nil {
			total += int64(res.Count)
			continue
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			failf("Read: %s", err)
		}
		// Re-check readiness after WouldBlock before waiting: the data may
		// have arrived between the failed Read and now (the event would
		// already have fired).
		if ep.Readiness(waiter.ReadableEvents) != 0 {
			continue
		}
		<-ch
	}
}

// discard is an io.Writer that drops data (avoids buffering benchmarks).
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// benchBulk runs a single bulk client->server transfer measurement.
// It returns elapsed time and client-side TCP stats delta.
func (ts *twoStacks) benchBulk(b *testing.B, totalBytes int64) (time.Duration, benchStats) {
	pair := ts.connectPair(b)
	defer pair.client.Close()
	defer pair.server.Close()

	// Drain server side concurrently; ping data.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		readAll(pair.server, pair.serverWQ, totalBytes)
	}()

	// Sample the client's congestion window during the transfer so window
	// dynamics (e.g. repeated spurious collapses) are visible in benchmark
	// output.
	var cwndSamples []int
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-readerDone:
				return
			case <-t.C:
				var info tcpip.TCPInfoOption
				if err := pair.client.GetSockOpt(&info); err == nil {
					cwndSamples = append(cwndSamples, int(info.SndCwnd))
				}
			}
		}
	}()
	defer func() { <-sampleDone }()

	data := make([]byte, 128*1024)
	before := snapshotTCPStats(ts.client)
	start := time.Now()
	var wrote int64
	r := bytes.NewReader(data)
	for wrote < totalBytes {
		if r.Len() == 0 {
			r.Reset(data)
		}
		n, err := pair.client.Write(r, tcpip.WriteOptions{})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				b.Fatalf("Write: %s", err)
			}
			waitWritable(b, pair.client, pair.clientWQ)
			continue
		}
		wrote += n
	}
	readDone := func() bool {
		select {
		case <-readerDone:
			return true
		default:
			return false
		}
	}
	for !readDone() {
		time.Sleep(100 * time.Microsecond)
	}
	elapsed := time.Since(start)
	after := snapshotTCPStats(ts.client)
	if len(cwndSamples) > 0 {
		var sum, max int
		min := cwndSamples[0]
		for _, c := range cwndSamples {
			sum += c
			if c > max {
				max = c
			}
			if c < min {
				min = c
			}
		}
		b.ReportMetric(float64(sum)/float64(len(cwndSamples)), "avg-cwnd")
		b.ReportMetric(float64(max), "max-cwnd")
		b.ReportMetric(float64(min), "min-cwnd")
	}
	return elapsed, after.diff(before)
}

func waitWritable(b *testing.B, ep tcpip.Endpoint, wq *waiter.Queue) {
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	// Check readiness after registering: avoids missing an event that
	// fired between the failed Write and our registration.
	if ep.Readiness(waiter.WritableEvents) != 0 {
		return
	}
	<-ch
}

// runBulkBenchmarks runs the bulk sub-benchmarks.
func runBulkBenchmarks(b *testing.B, loss float64, delay time.Duration, sizes ...int64) {
	runBulkBenchmarksOpts(b, bulkOpts{loss: loss, delay: delay}, sizes...)
}

// bulkOpts parameterizes the link/transport model for bulk benchmarks.
type bulkOpts struct {
	loss        float64
	delay       time.Duration
	mtu         uint32
	gso         bool
	batchWindow time.Duration
}

func runBulkBenchmarksOpts(b *testing.B, opts bulkOpts, sizes ...int64) {
	for _, cfg := range benchConfigs {
		b.Run(fmt.Sprintf("cc=%s/rack=%t", cfg.cc, cfg.rack), func(b *testing.B) {
			for _, sz := range sizes {
				b.Run(fmt.Sprintf("bytes=%dMiB", sz>>20), func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						ts := newTwoStacksOpts(b, cfg, opts)
						ts.startPump()
						elapsed, stats := ts.benchBulk(b, sz)
						ts.stop()
						b.ReportMetric(float64(sz)/elapsed.Seconds()/(1<<20), "MiB/s")
						b.ReportMetric(elapsed.Seconds()*1e6/float64(stats.segmentsSent), "us/segment-sent")
						b.Log("tcp:", stats)
					}
				})
			}
		})
	}
}

// BenchmarkBulkBatchedLocalhost models a TCP flow carried between two
// userspace netstacks over a batched, encapsulating localhost transport
// (e.g. a userspace VPN tunnel): the inner TCP sees
//
//   - a reduced inner MTU for encapsulation overhead,
//   - GSO super-packets on transmit, which the receiving netstack
//     effectively sees coalesced again via its GRO path,
//   - batched delivery: the transport reads and processes packets in
//     per-wake batches and UDP GRO batches datagrams on localhost, so the
//     inner TCP's segments and ACKs move in bursts separated by scheduling
//     gaps rather than smoothly.
//
// The batchWindow dimension sweeps the inter-burst gap. Note that the
// spurious TLP probes triggered by batched delivery typically transmit new
// data rather than retransmissions, so they do not show up in the
// rxt/fastRxt/dsack counters; the spurious congestion response instead shows
// up as a suppressed avg-cwnd (and a higher segmentsSent) relative to the
// unbatched baseline.
func BenchmarkBulkBatchedLocalhost(b *testing.B) {
	for _, batch := range []time.Duration{0, 100 * time.Microsecond, 500 * time.Microsecond} {
		b.Run(fmt.Sprintf("batchWindow=%v", batch), func(b *testing.B) {
			runBulkBenchmarksOpts(b, bulkOpts{
				mtu:         vpnMTU,
				gso:         true,
				batchWindow: batch,
			}, 64<<20)
		})
	}
}

// BenchmarkBulkThroughput measures raw back-to-back throughput for each
// CC/recovery combination on a clean, zero-delay link. All combinations
// should be roughly equivalent; big deltas indicate per-packet CPU cost in
// the RACK/CUBIC machinery.
func BenchmarkBulkThroughput(b *testing.B) {
	runBulkBenchmarks(b, 0 /* loss */, 0 /* delay */, 64<<20)
}

// BenchmarkBulkThroughputLatency adds symmetric one-way propagation delay
// via a pipelined delay queue, approximating real-RTT paths (LAN to small
// WAN). On these paths the bandwidth-delay product is large enough that
// congestion window dynamics — not just per-packet CPU — determine
// throughput. In particular this exposes CUBIC HyStart's slow-start exit
// clamping cwnd far below the BDP on low-RTT paths.
func BenchmarkBulkThroughputLatency(b *testing.B) {
	for _, delay := range []time.Duration{time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("oneWayDelay=%v", delay), func(b *testing.B) {
			runBulkBenchmarks(b, 0 /* loss */, delay, 32<<20)
		})
	}
}

// BenchmarkLossyThroughput drives actual loss recovery: 0.1% packet loss
// exercises fast retransmit/SACK recovery (and RACK TLP) with identical loss
// patterns across configs. Watch the recovery counters; spurious recovery on
// a *reordering-free* synthetic lossy link is a red flag.
func BenchmarkLossyThroughput(b *testing.B) {
	runBulkBenchmarks(b, 0.001 /* loss */, 0 /* delay */, 16<<20)
}

// BenchmarkPingPong measures single-message round-trip latency through both
// stacks (the interactive/ssh-style path). It exercises ACK/delayed-ACK
// handling, Nagle (off by default in netstack), and PTO scheduling on quiet
// connections.
func BenchmarkPingPong(b *testing.B) {
	for _, cfg := range benchConfigs {
		b.Run(fmt.Sprintf("cc=%s/rack=%t", cfg.cc, cfg.rack), func(b *testing.B) {
			ts := newTwoStacks(b, cfg)
			ts.startPump()
			defer ts.stop()

			pair := ts.connectPair(b)
			defer pair.client.Close()
			defer pair.server.Close()

			// Echo server goroutine. Runs until the endpoint is closed by the
			// deferred closes after the measurement.
			echoQuit := make(chan struct{})
			defer close(echoQuit)
			go func() {
				we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				pair.serverWQ.EventRegister(&we)
				defer pair.serverWQ.EventUnregister(&we)
				var echo bytes.Buffer
				for {
					select {
					case <-echoQuit:
						return
					default:
					}
					_, err := pair.server.Read(&echo, tcpip.ReadOptions{})
					if err == nil {
						// Echo back the bytes just read.
						r := bytes.NewReader(echo.Bytes())
						echo.Reset()
						for r.Len() > 0 {
							if _, werr := pair.server.Write(r, tcpip.WriteOptions{}); werr != nil {
								if _, ok := werr.(*tcpip.ErrWouldBlock); !ok {
									failf("server echo Write: %s", werr)
								}
								waitWritable(b, pair.server, pair.serverWQ)
							}
						}
						continue
					}
					if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
						// Endpoint closure during teardown can surface as a read
						// error here; treat it as benign once teardown has begun.
						select {
						case <-echoQuit:
							return
						default:
						}
						failf("server echo Read: %s", err)
					}
					select {
					case <-echoQuit:
						return
					case <-ch:
					}
				}
			}()

			msg := make([]byte, 64)
			we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			pair.clientWQ.EventRegister(&we)
			defer pair.clientWQ.EventUnregister(&we)

			start := time.Now()
			for i := 0; i < b.N; i++ {
				// Write the message fully: a partial write (nil error, fewer
				// bytes consumed) would otherwise truncate the echoed reply and
				// hang the read loop below.
				r := bytes.NewReader(msg)
				for r.Len() > 0 {
					if _, err := pair.client.Write(r, tcpip.WriteOptions{}); err != nil {
						if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
							b.Fatalf("Write: %s", err)
						}
						waitWritable(b, pair.client, pair.clientWQ)
					}
				}
				got := 0
				for got < len(msg) {
					res, err := pair.client.Read(discard{}, tcpip.ReadOptions{})
					if err == nil {
						got += res.Count
						continue
					}
					if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
						b.Fatalf("Read: %s", err)
					}
					if pair.client.Readiness(waiter.ReadableEvents) != 0 {
						continue
					}
					<-ch
				}
			}
			elapsed := time.Since(start)
			b.ReportMetric(float64(elapsed)/float64(b.N)/float64(time.Microsecond), "us/rtt")
		})
	}
}

// BenchmarkPerAckSegmentCost measures the sender's per-ACK processing cost
// directly: it keeps the pipe full and counts segments and elapsed CPU time
// to send/ack a large number of packets, amortizing away goroutine wakeup
// costs, reporting per-segment time on the hot path.
func BenchmarkPerAckSegmentCost(b *testing.B) {
	for _, cfg := range benchConfigs {
		b.Run(fmt.Sprintf("cc=%s/rack=%t", cfg.cc, cfg.rack), func(b *testing.B) {
			ts := newTwoStacks(b, cfg)
			ts.startPump()
			defer ts.stop()

			pair := ts.connectPair(b)
			defer pair.client.Close()
			defer pair.server.Close()

			total := int64(32 << 20)
			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				readAll(pair.server, pair.serverWQ, total*int64(b.N))
			}()

			data := make([]byte, 128*1024)
			before := snapshotTCPStats(ts.client)
			start := time.Now()
			for i := 0; i < b.N; i++ {
				// Reuse a single bytes.Reader across writes (as benchBulk does):
				// after a partial write, the next Write offers only the remaining
				// unconsumed bytes instead of restarting from a full buffer.
				var wrote int64
				r := bytes.NewReader(data)
				for wrote < total {
					if r.Len() == 0 {
						r.Reset(data)
					}
					n, err := pair.client.Write(r, tcpip.WriteOptions{})
					if err != nil {
						if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
							b.Fatalf("Write: %s", err)
						}
						waitWritable(b, pair.client, pair.clientWQ)
						continue
					}
					wrote += n
				}
			}
			<-readerDone
			elapsed := time.Since(start)
			after := snapshotTCPStats(ts.client)
			d := after.diff(before)
			b.ReportMetric(float64(elapsed.Microseconds())/float64(d.segmentsSent), "us/segment-sent")
			b.ReportMetric(float64(total*int64(b.N))/elapsed.Seconds()/(1<<20), "MiB/s")

			b.Log("tcp:", d)
		})
	}
}
