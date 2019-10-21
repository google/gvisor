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

// +build linux

package sharedmem

import (
	"bytes"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	localLinkAddr  = "\xde\xad\xbe\xef\x56\x78"
	remoteLinkAddr = "\xde\xad\xbe\xef\x12\x34"

	queueDataSize = 1024 * 1024
	queuePipeSize = 4096
)

type queueBuffers struct {
	data []byte
	rx   pipe.Tx
	tx   pipe.Rx
}

func initQueue(t *testing.T, q *queueBuffers, c *QueueConfig) {
	// Prepare tx pipe.
	b, err := getBuffer(c.TxPipeFD)
	if err != nil {
		t.Fatalf("getBuffer failed: %v", err)
	}
	q.tx.Init(b)

	// Prepare rx pipe.
	b, err = getBuffer(c.RxPipeFD)
	if err != nil {
		t.Fatalf("getBuffer failed: %v", err)
	}
	q.rx.Init(b)

	// Get data slice.
	q.data, err = getBuffer(c.DataFD)
	if err != nil {
		t.Fatalf("getBuffer failed: %v", err)
	}
}

func (q *queueBuffers) cleanup() {
	syscall.Munmap(q.tx.Bytes())
	syscall.Munmap(q.rx.Bytes())
	syscall.Munmap(q.data)
}

type packetInfo struct {
	addr       tcpip.LinkAddress
	proto      tcpip.NetworkProtocolNumber
	vv         buffer.VectorisedView
	linkHeader buffer.View
}

type testContext struct {
	t     *testing.T
	ep    *endpoint
	txCfg QueueConfig
	rxCfg QueueConfig
	txq   queueBuffers
	rxq   queueBuffers

	packetCh chan struct{}
	mu       sync.Mutex
	packets  []packetInfo
}

func newTestContext(t *testing.T, mtu, bufferSize uint32, addr tcpip.LinkAddress) *testContext {
	var err error
	c := &testContext{
		t:        t,
		packetCh: make(chan struct{}, 1000000),
	}
	c.txCfg = createQueueFDs(t, queueSizes{
		dataSize:       queueDataSize,
		txPipeSize:     queuePipeSize,
		rxPipeSize:     queuePipeSize,
		sharedDataSize: 4096,
	})

	c.rxCfg = createQueueFDs(t, queueSizes{
		dataSize:       queueDataSize,
		txPipeSize:     queuePipeSize,
		rxPipeSize:     queuePipeSize,
		sharedDataSize: 4096,
	})

	initQueue(t, &c.txq, &c.txCfg)
	initQueue(t, &c.rxq, &c.rxCfg)

	ep, err := New(mtu, bufferSize, addr, c.txCfg, c.rxCfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	c.ep = ep.(*endpoint)
	c.ep.Attach(c)

	return c
}

func (c *testContext) DeliverNetworkPacket(_ stack.LinkEndpoint, remoteLinkAddr, localLinkAddr tcpip.LinkAddress, proto tcpip.NetworkProtocolNumber, vv buffer.VectorisedView, linkHeader buffer.View) {
	c.mu.Lock()
	c.packets = append(c.packets, packetInfo{
		addr:       remoteLinkAddr,
		proto:      proto,
		vv:         vv.Clone(nil),
		linkHeader: linkHeader,
	})
	c.mu.Unlock()

	c.packetCh <- struct{}{}
}

func (c *testContext) cleanup() {
	c.ep.Close()
	closeFDs(&c.txCfg)
	closeFDs(&c.rxCfg)
	c.txq.cleanup()
	c.rxq.cleanup()
}

func (c *testContext) waitForPackets(n int, to <-chan time.Time, errorStr string) {
	for i := 0; i < n; i++ {
		select {
		case <-c.packetCh:
		case <-to:
			c.t.Fatalf(errorStr)
		}
	}
}

func (c *testContext) pushRxCompletion(size uint32, bs []queue.RxBuffer) {
	b := c.rxq.rx.Push(queue.RxCompletionSize(len(bs)))
	queue.EncodeRxCompletion(b, size, 0)
	for i := range bs {
		queue.EncodeRxCompletionBuffer(b, i, queue.RxBuffer{
			Offset: bs[i].Offset,
			Size:   bs[i].Size,
			ID:     bs[i].ID,
		})
	}
}

func randomFill(b []byte) {
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
}

func shuffle(b []int) {
	for i := len(b) - 1; i >= 0; i-- {
		j := rand.Intn(i + 1)
		b[i], b[j] = b[j], b[i]
	}
}

func createFile(t *testing.T, size int64, initQueue bool) int {
	tmpDir := os.Getenv("TEST_TMPDIR")
	if tmpDir == "" {
		tmpDir = os.Getenv("TMPDIR")
	}
	f, err := ioutil.TempFile(tmpDir, "sharedmem_test")
	if err != nil {
		t.Fatalf("TempFile failed: %v", err)
	}
	defer f.Close()
	syscall.Unlink(f.Name())

	if initQueue {
		// Write the "slot-free" flag in the initial queue.
		_, err := f.WriteAt([]byte{0, 0, 0, 0, 0, 0, 0, 0x80}, 0)
		if err != nil {
			t.Fatalf("WriteAt failed: %v", err)
		}
	}

	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatalf("Dup failed: %v", err)
	}

	if err := syscall.Ftruncate(fd, size); err != nil {
		syscall.Close(fd)
		t.Fatalf("Ftruncate failed: %v", err)
	}

	return fd
}

func closeFDs(c *QueueConfig) {
	syscall.Close(c.DataFD)
	syscall.Close(c.EventFD)
	syscall.Close(c.TxPipeFD)
	syscall.Close(c.RxPipeFD)
	syscall.Close(c.SharedDataFD)
}

type queueSizes struct {
	dataSize       int64
	txPipeSize     int64
	rxPipeSize     int64
	sharedDataSize int64
}

func createQueueFDs(t *testing.T, s queueSizes) QueueConfig {
	fd, _, err := syscall.RawSyscall(syscall.SYS_EVENTFD2, 0, 0, 0)
	if err != 0 {
		t.Fatalf("eventfd failed: %v", error(err))
	}

	return QueueConfig{
		EventFD:      int(fd),
		DataFD:       createFile(t, s.dataSize, false),
		TxPipeFD:     createFile(t, s.txPipeSize, true),
		RxPipeFD:     createFile(t, s.rxPipeSize, true),
		SharedDataFD: createFile(t, s.sharedDataSize, false),
	}
}

// TestSimpleSend sends 1000 packets with random header and payload sizes,
// then checks that the right payload is received on the shared memory queues.
func TestSimpleSend(t *testing.T) {
	c := newTestContext(t, 20000, 1500, localLinkAddr)
	defer c.cleanup()

	// Prepare route.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}

	for iters := 1000; iters > 0; iters-- {
		func() {
			// Prepare and send packet.
			n := rand.Intn(10000)
			hdr := buffer.NewPrependable(n + int(c.ep.MaxHeaderLength()))
			hdrBuf := hdr.Prepend(n)
			randomFill(hdrBuf)

			n = rand.Intn(10000)
			buf := buffer.NewView(n)
			randomFill(buf)

			proto := tcpip.NetworkProtocolNumber(rand.Intn(0x10000))
			if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), proto); err != nil {
				t.Fatalf("WritePacket failed: %v", err)
			}

			// Receive packet.
			desc := c.txq.tx.Pull()
			pi := queue.DecodeTxPacketHeader(desc)
			if pi.Reserved != 0 {
				t.Fatalf("Reserved value is non-zero: 0x%x", pi.Reserved)
			}
			contents := make([]byte, 0, pi.Size)
			for i := 0; i < pi.BufferCount; i++ {
				bi := queue.DecodeTxBufferHeader(desc, i)
				contents = append(contents, c.txq.data[bi.Offset:][:bi.Size]...)
			}
			c.txq.tx.Flush()

			defer func() {
				// Tell the endpoint about the completion of the write.
				b := c.txq.rx.Push(8)
				queue.EncodeTxCompletion(b, pi.ID)
				c.txq.rx.Flush()
			}()

			// Check the ethernet header.
			ethTemplate := make(header.Ethernet, header.EthernetMinimumSize)
			ethTemplate.Encode(&header.EthernetFields{
				SrcAddr: localLinkAddr,
				DstAddr: remoteLinkAddr,
				Type:    proto,
			})
			if got := contents[:header.EthernetMinimumSize]; !bytes.Equal(got, []byte(ethTemplate)) {
				t.Fatalf("Bad ethernet header in packet: got %x, want %x", got, ethTemplate)
			}

			// Compare contents skipping the ethernet header added by the
			// endpoint.
			merged := append(hdrBuf, buf...)
			if uint32(len(contents)) < pi.Size {
				t.Fatalf("Sum of buffers is less than packet size: %v < %v", len(contents), pi.Size)
			}
			contents = contents[:pi.Size][header.EthernetMinimumSize:]

			if !bytes.Equal(contents, merged) {
				t.Fatalf("Buffers are different: got %x (%v bytes), want %x (%v bytes)", contents, len(contents), merged, len(merged))
			}
		}()
	}
}

// TestPreserveSrcAddressInSend calls WritePacket once with LocalLinkAddress
// set in Route (using much of the same code as TestSimpleSend), then checks
// that the encoded ethernet header received includes the correct SrcAddr.
func TestPreserveSrcAddressInSend(t *testing.T) {
	c := newTestContext(t, 20000, 1500, localLinkAddr)
	defer c.cleanup()

	newLocalLinkAddress := tcpip.LinkAddress(strings.Repeat("0xFE", 6))
	// Set both remote and local link address in route.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
		LocalLinkAddress:  newLocalLinkAddress,
	}

	// WritePacket panics given a prependable with anything less than
	// the minimum size of the ethernet header.
	hdr := buffer.NewPrependable(header.EthernetMinimumSize)

	proto := tcpip.NetworkProtocolNumber(rand.Intn(0x10000))
	if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buffer.VectorisedView{}, proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Receive packet.
	desc := c.txq.tx.Pull()
	pi := queue.DecodeTxPacketHeader(desc)
	if pi.Reserved != 0 {
		t.Fatalf("Reserved value is non-zero: 0x%x", pi.Reserved)
	}
	contents := make([]byte, 0, pi.Size)
	for i := 0; i < pi.BufferCount; i++ {
		bi := queue.DecodeTxBufferHeader(desc, i)
		contents = append(contents, c.txq.data[bi.Offset:][:bi.Size]...)
	}
	c.txq.tx.Flush()

	defer func() {
		// Tell the endpoint about the completion of the write.
		b := c.txq.rx.Push(8)
		queue.EncodeTxCompletion(b, pi.ID)
		c.txq.rx.Flush()
	}()

	// Check that the ethernet header contains the expected SrcAddr.
	ethTemplate := make(header.Ethernet, header.EthernetMinimumSize)
	ethTemplate.Encode(&header.EthernetFields{
		SrcAddr: newLocalLinkAddress,
		DstAddr: remoteLinkAddr,
		Type:    proto,
	})
	if got := contents[:header.EthernetMinimumSize]; !bytes.Equal(got, []byte(ethTemplate)) {
		t.Fatalf("Bad ethernet header in packet: got %x, want %x", got, ethTemplate)
	}
}

// TestFillTxQueue sends packets until the queue is full.
func TestFillTxQueue(t *testing.T) {
	c := newTestContext(t, 20000, 1500, localLinkAddr)
	defer c.cleanup()

	// Prepare to send a packet.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}

	buf := buffer.NewView(100)

	// Each packet is uses no more than 40 bytes, so write that many packets
	// until the tx queue if full.
	ids := make(map[uint64]struct{})
	for i := queuePipeSize / 40; i > 0; i-- {
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))

		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}

		// Check that they have different IDs.
		desc := c.txq.tx.Pull()
		pi := queue.DecodeTxPacketHeader(desc)
		if _, ok := ids[pi.ID]; ok {
			t.Fatalf("ID (%v) reused", pi.ID)
		}
		ids[pi.ID] = struct{}{}
	}

	// Next attempt to write must fail.
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
	if want, err := tcpip.ErrWouldBlock, c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != want {
		t.Fatalf("WritePacket return unexpected result: got %v, want %v", err, want)
	}
}

// TestFillTxQueueAfterBadCompletion sends a bad completion, then sends packets
// until the queue is full.
func TestFillTxQueueAfterBadCompletion(t *testing.T) {
	c := newTestContext(t, 20000, 1500, localLinkAddr)
	defer c.cleanup()

	// Send a bad completion.
	queue.EncodeTxCompletion(c.txq.rx.Push(8), 1)
	c.txq.rx.Flush()

	// Prepare to send a packet.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}

	buf := buffer.NewView(100)

	// Send two packets so that the id slice has at least two slots.
	for i := 2; i > 0; i-- {
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}
	}

	// Complete the two writes twice.
	for i := 2; i > 0; i-- {
		pi := queue.DecodeTxPacketHeader(c.txq.tx.Pull())

		queue.EncodeTxCompletion(c.txq.rx.Push(8), pi.ID)
		queue.EncodeTxCompletion(c.txq.rx.Push(8), pi.ID)
		c.txq.rx.Flush()
	}
	c.txq.tx.Flush()

	// Each packet is uses no more than 40 bytes, so write that many packets
	// until the tx queue if full.
	ids := make(map[uint64]struct{})
	for i := queuePipeSize / 40; i > 0; i-- {
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}

		// Check that they have different IDs.
		desc := c.txq.tx.Pull()
		pi := queue.DecodeTxPacketHeader(desc)
		if _, ok := ids[pi.ID]; ok {
			t.Fatalf("ID (%v) reused", pi.ID)
		}
		ids[pi.ID] = struct{}{}
	}

	// Next attempt to write must fail.
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
	if want, err := tcpip.ErrWouldBlock, c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != want {
		t.Fatalf("WritePacket return unexpected result: got %v, want %v", err, want)
	}
}

// TestFillTxMemory sends packets until the we run out of shared memory.
func TestFillTxMemory(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	defer c.cleanup()

	// Prepare to send a packet.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}

	buf := buffer.NewView(100)

	// Each packet is uses up one buffer, so write as many as possible until
	// we fill the memory.
	ids := make(map[uint64]struct{})
	for i := queueDataSize / bufferSize; i > 0; i-- {
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}

		// Check that they have different IDs.
		desc := c.txq.tx.Pull()
		pi := queue.DecodeTxPacketHeader(desc)
		if _, ok := ids[pi.ID]; ok {
			t.Fatalf("ID (%v) reused", pi.ID)
		}
		ids[pi.ID] = struct{}{}
		c.txq.tx.Flush()
	}

	// Next attempt to write must fail.
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
	err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber)
	if want := tcpip.ErrWouldBlock; err != want {
		t.Fatalf("WritePacket return unexpected result: got %v, want %v", err, want)
	}
}

// TestFillTxMemoryWithMultiBuffer sends packets until the we run out of
// shared memory for a 2-buffer packet, but still with room for a 1-buffer
// packet.
func TestFillTxMemoryWithMultiBuffer(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	defer c.cleanup()

	// Prepare to send a packet.
	r := stack.Route{
		RemoteLinkAddress: remoteLinkAddr,
	}

	buf := buffer.NewView(100)

	// Each packet is uses up one buffer, so write as many as possible
	// until there is only one buffer left.
	for i := queueDataSize/bufferSize - 1; i > 0; i-- {
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}

		// Pull the posted buffer.
		c.txq.tx.Pull()
		c.txq.tx.Flush()
	}

	// Attempt to write a two-buffer packet. It must fail.
	{
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		uu := buffer.NewView(bufferSize).ToVectorisedView()
		if want, err := tcpip.ErrWouldBlock, c.ep.WritePacket(&r, nil /* gso */, hdr, uu, header.IPv4ProtocolNumber); err != want {
			t.Fatalf("WritePacket return unexpected result: got %v, want %v", err, want)
		}
	}

	// Attempt to write the one-buffer packet again. It must succeed.
	{
		hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()))
		if err := c.ep.WritePacket(&r, nil /* gso */, hdr, buf.ToVectorisedView(), header.IPv4ProtocolNumber); err != nil {
			t.Fatalf("WritePacket failed unexpectedly: %v", err)
		}
	}
}

func pollPull(t *testing.T, p *pipe.Rx, to <-chan time.Time, errStr string) []byte {
	t.Helper()

	for {
		b := p.Pull()
		if b != nil {
			return b
		}

		select {
		case <-time.After(10 * time.Millisecond):
		case <-to:
			t.Fatal(errStr)
		}
	}
}

// TestSimpleReceive completes 1000 different receives with random payload and
// random number of buffers. It checks that the contents match the expected
// values.
func TestSimpleReceive(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	defer c.cleanup()

	// Check that buffers have been posted.
	limit := c.ep.rx.q.PostedBuffersLimit()
	for i := uint64(0); i < limit; i++ {
		timeout := time.After(2 * time.Second)
		bi := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, timeout, "Timeout waiting for all buffers to be posted"))

		if want := i * bufferSize; want != bi.Offset {
			t.Fatalf("Bad posted offset: got %v, want %v", bi.Offset, want)
		}

		if want := i; want != bi.ID {
			t.Fatalf("Bad posted ID: got %v, want %v", bi.ID, want)
		}

		if bufferSize != bi.Size {
			t.Fatalf("Bad posted bufferSize: got %v, want %v", bi.Size, bufferSize)
		}
	}
	c.rxq.tx.Flush()

	// Create a slice with the indices 0..limit-1.
	idx := make([]int, limit)
	for i := range idx {
		idx[i] = i
	}

	// Complete random packets 1000 times.
	for iters := 1000; iters > 0; iters-- {
		timeout := time.After(2 * time.Second)
		// Prepare a random packet.
		shuffle(idx)
		n := 1 + rand.Intn(10)
		bufs := make([]queue.RxBuffer, n)
		contents := make([]byte, bufferSize*n-rand.Intn(500))
		randomFill(contents)
		for i := range bufs {
			j := idx[i]
			bufs[i].Size = bufferSize
			bufs[i].Offset = uint64(bufferSize * j)
			bufs[i].ID = uint64(j)

			copy(c.rxq.data[bufs[i].Offset:][:bufferSize], contents[i*bufferSize:])
		}

		// Push completion.
		c.pushRxCompletion(uint32(len(contents)), bufs)
		c.rxq.rx.Flush()
		syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

		// Wait for packet to be received, then check it.
		c.waitForPackets(1, time.After(5*time.Second), "Timeout waiting for packet")
		c.mu.Lock()
		rcvd := []byte(c.packets[0].vv.First())
		c.packets = c.packets[:0]
		c.mu.Unlock()

		if contents := contents[header.EthernetMinimumSize:]; !bytes.Equal(contents, rcvd) {
			t.Fatalf("Unexpected buffer contents: got %x, want %x", rcvd, contents)
		}

		// Check that buffers have been reposted.
		for i := range bufs {
			bi := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, timeout, "Timeout waiting for buffers to be reposted"))
			if bi != bufs[i] {
				t.Fatalf("Unexpected buffer reposted: got %x, want %x", bi, bufs[i])
			}
		}
		c.rxq.tx.Flush()
	}
}

// TestRxBuffersReposted tests that rx buffers get reposted after they have been
// completed.
func TestRxBuffersReposted(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	defer c.cleanup()

	// Receive all posted buffers.
	limit := c.ep.rx.q.PostedBuffersLimit()
	buffers := make([]queue.RxBuffer, 0, limit)
	for i := limit; i > 0; i-- {
		timeout := time.After(2 * time.Second)
		buffers = append(buffers, queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, timeout, "Timeout waiting for all buffers")))
	}
	c.rxq.tx.Flush()

	// Check that all buffers are reposted when individually completed.
	for i := range buffers {
		timeout := time.After(2 * time.Second)
		// Complete the buffer.
		c.pushRxCompletion(buffers[i].Size, buffers[i:][:1])
		c.rxq.rx.Flush()
		syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

		// Wait for it to be reposted.
		bi := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, timeout, "Timeout waiting for buffer to be reposted"))
		if bi != buffers[i] {
			t.Fatalf("Different buffer posted: got %v, want %v", bi, buffers[i])
		}
	}
	c.rxq.tx.Flush()

	// Check that all buffers are reposted when completed in pairs.
	for i := 0; i < len(buffers)/2; i++ {
		timeout := time.After(2 * time.Second)
		// Complete with two buffers.
		c.pushRxCompletion(2*bufferSize, buffers[2*i:][:2])
		c.rxq.rx.Flush()
		syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

		// Wait for them to be reposted.
		for j := 0; j < 2; j++ {
			bi := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, timeout, "Timeout waiting for buffer to be reposted"))
			if bi != buffers[2*i+j] {
				t.Fatalf("Different buffer posted: got %v, want %v", bi, buffers[2*i+j])
			}
		}
	}
	c.rxq.tx.Flush()
}

// TestReceivePostingIsFull checks that the endpoint will properly handle the
// case when a received buffer cannot be immediately reposted because it hasn't
// been pulled from the tx pipe yet.
func TestReceivePostingIsFull(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	defer c.cleanup()

	// Complete first posted buffer before flushing it from the tx pipe.
	first := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, time.After(time.Second), "Timeout waiting for first buffer to be posted"))
	c.pushRxCompletion(first.Size, []queue.RxBuffer{first})
	c.rxq.rx.Flush()
	syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Check that packet is received.
	c.waitForPackets(1, time.After(time.Second), "Timeout waiting for completed packet")

	// Complete another buffer.
	second := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, time.After(time.Second), "Timeout waiting for second buffer to be posted"))
	c.pushRxCompletion(second.Size, []queue.RxBuffer{second})
	c.rxq.rx.Flush()
	syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Check that no packet is received yet, as the worker is blocked trying
	// to repost.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-c.packetCh:
		t.Fatalf("Unexpected packet received")
	}

	// Flush tx queue, which will allow the first buffer to be reposted,
	// and the second completion to be pulled.
	c.rxq.tx.Flush()
	syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Check that second packet completes.
	c.waitForPackets(1, time.After(time.Second), "Timeout waiting for second completed packet")
}

// TestCloseWhileWaitingToPost closes the endpoint while it is waiting to
// repost a buffer. Make sure it backs out.
func TestCloseWhileWaitingToPost(t *testing.T) {
	const bufferSize = 1500
	c := newTestContext(t, 20000, bufferSize, localLinkAddr)
	cleaned := false
	defer func() {
		if !cleaned {
			c.cleanup()
		}
	}()

	// Complete first posted buffer before flushing it from the tx pipe.
	bi := queue.DecodeRxBufferHeader(pollPull(t, &c.rxq.tx, time.After(time.Second), "Timeout waiting for initial buffer to be posted"))
	c.pushRxCompletion(bi.Size, []queue.RxBuffer{bi})
	c.rxq.rx.Flush()
	syscall.Write(c.rxCfg.EventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Wait for packet to be indicated.
	c.waitForPackets(1, time.After(time.Second), "Timeout waiting for completed packet")

	// Cleanup and wait for worker to complete.
	c.cleanup()
	cleaned = true
	c.ep.Wait()
}
