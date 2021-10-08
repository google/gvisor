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

//go:build linux
// +build linux

// Package sharedmem provides the implemention of data-link layer endpoints
// backed by shared memory.
//
// Shared memory endpoints can be used in the networking stack by calling New()
// to create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package sharedmem

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// QueueConfig holds all the file descriptors needed to describe a tx or rx
// queue over shared memory. It is used when creating new shared memory
// endpoints to describe tx and rx queues.
type QueueConfig struct {
	// DataFD is a file descriptor for the file that contains the data to
	// be transmitted via this queue. Descriptors contain offsets within
	// this file.
	DataFD int

	// EventFD is a file descriptor for the event that is signaled when
	// data is becomes available in this queue.
	EventFD eventfd.Eventfd

	// TxPipeFD is a file descriptor for the tx pipe associated with the
	// queue.
	TxPipeFD int

	// RxPipeFD is a file descriptor for the rx pipe associated with the
	// queue.
	RxPipeFD int

	// SharedDataFD is a file descriptor for the file that contains shared
	// state between the two ends of the queue. This data specifies, for
	// example, whether EventFD signaling is enabled or disabled.
	SharedDataFD int
}

// FDs returns the FD's in the QueueConfig as a slice of ints. This must
// be used in conjunction with QueueConfigFromFDs to ensure the order
// of FDs matches when reconstructing the config when serialized or sent
// as part of control messages.
func (q *QueueConfig) FDs() []int {
	return []int{q.DataFD, q.EventFD.FD(), q.TxPipeFD, q.RxPipeFD, q.SharedDataFD}
}

// QueueConfigFromFDs constructs a QueueConfig out of a slice of ints where each
// entry represents an file descriptor. The order of FDs in the slice must be in
// the order specified below for the config to be valid. QueueConfig.FDs()
// should be used when the config needs to be serialized or sent as part of a
// control message to ensure the correct order.
func QueueConfigFromFDs(fds []int) (QueueConfig, error) {
	if len(fds) != 5 {
		return QueueConfig{}, fmt.Errorf("insufficient number of fds: len(fds): %d, want: 5", len(fds))
	}
	return QueueConfig{
		DataFD:       fds[0],
		EventFD:      eventfd.Wrap(fds[1]),
		TxPipeFD:     fds[2],
		RxPipeFD:     fds[3],
		SharedDataFD: fds[4],
	}, nil
}

// Options specify the details about the sharedmem endpoint to be created.
type Options struct {
	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// BufferSize is the size of each scatter/gather buffer that will hold packet
	// data.
	//
	// NOTE: This directly determines number of packets that can be held in
	// the ring buffer at any time. This does not have to be sized to the MTU as
	// the shared memory queue design allows usage of more than one buffer to be
	// used to make up a given packet.
	BufferSize uint32

	// LinkAddress is the link address for this endpoint (required).
	LinkAddress tcpip.LinkAddress

	// TX is the transmit queue configuration for this shared memory endpoint.
	TX QueueConfig

	// RX is the receive queue configuration for this shared memory endpoint.
	RX QueueConfig

	// PeerFD is the fd for the connected peer which can be used to detect
	// peer disconnects.
	PeerFD int

	// OnClosed is a function that is called when the endpoint is being closed
	// (probably due to peer going away)
	OnClosed func(err tcpip.Error)

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool
}

type endpoint struct {
	// mtu (maximum transmission unit) is the maximum size of a packet.
	// mtu is immutable.
	mtu uint32

	// bufferSize is the size of each individual buffer.
	// bufferSize is immutable.
	bufferSize uint32

	// addr is the local address of this endpoint.
	// addr is immutable.
	addr tcpip.LinkAddress

	// peerFD is an fd to the peer that can be used to detect when the
	// peer is gone.
	// peerFD is immutable.
	peerFD int

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// hdrSize is the size of the link layer header if any.
	// hdrSize is immutable.
	hdrSize uint32

	// rx is the receive queue.
	rx rx

	// stopRequested is to be accessed atomically only, and determines if
	// the worker goroutines should stop.
	stopRequested uint32

	// Wait group used to indicate that all workers have stopped.
	completed sync.WaitGroup

	// onClosed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	onClosed func(tcpip.Error)

	// mu protects the following fields.
	mu sync.Mutex

	// tx is the transmit queue.
	// +checklocks:mu
	tx tx

	// workerStarted specifies whether the worker goroutine was started.
	// +checklocks:mu
	workerStarted bool
}

// New creates a new shared-memory-based endpoint. Buffers will be broken up
// into buffers of "bufferSize" bytes.
func New(opts Options) (stack.LinkEndpoint, error) {
	e := &endpoint{
		mtu:        opts.MTU,
		bufferSize: opts.BufferSize,
		addr:       opts.LinkAddress,
		peerFD:     opts.PeerFD,
		onClosed:   opts.OnClosed,
	}

	if err := e.tx.init(opts.BufferSize, &opts.TX); err != nil {
		return nil, err
	}

	if err := e.rx.init(opts.BufferSize, &opts.RX); err != nil {
		e.tx.cleanup()
		return nil, err
	}

	e.caps = stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		e.caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		e.caps |= stack.CapabilityTXChecksumOffload
	}

	if opts.LinkAddress != "" {
		e.hdrSize = header.EthernetMinimumSize
		e.caps |= stack.CapabilityResolutionRequired
	}
	return e, nil
}

// Close frees all resources associated with the endpoint.
func (e *endpoint) Close() {
	// Tell dispatch goroutine to stop, then write to the eventfd so that
	// it wakes up in case it's sleeping.
	atomic.StoreUint32(&e.stopRequested, 1)
	e.rx.eventFD.Notify()

	// Cleanup the queues inline if the worker hasn't started yet; we also
	// know it won't start from now on because stopRequested is set to 1.
	e.mu.Lock()
	defer e.mu.Unlock()
	workerPresent := e.workerStarted

	if !workerPresent {
		e.tx.cleanup()
		e.rx.cleanup()
	}
}

// Wait implements stack.LinkEndpoint.Wait. It waits until all workers have
// stopped after a Close() call.
func (e *endpoint) Wait() {
	e.completed.Wait()
}

// Attach implements stack.LinkEndpoint.Attach. It launches the goroutine that
// reads packets from the rx queue.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if !e.workerStarted && atomic.LoadUint32(&e.stopRequested) == 0 {
		e.workerStarted = true
		e.completed.Add(1)

		// Spin up a goroutine to monitor for peer shutdown.
		if e.peerFD >= 0 {
			e.completed.Add(1)
			go func() {
				defer e.completed.Done()
				b := make([]byte, 1)
				// When sharedmem endpoint is in use the peerFD is never used for any data
				// transfer and this Read should only return if the peer is shutting down.
				_, err := rawfile.BlockingRead(e.peerFD, b)
				if e.onClosed != nil {
					e.onClosed(err)
				}
			}()
		}

		// Link endpoints are not savable. When transportation endpoints
		// are saved, they stop sending outgoing packets and all
		// incoming packets are rejected.
		go e.dispatchLoop(dispatcher) // S/R-SAFE: see above.
	}
	e.mu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu - e.hdrSize
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. It returns the
// ethernet frame header size.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress. It returns the local
// link address.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	// Add ethernet header if needed.
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	ethHdr := &header.EthernetFields{
		DstAddr: remote,
		Type:    protocol,
	}

	// Preserve the src address if it's set in the route.
	if local != "" {
		ethHdr.SrcAddr = local
	} else {
		ethHdr.SrcAddr = e.addr
	}
	eth.Encode(ethHdr)
}

// WriteRawPacket implements stack.LinkEndpoint.
func (*endpoint) WriteRawPacket(*stack.PacketBuffer) tcpip.Error { return &tcpip.ErrNotSupported{} }

// +checklocks:e.mu
func (e *endpoint) writePacketLocked(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if e.addr != "" {
		e.AddHeader(r.LocalLinkAddress, r.RemoteLinkAddress, protocol, pkt)
	}

	views := pkt.Views()
	// Transmit the packet.
	ok := e.tx.transmit(views...)
	if !ok {
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.writePacketLocked(r, protocol, pkt); err != nil {
		return err
	}
	e.tx.notify()
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := 0
	var err tcpip.Error
	e.mu.Lock()
	defer e.mu.Unlock()
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err = e.writePacketLocked(r, pkt.NetworkProtocolNumber, pkt); err != nil {
			break
		}
		n++
	}
	// WritePackets never returns an error if it successfully transmitted at least
	// one packet.
	if err != nil && n == 0 {
		return 0, err
	}
	e.tx.notify()
	return n, nil
}

// dispatchLoop reads packets from the rx queue in a loop and dispatches them
// to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) {
	// Post initial set of buffers.
	limit := e.rx.q.PostedBuffersLimit()
	if l := uint64(len(e.rx.data)) / uint64(e.bufferSize); limit > l {
		limit = l
	}
	for i := uint64(0); i < limit; i++ {
		b := queue.RxBuffer{
			Offset: i * uint64(e.bufferSize),
			Size:   e.bufferSize,
			ID:     i,
		}
		if !e.rx.q.PostBuffers([]queue.RxBuffer{b}) {
			log.Warningf("Unable to post %v-th buffer", i)
		}
	}

	// Read in a loop until a stop is requested.
	var rxb []queue.RxBuffer
	for atomic.LoadUint32(&e.stopRequested) == 0 {
		var n uint32
		rxb, n = e.rx.postAndReceive(rxb, &e.stopRequested)

		// Copy data from the shared area to its own buffer, then
		// prepare to repost the buffer.
		b := make([]byte, n)
		offset := uint32(0)
		for i := range rxb {
			copy(b[offset:], e.rx.data[rxb[i].Offset:][:rxb[i].Size])
			offset += rxb[i].Size

			rxb[i].Size = e.bufferSize
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.View(b).ToVectorisedView(),
		})

		var src, dst tcpip.LinkAddress
		var proto tcpip.NetworkProtocolNumber
		if e.addr != "" {
			hdr, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
			if !ok {
				continue
			}
			eth := header.Ethernet(hdr)
			src = eth.SourceAddress()
			dst = eth.DestinationAddress()
			proto = eth.Type()
		} else {
			// We don't get any indication of what the packet is, so try to guess
			// if it's an IPv4 or IPv6 packet.
			// IP version information is at the first octet, so pulling up 1 byte.
			h, ok := pkt.Data().PullUp(1)
			if !ok {
				continue
			}
			switch header.IPVersion(h) {
			case header.IPv4Version:
				proto = header.IPv4ProtocolNumber
			case header.IPv6Version:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
		}

		// Send packet up the stack.
		d.DeliverNetworkPacket(src, dst, proto, pkt)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Clean state.
	e.tx.cleanup()
	e.rx.cleanup()

	e.completed.Done()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType
func (*endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}
