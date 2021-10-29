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

//go:build linux
// +build linux

package sharedmem

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type serverEndpoint struct {
	// mtu (maximum transmission unit) is the maximum size of a packet.
	// mtu is immutable.
	mtu uint32

	// bufferSize is the size of each individual buffer.
	// bufferSize is immutable.
	bufferSize uint32

	// addr is the local address of this endpoint.
	// addr is immutable
	addr tcpip.LinkAddress

	// rx is the receive queue.
	rx serverRx

	// stopRequested is to be accessed atomically only, and determines if the
	// worker goroutines should stop.
	stopRequested uint32

	// Wait group used to indicate that all workers have stopped.
	completed sync.WaitGroup

	// peerFD is an fd to the peer that can be used to detect when the peer is
	// gone.
	// peerFD is immutable.
	peerFD int

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// hdrSize is the size of the link layer header if any.
	// hdrSize is immutable.
	hdrSize uint32

	// onClosed is a function to be called when the FD's peer (if any) closes its
	// end of the communication pipe.
	onClosed func(tcpip.Error)

	// mu protects the following fields.
	mu sync.Mutex

	// tx is the transmit queue.
	// +checklocks:mu
	tx serverTx

	// workerStarted specifies whether the worker goroutine was started.
	// +checklocks:mu
	workerStarted bool
}

// NewServerEndpoint creates a new shared-memory-based endpoint. Buffers will be
// broken up into buffers of "bufferSize" bytes.
func NewServerEndpoint(opts Options) (stack.LinkEndpoint, error) {
	e := &serverEndpoint{
		mtu:        opts.MTU,
		bufferSize: opts.BufferSize,
		addr:       opts.LinkAddress,
		peerFD:     opts.PeerFD,
		onClosed:   opts.OnClosed,
	}

	if err := e.tx.init(&opts.RX); err != nil {
		return nil, err
	}

	if err := e.rx.init(&opts.TX); err != nil {
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
func (e *serverEndpoint) Close() {
	// Tell dispatch goroutine to stop, then write to the eventfd so that it wakes
	// up in case it's sleeping.
	atomic.StoreUint32(&e.stopRequested, 1)
	e.rx.eventFD.Notify()

	// Cleanup the queues inline if the worker hasn't started yet; we also know it
	// won't start from now on because stopRequested is set to 1.
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
func (e *serverEndpoint) Wait() {
	e.completed.Wait()
}

// Attach implements stack.LinkEndpoint.Attach. It launches the goroutine that
// reads packets from the rx queue.
func (e *serverEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if !e.workerStarted && atomic.LoadUint32(&e.stopRequested) == 0 {
		e.workerStarted = true
		e.completed.Add(1)
		if e.peerFD >= 0 {
			e.completed.Add(1)
			// Spin up a goroutine to monitor for peer shutdown.
			go func() {
				b := make([]byte, 1)
				// When sharedmem endpoint is in use the peerFD is never used for any
				// data transfer and this Read should only return if the peer is
				// shutting down.
				_, err := rawfile.BlockingRead(e.peerFD, b)
				if e.onClosed != nil {
					e.onClosed(err)
				}
				e.completed.Done()
			}()
		}
		// Link endpoints are not savable. When transportation endpoints are saved,
		// they stop sending outgoing packets and all incoming packets are rejected.
		go e.dispatchLoop(dispatcher) // S/R-SAFE: see above.
	}
	e.mu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *serverEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *serverEndpoint) MTU() uint32 {
	return e.mtu - e.hdrSize
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *serverEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. It returns the
// ethernet frame header size.
func (e *serverEndpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress. It returns the local
// link address.
func (e *serverEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *serverEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
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

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket
func (e *serverEndpoint) WriteRawPacket(pkt *stack.PacketBuffer) tcpip.Error {
	views := pkt.Views()
	e.mu.Lock()
	defer e.mu.Unlock()
	ok := e.tx.transmit(views)
	if !ok {
		return tcpip.ErrWouldBlock
	}
	e.tx.notify()
	return nil
}

// +checklocks:e.mu
func (e *serverEndpoint) writePacketLocked(r stack.RouteInfo, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if e.addr != "" {
		e.AddHeader(r.LocalLinkAddress, r.RemoteLinkAddress, protocol, pkt)
	}

	views := pkt.Views()
	ok := e.tx.transmit(views)
	if !ok {
		return tcpip.ErrWouldBlock
	}

	return nil
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
// WritePacket implements stack.LinkEndpoint.WritePacket.
func (e *serverEndpoint) WritePacket(_ stack.RouteInfo, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	// Transmit the packet.
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.writePacketLocked(pkt.EgressRoute, pkt.NetworkProtocolNumber, pkt); err != nil {
		return err
	}
	e.tx.notify()
	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *serverEndpoint) WritePackets(_ stack.RouteInfo, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n := 0
	var err tcpip.Error
	e.mu.Lock()
	defer e.mu.Unlock()
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err = e.writePacketLocked(pkt.EgressRoute, pkt.NetworkProtocolNumber, pkt); err != nil {
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
func (e *serverEndpoint) dispatchLoop(d stack.NetworkDispatcher) {
	for atomic.LoadUint32(&e.stopRequested) == 0 {
		b := e.rx.receive()
		if b == nil {
			e.rx.EnableNotification()
			// Now pull again to make sure we didn't receive any packets
			// while notifications were not enabled.
			for {
				b = e.rx.receive()
				if b != nil {
					// Disable notifications as we only need to be notified when we are going
					// to block on eventFD. This should prevent the peer from needlessly
					// writing to eventFD when this end is already awake and processing
					// packets.
					e.rx.DisableNotification()
					break
				}
				e.rx.waitForPackets()
			}
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.View(b).ToVectorisedView(),
		})
		var src, dst tcpip.LinkAddress
		var proto tcpip.NetworkProtocolNumber
		if e.addr != "" {
			hdr, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
			if !ok {
				pkt.DecRef()
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
				pkt.DecRef()
				continue
			}
			switch header.IPVersion(h) {
			case header.IPv4Version:
				proto = header.IPv4ProtocolNumber
			case header.IPv6Version:
				proto = header.IPv6ProtocolNumber
			default:
				pkt.DecRef()
				continue
			}
		}
		// Send packet up the stack.
		d.DeliverNetworkPacket(src, dst, proto, pkt)
		pkt.DecRef()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Clean state.
	e.tx.cleanup()
	e.rx.cleanup()

	e.completed.Done()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType
func (e *serverEndpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}
