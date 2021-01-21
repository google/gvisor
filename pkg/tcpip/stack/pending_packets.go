// Copyright 2020 The gVisor Authors.
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

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// maxPendingResolutions is the maximum number of pending link-address
	// resolutions.
	maxPendingResolutions          = 64
	maxPendingPacketsPerResolution = 256
)

// pendingPacketBuffer is a pending packet buffer.
//
// TODO(gvisor.dev/issue/5331): Drop this when we drop WritePacket and only use
// WritePackets so we can use a PacketBufferList everywhere.
type pendingPacketBuffer interface {
	len() int
}

func (*PacketBuffer) len() int {
	return 1
}

func (p *PacketBufferList) len() int {
	return p.Len()
}

type pendingPacket struct {
	route *Route
	proto tcpip.NetworkProtocolNumber
	pkt   pendingPacketBuffer
}

// packetsPendingLinkResolution is a queue of packets pending link resolution.
//
// Once link resolution completes successfully, the packets will be written.
type packetsPendingLinkResolution struct {
	sync.Mutex

	// The packets to send once the resolver completes.
	packets map[<-chan struct{}][]pendingPacket

	// FIFO of channels used to cancel the oldest goroutine waiting for
	// link-address resolution.
	cancelChans []chan struct{}
}

func (f *packetsPendingLinkResolution) init() {
	f.Lock()
	defer f.Unlock()
	f.packets = make(map[<-chan struct{}][]pendingPacket)
}

func incrementOutgoingPacketErrors(r *Route, proto tcpip.NetworkProtocolNumber, pkt pendingPacketBuffer) {
	n := uint64(pkt.len())
	r.Stats().IP.OutgoingPacketErrors.IncrementBy(n)

	// ok may be false if the endpoint's stats do not collect IP-related data.
	if ipEndpointStats, ok := r.outgoingNIC.getNetworkEndpoint(proto).Stats().(IPNetworkEndpointStats); ok {
		ipEndpointStats.IPStats().OutgoingPacketErrors.IncrementBy(n)
	}
}

func (f *packetsPendingLinkResolution) enqueue(ch <-chan struct{}, r *Route, proto tcpip.NetworkProtocolNumber, pkt pendingPacketBuffer) {
	f.Lock()
	defer f.Unlock()

	packets, ok := f.packets[ch]
	if len(packets) == maxPendingPacketsPerResolution {
		p := packets[0]
		packets[0] = pendingPacket{}
		packets = packets[1:]

		incrementOutgoingPacketErrors(r, proto, p.pkt)

		p.route.Release()
	}

	if l := len(packets); l >= maxPendingPacketsPerResolution {
		panic(fmt.Sprintf("max pending packets for resolution reached; got %d packets, max = %d", l, maxPendingPacketsPerResolution))
	}

	f.packets[ch] = append(packets, pendingPacket{
		route: r,
		proto: proto,
		pkt:   pkt,
	})

	if ok {
		return
	}

	// Wait for the link-address resolution to complete.
	cancel := f.newCancelChannelLocked()
	go func() {
		cancelled := false
		select {
		case <-ch:
		case <-cancel:
			cancelled = true
		}

		f.Lock()
		packets, ok := f.packets[ch]
		delete(f.packets, ch)
		f.Unlock()

		if !ok {
			panic(fmt.Sprintf("link-resolution goroutine woke up but no entry exists in the queue of packets"))
		}

		for _, p := range packets {
			if cancelled || p.route.IsResolutionRequired() {
				incrementOutgoingPacketErrors(r, proto, p.pkt)

				if linkResolvableEP, ok := p.route.outgoingNIC.getNetworkEndpoint(p.route.NetProto).(LinkResolvableNetworkEndpoint); ok {
					switch pkt := p.pkt.(type) {
					case *PacketBuffer:
						linkResolvableEP.HandleLinkResolutionFailure(pkt)
					case *PacketBufferList:
						for pb := pkt.Front(); pb != nil; pb = pb.Next() {
							linkResolvableEP.HandleLinkResolutionFailure(pb)
						}
					default:
						panic(fmt.Sprintf("unrecognized pending packet buffer type = %T", p.pkt))
					}
				}
			} else {
				switch pkt := p.pkt.(type) {
				case *PacketBuffer:
					p.route.outgoingNIC.writePacket(p.route.Fields(), nil /* gso */, p.proto, pkt)
				case *PacketBufferList:
					p.route.outgoingNIC.writePackets(p.route.Fields(), nil /* gso */, p.proto, *pkt)
				default:
					panic(fmt.Sprintf("unrecognized pending packet buffer type = %T", p.pkt))
				}
			}
			p.route.Release()
		}
	}()
}

// newCancelChannel creates a channel that can cancel a pending forwarding
// activity. The oldest channel is closed if the number of open channels would
// exceed maxPendingResolutions.
func (f *packetsPendingLinkResolution) newCancelChannelLocked() chan struct{} {
	if len(f.cancelChans) == maxPendingResolutions {
		ch := f.cancelChans[0]
		f.cancelChans[0] = nil
		f.cancelChans = f.cancelChans[1:]
		close(ch)
	}
	if l := len(f.cancelChans); l >= maxPendingResolutions {
		panic(fmt.Sprintf("max pending resolutions reached; got %d active resolutions, max = %d", l, maxPendingResolutions))
	}

	ch := make(chan struct{})
	f.cancelChans = append(f.cancelChans, ch)
	return ch
}
