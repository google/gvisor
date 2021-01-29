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
	routeInfo RouteInfo
	gso       *GSO
	proto     tcpip.NetworkProtocolNumber
	pkt       pendingPacketBuffer
}

// packetsPendingLinkResolution is a queue of packets pending link resolution.
//
// Once link resolution completes successfully, the packets will be written.
type packetsPendingLinkResolution struct {
	nic *NIC

	mu struct {
		sync.Mutex

		// The packets to send once the resolver completes.
		//
		// The link resolution channel is used as the key for this map.
		packets map[<-chan struct{}][]pendingPacket

		// FIFO of channels used to cancel the oldest goroutine waiting for
		// link-address resolution.
		//
		// cancelChans holds the same channels that are used as keys to packets.
		cancelChans []<-chan struct{}
	}
}

func (f *packetsPendingLinkResolution) incrementOutgoingPacketErrors(proto tcpip.NetworkProtocolNumber, pkt pendingPacketBuffer) {
	n := uint64(pkt.len())
	f.nic.stack.stats.IP.OutgoingPacketErrors.IncrementBy(n)

	if ipEndpointStats, ok := f.nic.getNetworkEndpoint(proto).Stats().(IPNetworkEndpointStats); ok {
		ipEndpointStats.IPStats().OutgoingPacketErrors.IncrementBy(n)
	}
}

func (f *packetsPendingLinkResolution) init(nic *NIC) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nic = nic
	f.mu.packets = make(map[<-chan struct{}][]pendingPacket)
}

// dequeue any pending packets associated with ch.
//
// If success is true, packets will be written and sent to the given remote link
// address.
func (f *packetsPendingLinkResolution) dequeue(ch <-chan struct{}, linkAddr tcpip.LinkAddress, success bool) {
	f.mu.Lock()
	packets, ok := f.mu.packets[ch]
	delete(f.mu.packets, ch)

	if ok {
		for i, cancelChan := range f.mu.cancelChans {
			if cancelChan == ch {
				f.mu.cancelChans = append(f.mu.cancelChans[:i], f.mu.cancelChans[i+1:]...)
				break
			}
		}
	}

	f.mu.Unlock()

	if ok {
		f.dequeuePackets(packets, linkAddr, success)
	}
}

func (f *packetsPendingLinkResolution) writePacketBuffer(r RouteInfo, gso *GSO, proto tcpip.NetworkProtocolNumber, pkt pendingPacketBuffer) (int, tcpip.Error) {
	switch pkt := pkt.(type) {
	case *PacketBuffer:
		if err := f.nic.writePacket(r, gso, proto, pkt); err != nil {
			return 0, err
		}
		return 1, nil
	case *PacketBufferList:
		return f.nic.writePackets(r, gso, proto, *pkt)
	default:
		panic(fmt.Sprintf("unrecognized pending packet buffer type = %T", pkt))
	}
}

// enqueue a packet to be sent once link resolution completes.
//
// If the maximum number of pending resolutions is reached, the packets
// associated with the oldest link resolution will be dequeued as if they failed
// link resolution.
func (f *packetsPendingLinkResolution) enqueue(r *Route, gso *GSO, proto tcpip.NetworkProtocolNumber, pkt pendingPacketBuffer) (int, tcpip.Error) {
	f.mu.Lock()
	// Make sure we attempt resolution while holding f's lock so that we avoid
	// a race where link resolution completes before we enqueue the packets.
	//
	//   A @ T1: Call ResolvedFields (get link resolution channel)
	//   B @ T2: Complete link resolution, dequeue pending packets
	//   C @ T1: Enqueue packet that already completed link resolution (which will
	//       never dequeue)
	//
	// To make sure B does not interleave with A and C, we make sure A and C are
	// done while holding the lock.
	routeInfo, ch, err := r.resolvedFields(nil)
	switch err.(type) {
	case nil:
		// The route resolved immediately, so we don't need to wait for link
		// resolution to send the packet.
		f.mu.Unlock()
		return f.writePacketBuffer(routeInfo, gso, proto, pkt)
	case *tcpip.ErrWouldBlock:
		// We need to wait for link resolution to complete.
	default:
		f.mu.Unlock()
		return 0, err
	}

	defer f.mu.Unlock()

	packets, ok := f.mu.packets[ch]
	packets = append(packets, pendingPacket{
		routeInfo: routeInfo,
		gso:       gso,
		proto:     proto,
		pkt:       pkt,
	})

	if len(packets) > maxPendingPacketsPerResolution {
		f.incrementOutgoingPacketErrors(packets[0].proto, packets[0].pkt)
		packets[0] = pendingPacket{}
		packets = packets[1:]

		if numPackets := len(packets); numPackets != maxPendingPacketsPerResolution {
			panic(fmt.Sprintf("holding more queued packets than expected; got = %d, want <= %d", numPackets, maxPendingPacketsPerResolution))
		}
	}

	f.mu.packets[ch] = packets

	if ok {
		return pkt.len(), nil
	}

	cancelledPackets := f.newCancelChannelLocked(ch)

	if len(cancelledPackets) != 0 {
		// Dequeue the pending packets in a new goroutine to not hold up the current
		// goroutine as handing link resolution failures may be a costly operation.
		go f.dequeuePackets(cancelledPackets, "" /* linkAddr */, false /* success */)
	}

	return pkt.len(), nil
}

// newCancelChannelLocked appends the link resolution channel to a FIFO. If the
// maximum number of pending resolutions is reached, the oldest channel will be
// removed and its associated pending packets will be returned.
func (f *packetsPendingLinkResolution) newCancelChannelLocked(newCH <-chan struct{}) []pendingPacket {
	f.mu.cancelChans = append(f.mu.cancelChans, newCH)
	if len(f.mu.cancelChans) <= maxPendingResolutions {
		return nil
	}

	ch := f.mu.cancelChans[0]
	f.mu.cancelChans[0] = nil
	f.mu.cancelChans = f.mu.cancelChans[1:]
	if l := len(f.mu.cancelChans); l > maxPendingResolutions {
		panic(fmt.Sprintf("max pending resolutions reached; got %d active resolutions, max = %d", l, maxPendingResolutions))
	}

	packets, ok := f.mu.packets[ch]
	if !ok {
		panic("must have a packet queue for an uncancelled channel")
	}
	delete(f.mu.packets, ch)

	return packets
}

func (f *packetsPendingLinkResolution) dequeuePackets(packets []pendingPacket, linkAddr tcpip.LinkAddress, success bool) {
	for _, p := range packets {
		if success {
			p.routeInfo.RemoteLinkAddress = linkAddr
			_, _ = f.writePacketBuffer(p.routeInfo, p.gso, p.proto, p.pkt)
		} else {
			f.incrementOutgoingPacketErrors(p.proto, p.pkt)

			if linkResolvableEP, ok := f.nic.getNetworkEndpoint(p.proto).(LinkResolvableNetworkEndpoint); ok {
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
		}
	}
}
