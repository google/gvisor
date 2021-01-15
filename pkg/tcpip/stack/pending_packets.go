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

type pendingPacket struct {
	nic       *NIC
	routeInfo RouteInfo
	proto     tcpip.NetworkProtocolNumber
	pkt       *PacketBuffer
}

// packetsPendingLinkResolution is a queue of packets pending link resolution.
//
// Once link resolution completes successfully, the packets will be written.
type packetsPendingLinkResolution struct {
	sync.Mutex

	// The packets to send once the resolver completes.
	//
	// The channel used as the key for the map is the channel that becomes
	// readable once link resolution completes.
	packets map[<-chan struct{}][]pendingPacket

	// FIFO of channels used to cancel the oldest goroutine waiting for
	// link-address resolution.
	//
	// cancelChans holds the same channels that are used as keys to packets,
	// ordered by when the first packet was enqueued.
	cancelChans []<-chan struct{}
}

func (f *packetsPendingLinkResolution) init() {
	f.Lock()
	defer f.Unlock()
	f.packets = make(map[<-chan struct{}][]pendingPacket)
}

// dequeue dequeues any pending packets associated with the given link
// resolution channel.
//
// If link resolution successful, packets will be written and sent to the
// given remote link address.
//
// dequeue will send the packets on a new goroutine.
func (f *packetsPendingLinkResolution) dequeue(ch <-chan struct{}, linkAddr tcpip.LinkAddress, success bool) {
	f.Lock()
	packets, ok := f.packets[ch]
	delete(f.packets, ch)
	f.Unlock()

	if !ok {
		return
	}

	go dequeuePackets(packets, linkAddr, success)
}

func (f *packetsPendingLinkResolution) enqueue(ch <-chan struct{}, n *NIC, r RouteInfo, proto tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	f.Lock()

	packets, ok := f.packets[ch]
	if len(packets) == maxPendingPacketsPerResolution {
		p := packets[0]
		packets[0] = pendingPacket{}
		packets = packets[1:]
		p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
	}

	if l := len(packets); l >= maxPendingPacketsPerResolution {
		f.Unlock()
		panic(fmt.Sprintf("max pending packets for resolution reached; got %d packets, max = %d", l, maxPendingPacketsPerResolution))
	}

	f.packets[ch] = append(packets, pendingPacket{
		nic:       n,
		routeInfo: r,
		proto:     proto,
		pkt:       pkt,
	})

	if ok {
		f.Unlock()
		return
	}

	cancelledPackets := f.newCancelChannelLocked(ch)
	f.Unlock()

	if len(cancelledPackets) != 0 {
		// Dequeue the packets in a different goroutine to not unnecessarily hold
		// any locks for longer than they need to be.
		go dequeuePackets(cancelledPackets, "", false)
	}
}

// newCancelChannelLocked appends the resolution channel to the list of
// channels. If the max number of pending resolutions is reached, the oldest
// channel will be removed and its associated pending packets will be returned.
func (f *packetsPendingLinkResolution) newCancelChannelLocked(newCH <-chan struct{}) []pendingPacket {
	f.cancelChans = append(f.cancelChans, newCH)
	if len(f.cancelChans) <= maxPendingResolutions {
		return nil
	}

	ch := f.cancelChans[0]
	f.cancelChans[0] = nil
	f.cancelChans = f.cancelChans[1:]
	if l := len(f.cancelChans); l > maxPendingResolutions {
		panic(fmt.Sprintf("max pending resolutions reached; got %d active resolutions, max = %d", l, maxPendingResolutions))
	}

	packets, ok := f.packets[ch]
	if !ok {
		panic("must have a packet queue for an uncancelled channel")
	}
	delete(f.packets, ch)

	return packets
}

func dequeuePackets(packets []pendingPacket, linkAddr tcpip.LinkAddress, success bool) {
	for _, p := range packets {
		if !success {
			p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()

			if linkResolvableEP, ok := p.nic.getNetworkEndpoint(p.routeInfo.NetProto).(LinkResolvableNetworkEndpoint); ok {
				linkResolvableEP.HandleLinkResolutionFailure(p.pkt)
			}
		} else {
			p.routeInfo.RemoteLinkAddress = linkAddr
			p.nic.writePacket(p.routeInfo, nil /* gso */, p.proto, p.pkt)
		}
	}
}
