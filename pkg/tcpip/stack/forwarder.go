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
	nic   *NIC
	route *Route
	proto tcpip.NetworkProtocolNumber
	pkt   *PacketBuffer
}

type forwardQueue struct {
	sync.Mutex

	// The packets to send once the resolver completes.
	packets map[<-chan struct{}][]*pendingPacket

	// FIFO of channels used to cancel the oldest goroutine waiting for
	// link-address resolution.
	cancelChans []chan struct{}
}

func newForwardQueue() *forwardQueue {
	return &forwardQueue{packets: make(map[<-chan struct{}][]*pendingPacket)}
}

func (f *forwardQueue) enqueue(ch <-chan struct{}, n *NIC, r *Route, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	shouldWait := false

	f.Lock()
	packets, ok := f.packets[ch]
	if !ok {
		shouldWait = true
	}
	for len(packets) == maxPendingPacketsPerResolution {
		p := packets[0]
		packets = packets[1:]
		p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
		p.route.Release()
	}
	if l := len(packets); l >= maxPendingPacketsPerResolution {
		panic(fmt.Sprintf("max pending packets for resolution reached; got %d packets, max = %d", l, maxPendingPacketsPerResolution))
	}
	f.packets[ch] = append(packets, &pendingPacket{
		nic:   n,
		route: r,
		proto: protocol,
		pkt:   pkt,
	})
	f.Unlock()

	if !shouldWait {
		return
	}

	// Wait for the link-address resolution to complete.
	// Start a goroutine with a forwarding-cancel channel so that we can
	// limit the maximum number of goroutines running concurrently.
	cancel := f.newCancelChannel()
	go func() {
		cancelled := false
		select {
		case <-ch:
		case <-cancel:
			cancelled = true
		}

		f.Lock()
		packets := f.packets[ch]
		delete(f.packets, ch)
		f.Unlock()

		for _, p := range packets {
			if cancelled {
				p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
			} else if _, err := p.route.Resolve(nil); err != nil {
				p.nic.stack.stats.IP.OutgoingPacketErrors.Increment()
			} else {
				p.nic.forwardPacket(p.route, p.proto, p.pkt)
			}
			p.route.Release()
		}
	}()
}

// newCancelChannel creates a channel that can cancel a pending forwarding
// activity. The oldest channel is closed if the number of open channels would
// exceed maxPendingResolutions.
func (f *forwardQueue) newCancelChannel() chan struct{} {
	f.Lock()
	defer f.Unlock()

	if len(f.cancelChans) == maxPendingResolutions {
		ch := f.cancelChans[0]
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
