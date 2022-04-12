// Copyright 2022 The gVisor Authors.
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

package multicast_test

import (
	"fmt"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/multicast"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

// Example shows how to interact with a multicast RouteTable.
func Example() {
	address := testutil.MustParse4("192.168.1.1")
	routeKey := multicast.RouteKey{UnicastSource: address, MulticastDestination: address}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()

	// Create a route table from a specified config.
	table := multicast.RouteTable{}
	config := multicast.DefaultConfig(faketime.NewManualClock())

	if err := table.Init(config); err != nil {
		panic(err)
	}

	// Each entry in the table represents either an installed route or a pending
	// route. To insert a pending route, call:
	result, err := table.GetRouteOrInsertPending(routeKey, pkt)

	// Callers should handle a no buffer space error (e.g. only deliver the
	// packet locally).
	if err == multicast.ErrNoBufferSpace {
		deliverPktLocally(pkt)
	}

	if err != nil {
		panic(err)
	}

	// Callers should handle the various pending route states.
	switch result.PendingRouteState {
	case multicast.PendingRouteStateNone:
		// The packet can be forwarded using the installed route.
		forwardPkt(pkt, result.InstalledRoute)
	case multicast.PendingRouteStateInstalled:
		// The route has just entered the pending state.
		emitMissingRouteEvent(routeKey)
		deliverPktLocally(pkt)
	case multicast.PendingRouteStateAppended:
		// The route was already in the pending state.
		deliverPktLocally(pkt)
	}

	// Output:
	// emitMissingRouteEvent
	// deliverPktLocally
}

func forwardPkt(stack.PacketBufferPtr, *multicast.InstalledRoute) {}

func emitMissingRouteEvent(multicast.RouteKey) {
	fmt.Println("emitMissingRouteEvent")
}

func deliverPktLocally(stack.PacketBufferPtr) {
	fmt.Println("deliverPktLocally")
}

func newPacketBuffer(body string) stack.PacketBufferPtr {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.View(body).ToVectorisedView(),
	})
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refsvfs2.DoLeakCheck()
	os.Exit(code)
}
