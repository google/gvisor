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
	"time"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/multicast"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	defaultMinTTL             = 10
	defaultMTU                = 1500
	inputNICID    tcpip.NICID = 1
	outgoingNICID tcpip.NICID = 2
)

// Example shows how to interact with a multicast RouteTable.
func Example() {
	address := testutil.MustParse4("192.168.1.1")
	defaultOutgoingInterfaces := []stack.MulticastRouteOutgoingInterface{{ID: outgoingNICID, MinTTL: defaultMinTTL}}
	routeKey := stack.UnicastSourceAndMulticastDestination{Source: address, Destination: address}
	multicastRoute := stack.MulticastRoute{inputNICID, defaultOutgoingInterfaces}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()

	clock := faketime.NewManualClock()
	clock.Advance(10 * time.Second)

	// Create a route table from a specified config.
	table := multicast.RouteTable{}
	defer table.Close()
	config := multicast.DefaultConfig(clock)

	if err := table.Init(config); err != nil {
		panic(err)
	}

	// Each entry in the table represents either an installed route or a pending
	// route. To insert a pending route, call:
	result, hasBufferSpace := table.GetRouteOrInsertPending(routeKey, pkt)

	// Callers should handle a no buffer space error (e.g. only deliver the
	// packet locally).
	if !hasBufferSpace {
		deliverPktLocally(pkt)
	}

	// Callers should handle the various pending route states.
	switch result.GetRouteResultState {
	case multicast.InstalledRouteFound:
		// The packet can be forwarded using the installed route.
		forwardPkt(pkt, result.InstalledRoute)
	case multicast.NoRouteFoundAndPendingInserted:
		// The route has just entered the pending state.
		emitMissingRouteEvent(routeKey)
		deliverPktLocally(pkt)
	case multicast.PacketQueuedInPendingRoute:
		// The route was already in the pending state.
		deliverPktLocally(pkt)
	}

	// To transition a pending route to the installed state, call:
	route := table.NewInstalledRoute(multicastRoute)
	pendingPackets := table.AddInstalledRoute(routeKey, route)

	// If there was a pending route, then the caller is responsible for
	// flushing any pending packets.
	for _, pkt := range pendingPackets {
		forwardPkt(pkt, route)
		pkt.DecRef()
	}

	// To obtain the last used time of the route, call:
	timestamp, found := table.GetLastUsedTimestamp(routeKey)

	if !found {
		panic(fmt.Sprintf("table.GetLastUsedTimestamp(%#v) = (_, false)", routeKey))
	}

	fmt.Printf("Last used timestamp: %s", timestamp)

	// Finally, to remove an installed route, call:
	if removed := table.RemoveInstalledRoute(routeKey); !removed {
		panic(fmt.Sprintf("table.RemoveInstalledRoute(%#v) = false", routeKey))
	}

	// Output:
	// emitMissingRouteEvent
	// deliverPktLocally
	// forwardPkt
	// Last used timestamp: 10000000000
}

func forwardPkt(stack.PacketBufferPtr, *multicast.InstalledRoute) {
	fmt.Println("forwardPkt")
}

func emitMissingRouteEvent(stack.UnicastSourceAndMulticastDestination) {
	fmt.Println("emitMissingRouteEvent")
}

func deliverPktLocally(stack.PacketBufferPtr) {
	fmt.Println("deliverPktLocally")
}

func newPacketBuffer(body string) stack.PacketBufferPtr {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData([]byte(body)),
	})
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
