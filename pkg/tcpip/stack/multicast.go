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

package stack

import "gvisor.dev/gvisor/pkg/tcpip"

// UnicastSourceAndMulticastDestination is a tuple that represents a unicast
// source address and a multicast destination address.
type UnicastSourceAndMulticastDestination struct {
	// Source represents a unicast source address.
	Source tcpip.Address
	// Destination represents a multicast destination address.
	Destination tcpip.Address
}

// MulticastRoutingEventContext represents the context that resulted in a
// multicast routing event getting emitted.
type MulticastRoutingEventContext struct {
	// SourceAndDestination represents the unicast source address and the
	// multicast destination address found in the relevant multicast packet.
	SourceAndDestination UnicastSourceAndMulticastDestination
	// InputInterface is the interface that the relevant multicast packet arrived
	// at.
	InputInterface tcpip.NICID
}

// MulticastRoutingEventDispatcher is the interface that integrators should
// implement to receive and handle multicast routing events.
type MulticastRoutingEventDispatcher interface {
	// OnMissingRoute is called when an incoming multicast packet does match any
	// installed route and no other packets are queued for the relevant route.
	//
	// The packet that triggered this event may be queued so that it can be
	// transmitted once a route is installed. Note that the packet may still be
	// dropped as per the routing table's GC/eviction policy.
	OnMissingRoute(context MulticastRoutingEventContext)

	// OnUnexpectedInputInterface is called when a multicast packet arrives at an
	// interface that differs from what the relevant route expected.
	//
	// This may be an indication of a routing loop. The packet that triggered
	// this event will be dropped without being forwarded.
	OnUnexpectedInputInterface(context MulticastRoutingEventContext, expectedInputInterface tcpip.NICID)
}
