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

// Package testutil defines types and functions used to test Network Layer
// functionality such as IP fragmentation.
package testutil

import (
	"fmt"
	"math/rand"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestEndpoint is an endpoint used for testing, it stores packets written to it
// and can mock errors.
type TestEndpoint struct {
	*channel.Endpoint

	// WrittenPackets is where we store packets written via WritePacket().
	WrittenPackets []*stack.PacketBuffer

	packetCollectorErrors []*tcpip.Error
}

// NewTestEndpoint creates a new TestEndpoint endpoint.
//
// packetCollectorErrors can be used to set error values and each call to
// WritePacket will remove the first one from the slice and return it until
// the slice is empty - at that point it will return nil every time.
func NewTestEndpoint(ep *channel.Endpoint, packetCollectorErrors []*tcpip.Error) *TestEndpoint {
	return &TestEndpoint{
		Endpoint:              ep,
		WrittenPackets:        make([]*stack.PacketBuffer, 0),
		packetCollectorErrors: packetCollectorErrors,
	}
}

// WritePacket stores outbound packets and may return an error if one was
// injected.
func (e *TestEndpoint) WritePacket(_ *stack.Route, _ *stack.GSO, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) *tcpip.Error {
	e.WrittenPackets = append(e.WrittenPackets, pkt)

	if len(e.packetCollectorErrors) > 0 {
		nextError := e.packetCollectorErrors[0]
		e.packetCollectorErrors = e.packetCollectorErrors[1:]
		return nextError
	}

	return nil
}

// MakeRandPkt generates a randomized packet. transportHeaderLength indicates
// how many random bytes will be copied in the Transport Header.
// extraHeaderReserveLength indicates how much extra space will be reserved for
// the other headers. The payload is made from Views of the sizes listed in
// viewSizes.
func MakeRandPkt(transportHeaderLength int, extraHeaderReserveLength int, viewSizes []int, proto tcpip.NetworkProtocolNumber) *stack.PacketBuffer {
	var views buffer.VectorisedView

	for _, s := range viewSizes {
		newView := buffer.NewView(s)
		if _, err := rand.Read(newView); err != nil {
			panic(fmt.Sprintf("rand.Read: %s", err))
		}
		views.AppendView(newView)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: transportHeaderLength + extraHeaderReserveLength,
		Data:               views,
	})
	pkt.NetworkProtocolNumber = proto
	if _, err := rand.Read(pkt.TransportHeader().Push(transportHeaderLength)); err != nil {
		panic(fmt.Sprintf("rand.Read: %s", err))
	}
	return pkt
}
