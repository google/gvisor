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
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// MockLinkEndpoint is an endpoint used for testing, it stores packets written
// to it and can mock errors.
type MockLinkEndpoint struct {
	// WrittenPackets is where packets written to the endpoint are stored.
	WrittenPackets []*stack.PacketBuffer

	mtu          uint32
	err          tcpip.Error
	allowPackets int
}

// NewMockLinkEndpoint creates a new MockLinkEndpoint.
//
// err is the error that will be returned once allowPackets packets are written
// to the endpoint.
func NewMockLinkEndpoint(mtu uint32, err tcpip.Error, allowPackets int) *MockLinkEndpoint {
	return &MockLinkEndpoint{
		mtu:          mtu,
		err:          err,
		allowPackets: allowPackets,
	}
}

// MTU implements LinkEndpoint.MTU.
func (ep *MockLinkEndpoint) MTU() uint32 { return ep.mtu }

// Capabilities implements LinkEndpoint.Capabilities.
func (*MockLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }

// MaxHeaderLength implements LinkEndpoint.MaxHeaderLength.
func (*MockLinkEndpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements LinkEndpoint.LinkAddress.
func (*MockLinkEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

// WritePacket implements LinkEndpoint.WritePacket.
func (ep *MockLinkEndpoint) WritePacket(_ stack.RouteInfo, _ stack.GSO, _ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) tcpip.Error {
	if ep.allowPackets == 0 {
		return ep.err
	}
	ep.allowPackets--
	ep.WrittenPackets = append(ep.WrittenPackets, pkt)
	return nil
}

// WritePackets implements LinkEndpoint.WritePackets.
func (ep *MockLinkEndpoint) WritePackets(r stack.RouteInfo, gso stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	var n int

	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		if err := ep.WritePacket(r, gso, protocol, pkt); err != nil {
			return n, err
		}
		n++
	}

	return n, nil
}

// Attach implements LinkEndpoint.Attach.
func (*MockLinkEndpoint) Attach(stack.NetworkDispatcher) {}

// IsAttached implements LinkEndpoint.IsAttached.
func (*MockLinkEndpoint) IsAttached() bool { return false }

// Wait implements LinkEndpoint.Wait.
func (*MockLinkEndpoint) Wait() {}

// ARPHardwareType implements LinkEndpoint.ARPHardwareType.
func (*MockLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader implements LinkEndpoint.AddHeader.
func (*MockLinkEndpoint) AddHeader(_, _ tcpip.LinkAddress, _ tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
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

func checkFieldCounts(ref, multi reflect.Value) error {
	refTypeName := ref.Type().Name()
	multiTypeName := multi.Type().Name()
	refNumField := ref.NumField()
	multiNumField := multi.NumField()

	if refNumField != multiNumField {
		return fmt.Errorf("type %s has an incorrect number of fields: got = %d, want = %d (same as type %s)", multiTypeName, multiNumField, refNumField, refTypeName)
	}

	return nil
}

func validateField(ref reflect.Value, refName string, m tcpip.MultiCounterStat, multiName string) error {
	s, ok := ref.Addr().Interface().(**tcpip.StatCounter)
	if !ok {
		return fmt.Errorf("expected ref type's to be *StatCounter, but its type is %s", ref.Type().Elem().Name())
	}

	// The field names are expected to match (case insensitive).
	if !strings.EqualFold(refName, multiName) {
		return fmt.Errorf("wrong field name: got = %s, want = %s", multiName, refName)
	}

	base := (*s).Value()
	m.Increment()
	if (*s).Value() != base+1 {
		return fmt.Errorf("updates to the '%s MultiCounterStat' counters are not reflected in the '%s CounterStat'", multiName, refName)
	}

	return nil
}

// ValidateMultiCounterStats verifies that every counter stored in multi is
// correctly tracking its counterpart in the given counters.
func ValidateMultiCounterStats(multi reflect.Value, counters []reflect.Value) error {
	for _, c := range counters {
		if err := checkFieldCounts(c, multi); err != nil {
			return err
		}
	}

	for i := 0; i < multi.NumField(); i++ {
		multiName := multi.Type().Field(i).Name
		multiUnsafe := unsafeExposeUnexportedFields(multi.Field(i))

		if m, ok := multiUnsafe.Addr().Interface().(*tcpip.MultiCounterStat); ok {
			for _, c := range counters {
				if err := validateField(unsafeExposeUnexportedFields(c.Field(i)), c.Type().Field(i).Name, *m, multiName); err != nil {
					return err
				}
			}
		} else {
			var countersNextField []reflect.Value
			for _, c := range counters {
				countersNextField = append(countersNextField, c.Field(i))
			}
			if err := ValidateMultiCounterStats(multi.Field(i), countersNextField); err != nil {
				return err
			}
		}
	}

	return nil
}
