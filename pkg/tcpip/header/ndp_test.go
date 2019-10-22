// Copyright 2019 The gVisor Authors.
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

package header

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// TestNDPNeighborSolicit tests the functions of NDPNeighborSolicit.
func TestNDPNeighborSolicit(t *testing.T) {
	b := []byte{
		0, 0, 0, 0,
		1, 2, 3, 4,
		5, 6, 7, 8,
		9, 10, 11, 12,
		13, 14, 15, 16,
	}

	// Test getting the Target Address.
	ns := NDPNeighborSolicit(b)
	addr := tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
	if got := ns.TargetAddress(); got != addr {
		t.Fatalf("got ns.TargetAddress = %s, want %s", got, addr)
	}

	// Test updating the Target Address.
	addr2 := tcpip.Address("\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x11")
	ns.SetTargetAddress(addr2)
	if got := ns.TargetAddress(); got != addr2 {
		t.Fatalf("got ns.TargetAddress = %s, want %s", got, addr2)
	}
	// Make sure the address got updated in the backing buffer.
	if got := tcpip.Address(b[ndpNSTargetAddessOffset:][:IPv6AddressSize]); got != addr2 {
		t.Fatalf("got targetaddress buffer = %s, want %s", got, addr2)
	}
}

// TestNDPNeighborAdvert tests the functions of NDPNeighborAdvert.
func TestNDPNeighborAdvert(t *testing.T) {
	b := []byte{
		160, 0, 0, 0,
		1, 2, 3, 4,
		5, 6, 7, 8,
		9, 10, 11, 12,
		13, 14, 15, 16,
	}

	// Test getting the Target Address.
	na := NDPNeighborAdvert(b)
	addr := tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
	if got := na.TargetAddress(); got != addr {
		t.Fatalf("got TargetAddress = %s, want %s", got, addr)
	}

	// Test getting the Router Flag.
	if got := na.RouterFlag(); !got {
		t.Fatalf("got RouterFlag = false, want = true")
	}

	// Test getting the Solicited Flag.
	if got := na.SolicitedFlag(); got {
		t.Fatalf("got SolicitedFlag = true, want = false")
	}

	// Test getting the Override Flag.
	if got := na.OverrideFlag(); !got {
		t.Fatalf("got OverrideFlag = false, want = true")
	}

	// Test updating the Target Address.
	addr2 := tcpip.Address("\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x11")
	na.SetTargetAddress(addr2)
	if got := na.TargetAddress(); got != addr2 {
		t.Fatalf("got TargetAddress = %s, want %s", got, addr2)
	}
	// Make sure the address got updated in the backing buffer.
	if got := tcpip.Address(b[ndpNATargetAddressOffset:][:IPv6AddressSize]); got != addr2 {
		t.Fatalf("got targetaddress buffer = %s, want %s", got, addr2)
	}

	// Test updating the Router Flag.
	na.SetRouterFlag(false)
	if got := na.RouterFlag(); got {
		t.Fatalf("got RouterFlag = true, want = false")
	}

	// Test updating the Solicited Flag.
	na.SetSolicitedFlag(true)
	if got := na.SolicitedFlag(); !got {
		t.Fatalf("got SolicitedFlag = false, want = true")
	}

	// Test updating the Override Flag.
	na.SetOverrideFlag(false)
	if got := na.OverrideFlag(); got {
		t.Fatalf("got OverrideFlag = true, want = false")
	}

	// Make sure flags got updated in the backing buffer.
	if got := b[ndpNAFlagsOffset]; got != 64 {
		t.Fatalf("got flags byte = %d, want = 64")
	}
}

func TestNDPRouterAdvert(t *testing.T) {
	b := []byte{
		64, 128, 1, 2,
		3, 4, 5, 6,
		7, 8, 9, 10,
	}

	ra := NDPRouterAdvert(b)

	if got := ra.CurrHopLimit(); got != 64 {
		t.Fatalf("got ra.CurrHopLimit = %d, want = 64", got)
	}

	if got := ra.ManagedAddrConfFlag(); !got {
		t.Fatalf("got ManagedAddrConfFlag = false, want = true")
	}

	if got := ra.OtherConfFlag(); got {
		t.Fatalf("got OtherConfFlag = true, want = false")
	}

	if got, want := ra.RouterLifetime(), time.Second*258; got != want {
		t.Fatalf("got ra.RouterLifetime = %d, want = %d", got, want)
	}

	if got, want := ra.ReachableTime(), time.Millisecond*50595078; got != want {
		t.Fatalf("got ra.ReachableTime = %d, want = %d", got, want)
	}

	if got, want := ra.RetransTimer(), time.Millisecond*117967114; got != want {
		t.Fatalf("got ra.RetransTimer = %d, want = %d", got, want)
	}
}

// TestNDPTargetLinkLayerAddressOptionSerialize tests serializing a
// NDPTargetLinkLayerAddressOption.
func TestNDPTargetLinkLayerAddressOptionSerialize(t *testing.T) {
	tests := []struct {
		name        string
		buf         []byte
		expectedBuf []byte
		addr        tcpip.LinkAddress
	}{
		{
			"Ethernet",
			make([]byte, 8),
			[]byte{2, 1, 1, 2, 3, 4, 5, 6},
			"\x01\x02\x03\x04\x05\x06",
		},
		{
			"Padding",
			[]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			[]byte{2, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0},
			"\x01\x02\x03\x04\x05\x06\x07\x08",
		},
		{
			"Empty",
			[]byte{},
			[]byte{},
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := NDPOptions(test.buf)
			serializer := NDPOptionsSerializer{
				NDPTargetLinkLayerAddressOption(test.addr),
			}
			if got, want := int(serializer.Length()), len(test.expectedBuf); got != want {
				t.Fatalf("got Length = %d, want = %d", got, want)
			}
			opts.Serialize(serializer)
			if !bytes.Equal(test.buf, test.expectedBuf) {
				t.Fatalf("got b = %d, want = %d", test.buf, test.expectedBuf)
			}
		})
	}
}
