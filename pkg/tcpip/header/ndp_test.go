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

	"github.com/google/go-cmp/cmp"
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
		t.Errorf("got ns.TargetAddress = %s, want %s", got, addr)
	}

	// Test updating the Target Address.
	addr2 := tcpip.Address("\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x11")
	ns.SetTargetAddress(addr2)
	if got := ns.TargetAddress(); got != addr2 {
		t.Errorf("got ns.TargetAddress = %s, want %s", got, addr2)
	}
	// Make sure the address got updated in the backing buffer.
	if got := tcpip.Address(b[ndpNSTargetAddessOffset:][:IPv6AddressSize]); got != addr2 {
		t.Errorf("got targetaddress buffer = %s, want %s", got, addr2)
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
		t.Errorf("got TargetAddress = %s, want %s", got, addr)
	}

	// Test getting the Router Flag.
	if got := na.RouterFlag(); !got {
		t.Errorf("got RouterFlag = false, want = true")
	}

	// Test getting the Solicited Flag.
	if got := na.SolicitedFlag(); got {
		t.Errorf("got SolicitedFlag = true, want = false")
	}

	// Test getting the Override Flag.
	if got := na.OverrideFlag(); !got {
		t.Errorf("got OverrideFlag = false, want = true")
	}

	// Test updating the Target Address.
	addr2 := tcpip.Address("\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x11")
	na.SetTargetAddress(addr2)
	if got := na.TargetAddress(); got != addr2 {
		t.Errorf("got TargetAddress = %s, want %s", got, addr2)
	}
	// Make sure the address got updated in the backing buffer.
	if got := tcpip.Address(b[ndpNATargetAddressOffset:][:IPv6AddressSize]); got != addr2 {
		t.Errorf("got targetaddress buffer = %s, want %s", got, addr2)
	}

	// Test updating the Router Flag.
	na.SetRouterFlag(false)
	if got := na.RouterFlag(); got {
		t.Errorf("got RouterFlag = true, want = false")
	}

	// Test updating the Solicited Flag.
	na.SetSolicitedFlag(true)
	if got := na.SolicitedFlag(); !got {
		t.Errorf("got SolicitedFlag = false, want = true")
	}

	// Test updating the Override Flag.
	na.SetOverrideFlag(false)
	if got := na.OverrideFlag(); got {
		t.Errorf("got OverrideFlag = true, want = false")
	}

	// Make sure flags got updated in the backing buffer.
	if got := b[ndpNAFlagsOffset]; got != 64 {
		t.Errorf("got flags byte = %d, want = 64")
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
		t.Errorf("got ra.CurrHopLimit = %d, want = 64", got)
	}

	if got := ra.ManagedAddrConfFlag(); !got {
		t.Errorf("got ManagedAddrConfFlag = false, want = true")
	}

	if got := ra.OtherConfFlag(); got {
		t.Errorf("got OtherConfFlag = true, want = false")
	}

	if got, want := ra.RouterLifetime(), time.Second*258; got != want {
		t.Errorf("got ra.RouterLifetime = %d, want = %d", got, want)
	}

	if got, want := ra.ReachableTime(), time.Millisecond*50595078; got != want {
		t.Errorf("got ra.ReachableTime = %d, want = %d", got, want)
	}

	if got, want := ra.RetransTimer(), time.Millisecond*117967114; got != want {
		t.Errorf("got ra.RetransTimer = %d, want = %d", got, want)
	}
}

// TestNDPTargetLinkLayerAddressOptionEthernetAddress tests getting the
// Ethernet address from an NDPTargetLinkLayerAddressOption.
func TestNDPTargetLinkLayerAddressOptionEthernetAddress(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected tcpip.LinkAddress
	}{
		{
			"ValidMAC",
			[]byte{1, 2, 3, 4, 5, 6},
			tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06"),
		},
		{
			"TLLBodyTooShort",
			[]byte{1, 2, 3, 4, 5},
			tcpip.LinkAddress([]byte(nil)),
		},
		{
			"TLLBodyLargerThanNeeded",
			[]byte{1, 2, 3, 4, 5, 6, 7, 8},
			tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tll := NDPTargetLinkLayerAddressOption(test.buf)
			if got := tll.EthernetAddress(); got != test.expected {
				t.Errorf("got tll.EthernetAddress = %s, want = %s", got, test.expected)
			}
		})
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

			it, err := opts.Iter(true)
			if err != nil {
				t.Fatalf("got Iter = (_, %s), want = (_, nil)", err)
			}

			if len(test.expectedBuf) > 0 {
				next, done, err := it.Next()
				if err != nil {
					t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
				}
				if done {
					t.Fatal("got Next = (_, true, _), want = (_, false, _)")
				}
				if got := next.Type(); got != NDPTargetLinkLayerAddressOptionType {
					t.Fatalf("got Type %= %d, want = %d", got, NDPTargetLinkLayerAddressOptionType)
				}
				tll := next.(NDPTargetLinkLayerAddressOption)
				if got, want := []byte(tll), test.expectedBuf[2:]; !bytes.Equal(got, want) {
					t.Fatalf("got Next = (%x, _, _), want = (%x, _, _)", got, want)
				}

				if got, want := tll.EthernetAddress(), tcpip.LinkAddress(test.expectedBuf[2:][:EthernetAddressSize]); got != want {
					t.Errorf("got tll.MACAddress = %s, want = %s", got, want)
				}
			}

			// Iterator should not return anything else.
			next, done, err := it.Next()
			if err != nil {
				t.Errorf("got Next = (_, _, %s), want = (_, _, nil)", err)
			}
			if !done {
				t.Error("got Next = (_, false, _), want = (_, true, _)")
			}
			if next != nil {
				t.Errorf("got Next = (%x, _, _), want = (nil, _, _)", next)
			}
		})
	}
}

// TestNDPPrefixInformationOption tests the field getters and serialization of a
// NDPPrefixInformation.
func TestNDPPrefixInformationOption(t *testing.T) {
	b := []byte{
		43, 127,
		1, 2, 3, 4,
		5, 6, 7, 8,
		5, 5, 5, 5,
		9, 10, 11, 12,
		13, 14, 15, 16,
		17, 18, 19, 20,
		21, 22, 23, 24,
	}

	targetBuf := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	opts := NDPOptions(targetBuf)
	serializer := NDPOptionsSerializer{
		NDPPrefixInformation(b),
	}
	opts.Serialize(serializer)
	expectedBuf := []byte{
		3, 4, 43, 64,
		1, 2, 3, 4,
		5, 6, 7, 8,
		0, 0, 0, 0,
		9, 10, 11, 12,
		13, 14, 15, 16,
		17, 18, 19, 20,
		21, 22, 23, 24,
	}
	if !bytes.Equal(targetBuf, expectedBuf) {
		t.Fatalf("got targetBuf = %x, want = %x", targetBuf, expectedBuf)
	}

	it, err := opts.Iter(true)
	if err != nil {
		t.Fatalf("got Iter = (_, %s), want = (_, nil)", err)
	}

	next, done, err := it.Next()
	if err != nil {
		t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if done {
		t.Fatal("got Next = (_, true, _), want = (_, false, _)")
	}
	if got := next.Type(); got != NDPPrefixInformationType {
		t.Errorf("got Type = %d, want = %d", got, NDPPrefixInformationType)
	}

	pi := next.(NDPPrefixInformation)

	if got := pi.Type(); got != 3 {
		t.Errorf("got Type = %d, want = 3", got)
	}

	if got := pi.Length(); got != 30 {
		t.Errorf("got Length = %d, want = 30", got)
	}

	if got := pi.PrefixLength(); got != 43 {
		t.Errorf("got PrefixLength = %d, want = 43", got)
	}

	if pi.OnLinkFlag() {
		t.Error("got OnLinkFlag = true, want = false")
	}

	if !pi.AutonomousAddressConfigurationFlag() {
		t.Error("got AutonomousAddressConfigurationFlag = false, want = true")
	}

	if got, want := pi.ValidLifetime(), 16909060*time.Second; got != want {
		t.Errorf("got ValidLifetime = %d, want = %d", got, want)
	}

	if got, want := pi.PreferredLifetime(), 84281096*time.Second; got != want {
		t.Errorf("got PreferredLifetime = %d, want = %d", got, want)
	}

	if got, want := pi.Prefix(), tcpip.Address("\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18"); got != want {
		t.Errorf("got Prefix = %s, want = %s", got, want)
	}

	// Iterator should not return anything else.
	next, done, err = it.Next()
	if err != nil {
		t.Errorf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if !done {
		t.Error("got Next = (_, false, _), want = (_, true, _)")
	}
	if next != nil {
		t.Errorf("got Next = (%x, _, _), want = (nil, _, _)", next)
	}
}

// TestNDPDNSSearchListOption tests the getters of NDPDNSSearchList.
func TestNDPDNSSearchListOption(t *testing.T) {
	tests := []struct {
		name        string
		buf         []byte
		lifetime    time.Duration
		domainNames []string
	}{
		{
			"Valid1Label",
			[]byte{
				0, 0,
				0, 0, 0, 1,
				3, 'a', 'b', 'c',
				0,
				0, 0, 0,
			},
			time.Second,
			[]string{
				"abc",
			},
		},
		{
			"Valid2Label",
			[]byte{
				0, 0,
				0, 0, 0, 5,
				3, 'a', 'b', 'c',
				4, 'a', 'b', 'c', 'd',
				0,
				0, 0, 0, 0, 0, 0,
			},
			5 * time.Second,
			[]string{
				"abc.abcd",
			},
		},
		{
			"Valid3Label",
			[]byte{
				0, 0,
				1, 0, 0, 0,
				3, 'a', 'b', 'c',
				4, 'a', 'b', 'c', 'd',
				1, 'e',
				0,
				0, 0, 0, 0,
			},
			16777216 * time.Second,
			[]string{
				"abc.abcd.e",
			},
		},
		{
			"Valid2Domains",
			[]byte{
				0, 0,
				1, 2, 3, 4,
				3, 'a', 'b', 'c',
				0,
				2, 'd', 'e',
				3, 'x', 'y', 'z',
				0,
				0, 0, 0,
			},
			16909060 * time.Second,
			[]string{
				"abc",
				"de.xyz",
			},
		},
		{
			"Valid3DomainsMixedCase",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				3, 'a', 'B', 'c',
				0,
				2, 'd', 'E',
				3, 'X', 'y', 'z',
				0,
				1, 'J',
				0,
			},
			0,
			[]string{
				"abc",
				"de.xyz",
				"j",
			},
		},
		{
			"ValidDomainAfterNULL",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				3, 'a', 'B', 'c',
				0, 0, 0, 0,
				2, 'd', 'E',
				3, 'X', 'y', 'z',
				0,
			},
			0,
			[]string{
				"abc",
				"de.xyz",
			},
		},
		{
			"Valid0Domains",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				0,
				0, 0, 0, 0, 0, 0, 0,
			},
			0,
			nil,
		},
		{
			"NoTrailingNull",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				7, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			},
			0,
			nil,
		},
		{
			"IncorrectLength",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				8, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			},
			0,
			nil,
		},
		{
			"IncorrectLengthWithNULL",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				7, 'a', 'b', 'c', 'd', 'e', 'f',
				0,
			},
			0,
			nil,
		},
		{
			"LabelOfLength63",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				0,
			},
			0,
			[]string{
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
			},
		},
		{
			"LabelOfLength64",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				64, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l',
				0,
			},
			0,
			nil,
		},
		{
			"DomainNameOfLength255",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				62, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j',
				0,
			},
			0,
			[]string{
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij",
			},
		},
		{
			"DomainNameOfLength256",
			[]byte{
				0, 0,
				0, 0, 0, 0,
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				63, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
				'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
				'i', 'j', 'k',
				0,
			},
			0,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opt := NDPDNSSearchList(test.buf)

			if got := opt.Lifetime(); got != test.lifetime {
				t.Errorf("got Lifetime = %d, want = %d", got, test.lifetime)
			}
			if got := opt.DomainNames(); !cmp.Equal(got, test.domainNames) {
				t.Errorf("got DomainNames = %v, want = %v", got, test.domainNames)
			}
		})
	}
}

// TestNDPOptionsIterCheck tests that Iter will return false if the NDPOptions
// the iterator was returned for is malformed.
func TestNDPOptionsIterCheck(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected error
	}{
		{
			"ZeroLengthField",
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			ErrNDPOptZeroLength,
		},
		{
			"ValidTargetLinkLayerAddressOption",
			[]byte{2, 1, 1, 2, 3, 4, 5, 6},
			nil,
		},
		{
			"TooSmallTargetLinkLayerAddressOption",
			[]byte{2, 1, 1, 2, 3, 4, 5},
			ErrNDPOptBufExhausted,
		},
		{
			"ValidPrefixInformation",
			[]byte{
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23, 24,
			},
			nil,
		},
		{
			"TooSmallPrefixInformation",
			[]byte{
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23,
			},
			ErrNDPOptBufExhausted,
		},
		{
			"InvalidPrefixInformationLength",
			[]byte{
				3, 3, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
			},
			ErrNDPOptMalformedBody,
		},
		{
			"ValidTargetLinkLayerAddressWithPrefixInformation",
			[]byte{
				// Target Link-Layer Address.
				2, 1, 1, 2, 3, 4, 5, 6,

				// Prefix information.
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23, 24,
			},
			nil,
		},
		{
			"ValidTargetLinkLayerAddressWithPrefixInformationWithUnrecognized",
			[]byte{
				// Target Link-Layer Address.
				2, 1, 1, 2, 3, 4, 5, 6,

				// 255 is an unrecognized type. If 255 ends up
				// being the type for some recognized type,
				// update 255 to some other unrecognized value.
				255, 2, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8,

				// Prefix information.
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23, 24,
			},
			nil,
		},
		{
			"DNSSearchListTooSmall",
			[]byte{
				31, 1, 0, 0,
				0, 0, 0,
			},
			ErrNDPOptBufExhausted,
		},
		{
			"DNSSearchListNonCompiantRFC1035",
			[]byte{
				31, 2, 0, 0,
				0, 0, 0, 0,
				7, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			},
			ErrNDPOptMalformedBody,
		},
		{
			"DNSSearchListValidSmall",
			[]byte{
				31, 2, 0, 0,
				0, 0, 0, 0,
				6, 'a', 'b', 'c', 'd', 'e', 'f',
				0,
			},
			nil,
		},
		{
			"DNSSearchListValidLarge",
			[]byte{
				31, 3, 0, 0,
				0, 0, 0, 0,
				6, 'a', 'b', 'c', 'd', 'e', 'f',
				0,
				6, 'g', 'h', 'i', 'j', 'k', 'g',
				0,
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := NDPOptions(test.buf)

			if _, err := opts.Iter(true); err != test.expected {
				t.Fatalf("got Iter(true) = (_, %v), want = (_, %v)", err, test.expected)
			}

			// test.buf may be malformed but we chose not to check
			// the iterator so it must return true.
			if _, err := opts.Iter(false); err != nil {
				t.Fatalf("got Iter(false) = (_, %s), want = (_, nil)", err)
			}
		})
	}
}

// TestNDPOptionsIter tests that we can iterator over a valid NDPOptions. Note,
// this test does not actually check any of the option's getters, it simply
// checks the option Type and Body. We have other tests that tests the option
// field gettings given an option body and don't need to duplicate those tests
// here.
func TestNDPOptionsIter(t *testing.T) {
	buf := []byte{
		// Target Link-Layer Address.
		2, 1, 1, 2, 3, 4, 5, 6,

		// 255 is an unrecognized type. If 255 ends up being the type
		// for some recognized type, update 255 to some other
		// unrecognized value. Note, this option should be skipped when
		// iterating.
		255, 2, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8,

		// Prefix information.
		3, 4, 43, 64,
		1, 2, 3, 4,
		5, 6, 7, 8,
		0, 0, 0, 0,
		9, 10, 11, 12,
		13, 14, 15, 16,
		17, 18, 19, 20,
		21, 22, 23, 24,
	}

	opts := NDPOptions(buf)
	it, err := opts.Iter(true)
	if err != nil {
		t.Fatalf("got Iter = (_, %s), want = (_, nil)", err)
	}

	// Test the first (Taret Link-Layer) option.
	next, done, err := it.Next()
	if err != nil {
		t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if done {
		t.Fatal("got Next = (_, true, _), want = (_, false, _)")
	}
	if got, want := []byte(next.(NDPTargetLinkLayerAddressOption)), buf[2:][:6]; !bytes.Equal(got, want) {
		t.Errorf("got Next = (%x, _, _), want = (%x, _, _)", got, want)
	}
	if got := next.Type(); got != NDPTargetLinkLayerAddressOptionType {
		t.Errorf("got Type = %d, want = %d", got, NDPTargetLinkLayerAddressOptionType)
	}

	// Test the next (Prefix Information) option.
	// Note, the unrecognized option should be skipped.
	next, done, err = it.Next()
	if err != nil {
		t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if done {
		t.Fatal("got Next = (_, true, _), want = (_, false, _)")
	}
	if got, want := next.(NDPPrefixInformation), buf[26:][:30]; !bytes.Equal(got, want) {
		t.Errorf("got Next = (%x, _, _), want = (%x, _, _)", got, want)
	}
	if got := next.Type(); got != NDPPrefixInformationType {
		t.Errorf("got Type = %d, want = %d", got, NDPPrefixInformationType)
	}

	// Iterator should not return anything else.
	next, done, err = it.Next()
	if err != nil {
		t.Errorf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if !done {
		t.Error("got Next = (_, false, _), want = (_, true, _)")
	}
	if next != nil {
		t.Errorf("got Next = (%x, _, _), want = (nil, _, _)", next)
	}
}
