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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
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
		t.Errorf("got flags byte = %d, want = 64", got)
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

// TestNDPSourceLinkLayerAddressOptionEthernetAddress tests getting the
// Ethernet address from an NDPSourceLinkLayerAddressOption.
func TestNDPSourceLinkLayerAddressOptionEthernetAddress(t *testing.T) {
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
			"SLLBodyTooShort",
			[]byte{1, 2, 3, 4, 5},
			tcpip.LinkAddress([]byte(nil)),
		},
		{
			"SLLBodyLargerThanNeeded",
			[]byte{1, 2, 3, 4, 5, 6, 7, 8},
			tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sll := NDPSourceLinkLayerAddressOption(test.buf)
			if got := sll.EthernetAddress(); got != test.expected {
				t.Errorf("got sll.EthernetAddress = %s, want = %s", got, test.expected)
			}
		})
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

func TestOpts(t *testing.T) {
	const optionHeaderLen = 2

	checkNonce := func(expectedNonce []byte) func(*testing.T, NDPOption) {
		return func(t *testing.T, opt NDPOption) {
			if got := opt.Type(); got != NDPNonceOptionType {
				t.Errorf("got Type() = %d, want = %d", got, NDPNonceOptionType)
			}
			nonce, ok := opt.(NDPNonceOption)
			if !ok {
				t.Fatalf("got nonce = %T, want = NDPNonceOption", opt)
			}
			if diff := cmp.Diff(expectedNonce, nonce.Nonce()); diff != "" {
				t.Errorf("nonce mismatch (-want +got):\n%s", diff)
			}
		}
	}

	checkTLL := func(expectedAddr tcpip.LinkAddress) func(*testing.T, NDPOption) {
		return func(t *testing.T, opt NDPOption) {
			if got := opt.Type(); got != NDPTargetLinkLayerAddressOptionType {
				t.Errorf("got Type() = %d, want = %d", got, NDPTargetLinkLayerAddressOptionType)
			}
			tll, ok := opt.(NDPTargetLinkLayerAddressOption)
			if !ok {
				t.Fatalf("got tll = %T, want = NDPTargetLinkLayerAddressOption", opt)
			}
			if got, want := tll.EthernetAddress(), expectedAddr; got != want {
				t.Errorf("got tll.EthernetAddress = %s, want = %s", got, want)
			}
		}
	}

	checkSLL := func(expectedAddr tcpip.LinkAddress) func(*testing.T, NDPOption) {
		return func(t *testing.T, opt NDPOption) {
			if got := opt.Type(); got != NDPSourceLinkLayerAddressOptionType {
				t.Errorf("got Type() = %d, want = %d", got, NDPSourceLinkLayerAddressOptionType)
			}
			sll, ok := opt.(NDPSourceLinkLayerAddressOption)
			if !ok {
				t.Fatalf("got sll = %T, want = NDPSourceLinkLayerAddressOption", opt)
			}
			if got, want := sll.EthernetAddress(), expectedAddr; got != want {
				t.Errorf("got sll.EthernetAddress = %s, want = %s", got, want)
			}
		}
	}

	const validLifetimeSeconds = 16909060
	const address = tcpip.Address("\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18")

	expectedRDNSSBytes := [...]byte{
		// Type, Length
		25, 3,

		// Reserved
		0, 0,

		// Lifetime
		1, 2, 4, 8,

		// Address
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	}
	binary.BigEndian.PutUint32(expectedRDNSSBytes[4:], validLifetimeSeconds)
	if n := copy(expectedRDNSSBytes[8:], address); n != IPv6AddressSize {
		t.Fatalf("got copy(...) = %d, want = %d", n, IPv6AddressSize)
	}
	// Update reserved fields to non zero values to make sure serializing sets
	// them to zero.
	rdnssBytes := expectedRDNSSBytes
	rdnssBytes[1] = 1
	rdnssBytes[2] = 2

	const searchListPaddingBytes = 3
	const domainName = "abc.abcd.e"
	expectedSearchListBytes := [...]byte{
		// Type, Length
		31, 3,

		// Reserved
		0, 0,

		// Lifetime
		1, 0, 0, 0,

		// Domain names
		3, 'a', 'b', 'c',
		4, 'a', 'b', 'c', 'd',
		1, 'e',
		0,
		0, 0, 0, 0,
	}
	binary.BigEndian.PutUint32(expectedSearchListBytes[4:], validLifetimeSeconds)
	// Update reserved fields to non zero values to make sure serializing sets
	// them to zero.
	searchListBytes := expectedSearchListBytes
	searchListBytes[2] = 1
	searchListBytes[3] = 2

	const prefixLength = 43
	const onLinkFlag = false
	const slaacFlag = true
	const preferredLifetimeSeconds = 84281096
	const onLinkFlagBit = 7
	const slaacFlagBit = 6
	boolToByte := func(v bool) byte {
		if v {
			return 1
		}
		return 0
	}
	flags := boolToByte(onLinkFlag)<<onLinkFlagBit | boolToByte(slaacFlag)<<slaacFlagBit
	expectedPrefixInformationBytes := [...]byte{
		// Type, Length
		3, 4,

		prefixLength, flags,

		// Valid Lifetime
		1, 2, 3, 4,

		// Preferred Lifetime
		5, 6, 7, 8,

		// Reserved2
		0, 0, 0, 0,

		// Address
		9, 10, 11, 12,
		13, 14, 15, 16,
		17, 18, 19, 20,
		21, 22, 23, 24,
	}
	binary.BigEndian.PutUint32(expectedPrefixInformationBytes[4:], validLifetimeSeconds)
	binary.BigEndian.PutUint32(expectedPrefixInformationBytes[8:], preferredLifetimeSeconds)
	if n := copy(expectedPrefixInformationBytes[16:], address); n != IPv6AddressSize {
		t.Fatalf("got copy(...) = %d, want = %d", n, IPv6AddressSize)
	}
	// Update reserved fields to non zero values to make sure serializing sets
	// them to zero.
	prefixInformationBytes := expectedPrefixInformationBytes
	prefixInformationBytes[3] |= (1 << slaacFlagBit) - 1
	binary.BigEndian.PutUint32(prefixInformationBytes[12:], validLifetimeSeconds+1)
	tests := []struct {
		name        string
		buf         []byte
		opt         NDPOption
		expectedBuf []byte
		check       func(*testing.T, NDPOption)
	}{
		{
			name:        "Nonce",
			buf:         make([]byte, 8),
			opt:         NDPNonceOption([]byte{1, 2, 3, 4, 5, 6}),
			expectedBuf: []byte{14, 1, 1, 2, 3, 4, 5, 6},
			check:       checkNonce([]byte{1, 2, 3, 4, 5, 6}),
		},
		{
			name:        "Nonce with padding",
			buf:         []byte{1, 1, 1, 1, 1, 1, 1, 1},
			opt:         NDPNonceOption([]byte{1, 2, 3, 4, 5}),
			expectedBuf: []byte{14, 1, 1, 2, 3, 4, 5, 0},
			check:       checkNonce([]byte{1, 2, 3, 4, 5, 0}),
		},

		{
			name:        "TLL Ethernet",
			buf:         make([]byte, 8),
			opt:         NDPTargetLinkLayerAddressOption("\x01\x02\x03\x04\x05\x06"),
			expectedBuf: []byte{2, 1, 1, 2, 3, 4, 5, 6},
			check:       checkTLL("\x01\x02\x03\x04\x05\x06"),
		},
		{
			name:        "TLL Padding",
			buf:         []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			opt:         NDPTargetLinkLayerAddressOption("\x01\x02\x03\x04\x05\x06\x07\x08"),
			expectedBuf: []byte{2, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0},
			check:       checkTLL("\x01\x02\x03\x04\x05\x06"),
		},
		{
			name:        "TLL Empty",
			buf:         nil,
			opt:         NDPTargetLinkLayerAddressOption(""),
			expectedBuf: nil,
		},

		{
			name:        "SLL Ethernet",
			buf:         make([]byte, 8),
			opt:         NDPSourceLinkLayerAddressOption("\x01\x02\x03\x04\x05\x06"),
			expectedBuf: []byte{1, 1, 1, 2, 3, 4, 5, 6},
			check:       checkSLL("\x01\x02\x03\x04\x05\x06"),
		},
		{
			name:        "SLL Padding",
			buf:         []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			opt:         NDPSourceLinkLayerAddressOption("\x01\x02\x03\x04\x05\x06\x07\x08"),
			expectedBuf: []byte{1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0},
			check:       checkSLL("\x01\x02\x03\x04\x05\x06"),
		},
		{
			name:        "SLL Empty",
			buf:         nil,
			opt:         NDPSourceLinkLayerAddressOption(""),
			expectedBuf: nil,
		},

		{
			name: "RDNSS",
			buf:  []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			// NDPRecursiveDNSServer holds the option after the header bytes.
			opt:         NDPRecursiveDNSServer(rdnssBytes[optionHeaderLen:]),
			expectedBuf: expectedRDNSSBytes[:],
			check: func(t *testing.T, opt NDPOption) {
				if got := opt.Type(); got != NDPRecursiveDNSServerOptionType {
					t.Errorf("got Type() = %d, want = %d", got, NDPRecursiveDNSServerOptionType)
				}
				rdnss, ok := opt.(NDPRecursiveDNSServer)
				if !ok {
					t.Fatalf("got opt = %T, want = NDPRecursiveDNSServer", opt)
				}
				if got, want := rdnss.Length(), len(expectedRDNSSBytes[optionHeaderLen:]); got != want {
					t.Errorf("got Length() = %d, want = %d", got, want)
				}
				if got, want := rdnss.Lifetime(), validLifetimeSeconds*time.Second; got != want {
					t.Errorf("got Lifetime() = %s, want = %s", got, want)
				}
				if addrs, err := rdnss.Addresses(); err != nil {
					t.Errorf("Addresses(): %s", err)
				} else if diff := cmp.Diff([]tcpip.Address{address}, addrs); diff != "" {
					t.Errorf("mismatched addresses (-want +got):\n%s", diff)
				}
			},
		},

		{
			name:        "Search list",
			buf:         []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			opt:         NDPDNSSearchList(searchListBytes[optionHeaderLen:]),
			expectedBuf: expectedSearchListBytes[:],
			check: func(t *testing.T, opt NDPOption) {
				if got := opt.Type(); got != NDPDNSSearchListOptionType {
					t.Errorf("got Type() = %d, want = %d", got, NDPDNSSearchListOptionType)
				}

				dnssl, ok := opt.(NDPDNSSearchList)
				if !ok {
					t.Fatalf("got opt = %T, want = NDPDNSSearchList", opt)
				}
				if got, want := dnssl.Length(), len(expectedRDNSSBytes[optionHeaderLen:]); got != want {
					t.Errorf("got Length() = %d, want = %d", got, want)
				}
				if got, want := dnssl.Lifetime(), validLifetimeSeconds*time.Second; got != want {
					t.Errorf("got Lifetime() = %s, want = %s", got, want)
				}

				if domainNames, err := dnssl.DomainNames(); err != nil {
					t.Errorf("DomainNames(): %s", err)
				} else if diff := cmp.Diff([]string{domainName}, domainNames); diff != "" {
					t.Errorf("domain names mismatch (-want +got):\n%s", diff)
				}
			},
		},

		{
			name: "Prefix Information",
			buf:  []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			// NDPPrefixInformation holds the option after the header bytes.
			opt:         NDPPrefixInformation(prefixInformationBytes[optionHeaderLen:]),
			expectedBuf: expectedPrefixInformationBytes[:],
			check: func(t *testing.T, opt NDPOption) {
				if got := opt.Type(); got != NDPPrefixInformationType {
					t.Errorf("got Type() = %d, want = %d", got, NDPPrefixInformationType)
				}

				pi, ok := opt.(NDPPrefixInformation)
				if !ok {
					t.Fatalf("got opt = %T, want = NDPPrefixInformation", opt)
				}

				if got, want := pi.Length(), len(expectedPrefixInformationBytes[optionHeaderLen:]); got != want {
					t.Errorf("got Length() = %d, want = %d", got, want)
				}
				if got := pi.PrefixLength(); got != prefixLength {
					t.Errorf("got PrefixLength() = %d, want = %d", got, prefixLength)
				}
				if got := pi.OnLinkFlag(); got != onLinkFlag {
					t.Errorf("got OnLinkFlag() = %t, want = %t", got, onLinkFlag)
				}
				if got := pi.AutonomousAddressConfigurationFlag(); got != slaacFlag {
					t.Errorf("got AutonomousAddressConfigurationFlag() = %t, want = %t", got, slaacFlag)
				}
				if got, want := pi.ValidLifetime(), validLifetimeSeconds*time.Second; got != want {
					t.Errorf("got ValidLifetime() = %s, want = %s", got, want)
				}
				if got, want := pi.PreferredLifetime(), preferredLifetimeSeconds*time.Second; got != want {
					t.Errorf("got PreferredLifetime() = %s, want = %s", got, want)
				}
				if got := pi.Prefix(); got != address {
					t.Errorf("got Prefix() = %s, want = %s", got, address)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := NDPOptions(test.buf)
			serializer := NDPOptionsSerializer{
				test.opt,
			}
			if got, want := int(serializer.Length()), len(test.expectedBuf); got != want {
				t.Fatalf("got Length() = %d, want = %d", got, want)
			}
			opts.Serialize(serializer)
			if diff := cmp.Diff(test.expectedBuf, test.buf); diff != "" {
				t.Fatalf("serialized buffer mismatch (-want +got):\n%s", diff)
			}

			it, err := opts.Iter(true)
			if err != nil {
				t.Fatalf("got Iter(true) = (_, %s), want = (_, nil)", err)
			}

			if len(test.expectedBuf) > 0 {
				next, done, err := it.Next()
				if err != nil {
					t.Fatalf("got Next() = (_, _, %s), want = (_, _, nil)", err)
				}
				if done {
					t.Fatal("got Next() = (_, true, _), want = (_, false, _)")
				}
				test.check(t, next)
			}

			// Iterator should not return anything else.
			next, done, err := it.Next()
			if err != nil {
				t.Errorf("got Next() = (_, _, %s), want = (_, _, nil)", err)
			}
			if !done {
				t.Error("got Next() = (_, false, _), want = (_, true, _)")
			}
			if next != nil {
				t.Errorf("got Next() = (%x, _, _), want = (nil, _, _)", next)
			}
		})
	}
}

func TestNDPRecursiveDNSServerOption(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		lifetime time.Duration
		addrs    []tcpip.Address
	}{
		{
			"Valid1Addr",
			[]byte{
				25, 3, 0, 0,
				0, 0, 0, 0,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			},
			0,
			[]tcpip.Address{
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
			},
		},
		{
			"Valid2Addr",
			[]byte{
				25, 5, 0, 0,
				0, 0, 0, 0,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16,
			},
			0,
			[]tcpip.Address{
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
				"\x11\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x10",
			},
		},
		{
			"Valid3Addr",
			[]byte{
				25, 7, 0, 0,
				0, 0, 0, 0,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16,
				17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17,
			},
			0,
			[]tcpip.Address{
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
				"\x11\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x10",
				"\x11\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x11",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := NDPOptions(test.buf)
			it, err := opts.Iter(true)
			if err != nil {
				t.Fatalf("got Iter = (_, %s), want = (_, nil)", err)
			}

			// Iterator should get our option.
			next, done, err := it.Next()
			if err != nil {
				t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
			}
			if done {
				t.Fatal("got Next = (_, true, _), want = (_, false, _)")
			}
			if got := next.Type(); got != NDPRecursiveDNSServerOptionType {
				t.Fatalf("got Type = %d, want = %d", got, NDPRecursiveDNSServerOptionType)
			}

			opt, ok := next.(NDPRecursiveDNSServer)
			if !ok {
				t.Fatalf("next (type = %T) cannot be casted to an NDPRecursiveDNSServer", next)
			}
			if got := opt.Lifetime(); got != test.lifetime {
				t.Errorf("got Lifetime = %d, want = %d", got, test.lifetime)
			}
			addrs, err := opt.Addresses()
			if err != nil {
				t.Errorf("opt.Addresses() = %s", err)
			}
			if diff := cmp.Diff(addrs, test.addrs); diff != "" {
				t.Errorf("mismatched addresses (-want +got):\n%s", diff)
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
		})
	}
}

// TestNDPDNSSearchListOption tests the getters of NDPDNSSearchList.
func TestNDPDNSSearchListOption(t *testing.T) {
	tests := []struct {
		name        string
		buf         []byte
		lifetime    time.Duration
		domainNames []string
		err         error
	}{
		{
			name: "Valid1Label",
			buf: []byte{
				0, 0,
				0, 0, 0, 1,
				3, 'a', 'b', 'c',
				0,
				0, 0, 0,
			},
			lifetime: time.Second,
			domainNames: []string{
				"abc",
			},
			err: nil,
		},
		{
			name: "Valid2Label",
			buf: []byte{
				0, 0,
				0, 0, 0, 5,
				3, 'a', 'b', 'c',
				4, 'a', 'b', 'c', 'd',
				0,
				0, 0, 0, 0, 0, 0,
			},
			lifetime: 5 * time.Second,
			domainNames: []string{
				"abc.abcd",
			},
			err: nil,
		},
		{
			name: "Valid3Label",
			buf: []byte{
				0, 0,
				1, 0, 0, 0,
				3, 'a', 'b', 'c',
				4, 'a', 'b', 'c', 'd',
				1, 'e',
				0,
				0, 0, 0, 0,
			},
			lifetime: 16777216 * time.Second,
			domainNames: []string{
				"abc.abcd.e",
			},
			err: nil,
		},
		{
			name: "Valid2Domains",
			buf: []byte{
				0, 0,
				1, 2, 3, 4,
				3, 'a', 'b', 'c',
				0,
				2, 'd', 'e',
				3, 'x', 'y', 'z',
				0,
				0, 0, 0,
			},
			lifetime: 16909060 * time.Second,
			domainNames: []string{
				"abc",
				"de.xyz",
			},
			err: nil,
		},
		{
			name: "Valid3DomainsMixedCase",
			buf: []byte{
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
			lifetime: 0,
			domainNames: []string{
				"abc",
				"de.xyz",
				"j",
			},
			err: nil,
		},
		{
			name: "ValidDomainAfterNULL",
			buf: []byte{
				0, 0,
				0, 0, 0, 0,
				3, 'a', 'B', 'c',
				0, 0, 0, 0,
				2, 'd', 'E',
				3, 'X', 'y', 'z',
				0,
			},
			lifetime: 0,
			domainNames: []string{
				"abc",
				"de.xyz",
			},
			err: nil,
		},
		{
			name: "Valid0Domains",
			buf: []byte{
				0, 0,
				0, 0, 0, 0,
				0,
				0, 0, 0, 0, 0, 0, 0,
			},
			lifetime:    0,
			domainNames: nil,
			err:         nil,
		},
		{
			name: "NoTrailingNull",
			buf: []byte{
				0, 0,
				0, 0, 0, 0,
				7, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			},
			lifetime:    0,
			domainNames: nil,
			err:         io.ErrUnexpectedEOF,
		},
		{
			name: "IncorrectLength",
			buf: []byte{
				0, 0,
				0, 0, 0, 0,
				8, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			},
			lifetime:    0,
			domainNames: nil,
			err:         io.ErrUnexpectedEOF,
		},
		{
			name: "IncorrectLengthWithNULL",
			buf: []byte{
				0, 0,
				0, 0, 0, 0,
				7, 'a', 'b', 'c', 'd', 'e', 'f',
				0,
			},
			lifetime:    0,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "LabelOfLength63",
			buf: []byte{
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
			lifetime: 0,
			domainNames: []string{
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
			},
			err: nil,
		},
		{
			name: "LabelOfLength64",
			buf: []byte{
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
			lifetime:    0,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "DomainNameOfLength255",
			buf: []byte{
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
			lifetime: 0,
			domainNames: []string{
				"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij",
			},
			err: nil,
		},
		{
			name: "DomainNameOfLength256",
			buf: []byte{
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
			lifetime:    0,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "StartingDigitForLabel",
			buf: []byte{
				0, 0,
				0, 0, 0, 1,
				3, '9', 'b', 'c',
				0,
				0, 0, 0,
			},
			lifetime:    time.Second,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "StartingHyphenForLabel",
			buf: []byte{
				0, 0,
				0, 0, 0, 1,
				3, '-', 'b', 'c',
				0,
				0, 0, 0,
			},
			lifetime:    time.Second,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "EndingHyphenForLabel",
			buf: []byte{
				0, 0,
				0, 0, 0, 1,
				3, 'a', 'b', '-',
				0,
				0, 0, 0,
			},
			lifetime:    time.Second,
			domainNames: nil,
			err:         ErrNDPOptMalformedBody,
		},
		{
			name: "EndingDigitForLabel",
			buf: []byte{
				0, 0,
				0, 0, 0, 1,
				3, 'a', 'b', '9',
				0,
				0, 0, 0,
			},
			lifetime: time.Second,
			domainNames: []string{
				"ab9",
			},
			err: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opt := NDPDNSSearchList(test.buf)

			if got := opt.Lifetime(); got != test.lifetime {
				t.Errorf("got Lifetime = %d, want = %d", got, test.lifetime)
			}
			domainNames, err := opt.DomainNames()
			if !errors.Is(err, test.err) {
				t.Errorf("opt.DomainNames() = %s", err)
			}
			if diff := cmp.Diff(domainNames, test.domainNames); diff != "" {
				t.Errorf("mismatched domain names (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNDPSearchListOptionDomainNameLabelInvalidSymbols(t *testing.T) {
	for r := rune(0); r <= 255; r++ {
		t.Run(fmt.Sprintf("RuneVal=%d", r), func(t *testing.T) {
			buf := []byte{
				0, 0,
				0, 0, 0, 0,
				3, 'a', 0 /* will be replaced */, 'c',
				0,
				0, 0, 0,
			}
			buf[8] = uint8(r)
			opt := NDPDNSSearchList(buf)

			// As per RFC 1035 section 2.3.1, the label must only include ASCII
			// letters, digits and hyphens (a-z, A-Z, 0-9, -).
			var expectedErr error
			re := regexp.MustCompile(`[a-zA-Z0-9-]`)
			if !re.Match([]byte{byte(r)}) {
				expectedErr = ErrNDPOptMalformedBody
			}

			if domainNames, err := opt.DomainNames(); !errors.Is(err, expectedErr) {
				t.Errorf("got opt.DomainNames() = (%s, %v), want = (_, %v)", domainNames, err, ErrNDPOptMalformedBody)
			}
		})
	}
}

// TestNDPOptionsIterCheck tests that Iter will return false if the NDPOptions
// the iterator was returned for is malformed.
func TestNDPOptionsIterCheck(t *testing.T) {
	tests := []struct {
		name        string
		buf         []byte
		expectedErr error
	}{
		{
			name:        "ZeroLengthField",
			buf:         []byte{0, 0, 0, 0, 0, 0, 0, 0},
			expectedErr: ErrNDPOptMalformedHeader,
		},
		{
			name:        "ValidSourceLinkLayerAddressOption",
			buf:         []byte{1, 1, 1, 2, 3, 4, 5, 6},
			expectedErr: nil,
		},
		{
			name:        "TooSmallSourceLinkLayerAddressOption",
			buf:         []byte{1, 1, 1, 2, 3, 4, 5},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name:        "ValidTargetLinkLayerAddressOption",
			buf:         []byte{2, 1, 1, 2, 3, 4, 5, 6},
			expectedErr: nil,
		},
		{
			name:        "TooSmallTargetLinkLayerAddressOption",
			buf:         []byte{2, 1, 1, 2, 3, 4, 5},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name: "ValidPrefixInformation",
			buf: []byte{
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23, 24,
			},
			expectedErr: nil,
		},
		{
			name: "TooSmallPrefixInformation",
			buf: []byte{
				3, 4, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
				17, 18, 19, 20,
				21, 22, 23,
			},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name: "InvalidPrefixInformationLength",
			buf: []byte{
				3, 3, 43, 64,
				1, 2, 3, 4,
				5, 6, 7, 8,
				0, 0, 0, 0,
				9, 10, 11, 12,
				13, 14, 15, 16,
			},
			expectedErr: ErrNDPOptMalformedBody,
		},
		{
			name: "ValidSourceAndTargetLinkLayerAddressWithPrefixInformation",
			buf: []byte{
				// Source Link-Layer Address.
				1, 1, 1, 2, 3, 4, 5, 6,

				// Target Link-Layer Address.
				2, 1, 7, 8, 9, 10, 11, 12,

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
			expectedErr: nil,
		},
		{
			name: "ValidSourceAndTargetLinkLayerAddressWithPrefixInformationWithUnrecognized",
			buf: []byte{
				// Source Link-Layer Address.
				1, 1, 1, 2, 3, 4, 5, 6,

				// Target Link-Layer Address.
				2, 1, 7, 8, 9, 10, 11, 12,

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
			expectedErr: nil,
		},
		{
			name: "InvalidRecursiveDNSServerCutsOffAddress",
			buf: []byte{
				25, 4, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0, 1, 2, 3, 4, 5, 6, 7,
			},
			expectedErr: ErrNDPOptMalformedBody,
		},
		{
			name: "InvalidRecursiveDNSServerInvalidLengthField",
			buf: []byte{
				25, 2, 0, 0,
				0, 0, 0, 0,
				0, 1, 2, 3, 4, 5, 6, 7, 8,
			},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name: "RecursiveDNSServerTooSmall",
			buf: []byte{
				25, 1, 0, 0,
				0, 0, 0,
			},
			expectedErr: io.ErrUnexpectedEOF,
		},
		{
			name: "RecursiveDNSServerMulticast",
			buf: []byte{
				25, 3, 0, 0,
				0, 0, 0, 0,
				255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			},
			expectedErr: ErrNDPOptMalformedBody,
		},
		{
			name: "RecursiveDNSServerUnspecified",
			buf: []byte{
				25, 3, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			expectedErr: ErrNDPOptMalformedBody,
		},
		{
			name: "DNSSearchListLargeCompliantRFC1035",
			buf: []byte{
				31, 33, 0, 0,
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
			expectedErr: nil,
		},
		{
			name: "DNSSearchListNonCompliantRFC1035",
			buf: []byte{
				31, 33, 0, 0,
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
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			expectedErr: ErrNDPOptMalformedBody,
		},
		{
			name: "DNSSearchListValidSmall",
			buf: []byte{
				31, 2, 0, 0,
				0, 0, 0, 0,
				6, 'a', 'b', 'c', 'd', 'e', 'f',
				0,
			},
			expectedErr: nil,
		},
		{
			name: "DNSSearchListTooSmall",
			buf: []byte{
				31, 1, 0, 0,
				0, 0, 0,
			},
			expectedErr: io.ErrUnexpectedEOF,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := NDPOptions(test.buf)

			if _, err := opts.Iter(true); !errors.Is(err, test.expectedErr) {
				t.Fatalf("got Iter(true) = (_, %v), want = (_, %v)", err, test.expectedErr)
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
		// Source Link-Layer Address.
		1, 1, 1, 2, 3, 4, 5, 6,

		// Target Link-Layer Address.
		2, 1, 7, 8, 9, 10, 11, 12,

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

	// Test the first (Source Link-Layer) option.
	next, done, err := it.Next()
	if err != nil {
		t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if done {
		t.Fatal("got Next = (_, true, _), want = (_, false, _)")
	}
	if got, want := []byte(next.(NDPSourceLinkLayerAddressOption)), buf[2:][:6]; !bytes.Equal(got, want) {
		t.Errorf("got Next = (%x, _, _), want = (%x, _, _)", got, want)
	}
	if got := next.Type(); got != NDPSourceLinkLayerAddressOptionType {
		t.Errorf("got Type = %d, want = %d", got, NDPSourceLinkLayerAddressOptionType)
	}

	// Test the next (Target Link-Layer) option.
	next, done, err = it.Next()
	if err != nil {
		t.Fatalf("got Next = (_, _, %s), want = (_, _, nil)", err)
	}
	if done {
		t.Fatal("got Next = (_, true, _), want = (_, false, _)")
	}
	if got, want := []byte(next.(NDPTargetLinkLayerAddressOption)), buf[10:][:6]; !bytes.Equal(got, want) {
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
	if got, want := next.(NDPPrefixInformation), buf[34:][:30]; !bytes.Equal(got, want) {
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
