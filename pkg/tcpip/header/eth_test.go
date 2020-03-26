// Copyright 2018 The gVisor Authors.
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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestIsValidUnicastEthernetAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     tcpip.LinkAddress
		expected bool
	}{
		{
			"Nil",
			tcpip.LinkAddress([]byte(nil)),
			false,
		},
		{
			"Empty",
			tcpip.LinkAddress(""),
			false,
		},
		{
			"InvalidLength",
			tcpip.LinkAddress("\x01\x02\x03"),
			false,
		},
		{
			"Unspecified",
			unspecifiedEthernetAddress,
			false,
		},
		{
			"Multicast",
			tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06"),
			false,
		},
		{
			"Valid",
			tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06"),
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsValidUnicastEthernetAddress(test.addr); got != test.expected {
				t.Fatalf("got IsValidUnicastEthernetAddress = %t, want = %t", got, test.expected)
			}
		})
	}
}

func TestEthernetAddressFromMulticastIPv4Address(t *testing.T) {
	tests := []struct {
		name             string
		addr             tcpip.Address
		expectedLinkAddr tcpip.LinkAddress
	}{
		{
			name:             "IPv4 Multicast without 24th bit set",
			addr:             "\xe0\x7e\xdc\xba",
			expectedLinkAddr: "\x01\x00\x5e\x7e\xdc\xba",
		},
		{
			name:             "IPv4 Multicast with 24th bit set",
			addr:             "\xe0\xfe\xdc\xba",
			expectedLinkAddr: "\x01\x00\x5e\x7e\xdc\xba",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := EthernetAddressFromMulticastIPv4Address(test.addr); got != test.expectedLinkAddr {
				t.Fatalf("got EthernetAddressFromMulticastIPv4Address(%s) = %s, want = %s", test.addr, got, test.expectedLinkAddr)
			}
		})
	}
}

func TestEthernetAddressFromMulticastIPv6Address(t *testing.T) {
	addr := tcpip.Address("\xff\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x1a")
	if got, want := EthernetAddressFromMulticastIPv6Address(addr), tcpip.LinkAddress("\x33\x33\x0d\x0e\x0f\x1a"); got != want {
		t.Fatalf("got EthernetAddressFromMulticastIPv6Address(%s) = %s, want = %s", addr, got, want)
	}
}
