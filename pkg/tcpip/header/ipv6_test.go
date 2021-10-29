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

package header_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")

var (
	linkLocalAddr          = testutil.MustParse6("fe80::1")
	linkLocalMulticastAddr = testutil.MustParse6("ff02::1")
	uniqueLocalAddr1       = testutil.MustParse6("fc00::1")
	uniqueLocalAddr2       = testutil.MustParse6("fd00::2")
	globalAddr             = testutil.MustParse6("a000::1")
)

func TestEthernetAdddressToModifiedEUI64(t *testing.T) {
	expectedIID := [header.IIDSize]byte{0, 2, 3, 255, 254, 4, 5, 6}

	if diff := cmp.Diff(expectedIID, header.EthernetAddressToModifiedEUI64(linkAddr)); diff != "" {
		t.Errorf("EthernetAddressToModifiedEUI64(%s) mismatch (-want +got):\n%s", linkAddr, diff)
	}

	var buf [header.IIDSize]byte
	header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, buf[:])
	if diff := cmp.Diff(expectedIID, buf); diff != "" {
		t.Errorf("EthernetAddressToModifiedEUI64IntoBuf(%s, _) mismatch (-want +got):\n%s", linkAddr, diff)
	}
}

func TestLinkLocalAddr(t *testing.T) {
	if got, want := header.LinkLocalAddr(linkAddr), testutil.MustParse6("fe80::2:3ff:fe04:506"); got != want {
		t.Errorf("got LinkLocalAddr(%s) = %s, want = %s", linkAddr, got, want)
	}
}

func TestAppendOpaqueInterfaceIdentifier(t *testing.T) {
	var secretKeyBuf [header.OpaqueIIDSecretKeyMinBytes * 2]byte
	if n, err := rand.Read(secretKeyBuf[:]); err != nil {
		t.Fatalf("rand.Read(_): %s", err)
	} else if want := header.OpaqueIIDSecretKeyMinBytes * 2; n != want {
		t.Fatalf("expected rand.Read to read %d bytes, read %d bytes", want, n)
	}

	tests := []struct {
		name       string
		prefix     tcpip.Subnet
		nicName    string
		dadCounter uint8
		secretKey  []byte
	}{
		{
			name:       "SecretKey of minimum size",
			prefix:     header.IPv6LinkLocalPrefix.Subnet(),
			nicName:    "eth0",
			dadCounter: 0,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes],
		},
		{
			name: "SecretKey of less than minimum size",
			prefix: func() tcpip.Subnet {
				addrWithPrefix := tcpip.AddressWithPrefix{
					Address:   "\x01\x02\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
					PrefixLen: header.IIDOffsetInIPv6Address * 8,
				}
				return addrWithPrefix.Subnet()
			}(),
			nicName:    "eth10",
			dadCounter: 1,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes/2],
		},
		{
			name: "SecretKey of more than minimum size",
			prefix: func() tcpip.Subnet {
				addrWithPrefix := tcpip.AddressWithPrefix{
					Address:   "\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
					PrefixLen: header.IIDOffsetInIPv6Address * 8,
				}
				return addrWithPrefix.Subnet()
			}(),
			nicName:    "eth11",
			dadCounter: 2,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes*2],
		},
		{
			name: "Nil SecretKey and empty nicName",
			prefix: func() tcpip.Subnet {
				addrWithPrefix := tcpip.AddressWithPrefix{
					Address:   "\x01\x02\x03\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
					PrefixLen: header.IIDOffsetInIPv6Address * 8,
				}
				return addrWithPrefix.Subnet()
			}(),
			nicName:    "",
			dadCounter: 3,
			secretKey:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := sha256.New()
			h.Write([]byte(test.prefix.ID()[:header.IIDOffsetInIPv6Address]))
			h.Write([]byte(test.nicName))
			h.Write([]byte{test.dadCounter})
			if k := test.secretKey; k != nil {
				h.Write(k)
			}
			var hashSum [sha256.Size]byte
			h.Sum(hashSum[:0])
			want := hashSum[:header.IIDSize]

			// Passing a nil buffer should result in a new buffer returned with the
			// IID.
			if got := header.AppendOpaqueInterfaceIdentifier(nil, test.prefix, test.nicName, test.dadCounter, test.secretKey); !bytes.Equal(got, want) {
				t.Errorf("got AppendOpaqueInterfaceIdentifier(nil, %s, %s, %d, %x) = %x, want = %x", test.prefix, test.nicName, test.dadCounter, test.secretKey, got, want)
			}

			// Passing a buffer with sufficient capacity for the IID should populate
			// the buffer provided.
			var iidBuf [header.IIDSize]byte
			if got := header.AppendOpaqueInterfaceIdentifier(iidBuf[:0], test.prefix, test.nicName, test.dadCounter, test.secretKey); !bytes.Equal(got, want) {
				t.Errorf("got AppendOpaqueInterfaceIdentifier(iidBuf[:0], %s, %s, %d, %x) = %x, want = %x", test.prefix, test.nicName, test.dadCounter, test.secretKey, got, want)
			}
			if got := iidBuf[:]; !bytes.Equal(got, want) {
				t.Errorf("got iidBuf = %x, want = %x", got, want)
			}
		})
	}
}

func TestLinkLocalAddrWithOpaqueIID(t *testing.T) {
	var secretKeyBuf [header.OpaqueIIDSecretKeyMinBytes * 2]byte
	if n, err := rand.Read(secretKeyBuf[:]); err != nil {
		t.Fatalf("rand.Read(_): %s", err)
	} else if want := header.OpaqueIIDSecretKeyMinBytes * 2; n != want {
		t.Fatalf("expected rand.Read to read %d bytes, read %d bytes", want, n)
	}

	prefix := header.IPv6LinkLocalPrefix.Subnet()

	tests := []struct {
		name       string
		prefix     tcpip.Subnet
		nicName    string
		dadCounter uint8
		secretKey  []byte
	}{
		{
			name:       "SecretKey of minimum size",
			nicName:    "eth0",
			dadCounter: 0,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes],
		},
		{
			name:       "SecretKey of less than minimum size",
			nicName:    "eth10",
			dadCounter: 1,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes/2],
		},
		{
			name:       "SecretKey of more than minimum size",
			nicName:    "eth11",
			dadCounter: 2,
			secretKey:  secretKeyBuf[:header.OpaqueIIDSecretKeyMinBytes*2],
		},
		{
			name:       "Nil SecretKey and empty nicName",
			nicName:    "",
			dadCounter: 3,
			secretKey:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addrBytes := [header.IPv6AddressSize]byte{
				0: 0xFE,
				1: 0x80,
			}

			want := tcpip.Address(header.AppendOpaqueInterfaceIdentifier(
				addrBytes[:header.IIDOffsetInIPv6Address],
				prefix,
				test.nicName,
				test.dadCounter,
				test.secretKey,
			))

			if got := header.LinkLocalAddrWithOpaqueIID(test.nicName, test.dadCounter, test.secretKey); got != want {
				t.Errorf("got LinkLocalAddrWithOpaqueIID(%s, %d, %x) = %s, want = %s", test.nicName, test.dadCounter, test.secretKey, got, want)
			}
		})
	}
}

func TestIsV6LinkLocalMulticastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     tcpip.Address
		expected bool
	}{
		{
			name:     "Valid Link Local Multicast",
			addr:     linkLocalMulticastAddr,
			expected: true,
		},
		{
			name:     "Valid Link Local Multicast with flags",
			addr:     "\xff\xf2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			expected: true,
		},
		{
			name:     "Link Local Unicast",
			addr:     linkLocalAddr,
			expected: false,
		},
		{
			name:     "IPv4 Multicast",
			addr:     "\xe0\x00\x00\x01",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV6LinkLocalMulticastAddress(test.addr); got != test.expected {
				t.Errorf("got header.IsV6LinkLocalMulticastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}

func TestIsV6LinkLocalUnicastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     tcpip.Address
		expected bool
	}{
		{
			name:     "Valid Link Local Unicast",
			addr:     linkLocalAddr,
			expected: true,
		},
		{
			name:     "Link Local Multicast",
			addr:     linkLocalMulticastAddr,
			expected: false,
		},
		{
			name:     "Unique Local",
			addr:     uniqueLocalAddr1,
			expected: false,
		},
		{
			name:     "Global",
			addr:     globalAddr,
			expected: false,
		},
		{
			name:     "IPv4 Link Local",
			addr:     "\xa9\xfe\x00\x01",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV6LinkLocalUnicastAddress(test.addr); got != test.expected {
				t.Errorf("got header.IsV6LinkLocalUnicastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}

func TestScopeForIPv6Address(t *testing.T) {
	tests := []struct {
		name  string
		addr  tcpip.Address
		scope header.IPv6AddressScope
		err   tcpip.Error
	}{
		{
			name:  "Unique Local",
			addr:  uniqueLocalAddr1,
			scope: header.GlobalScope,
			err:   nil,
		},
		{
			name:  "Link Local Unicast",
			addr:  linkLocalAddr,
			scope: header.LinkLocalScope,
			err:   nil,
		},
		{
			name:  "Link Local Multicast",
			addr:  linkLocalMulticastAddr,
			scope: header.LinkLocalScope,
			err:   nil,
		},
		{
			name:  "Global",
			addr:  globalAddr,
			scope: header.GlobalScope,
			err:   nil,
		},
		{
			name:  "IPv4",
			addr:  "\x01\x02\x03\x04",
			scope: header.GlobalScope,
			err:   tcpip.ErrBadAddress,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := header.ScopeForIPv6Address(test.addr)
			if diff := cmp.Diff(test.err, err); diff != "" {
				t.Errorf("unexpected error from header.IsV6UniqueLocalAddress(%s), (-want, +got):\n%s", test.addr, diff)
			}
			if got != test.scope {
				t.Errorf("got header.IsV6UniqueLocalAddress(%s) = (%d, _), want = (%d, _)", test.addr, got, test.scope)
			}
		})
	}
}

func TestSolicitedNodeAddr(t *testing.T) {
	tests := []struct {
		addr tcpip.Address
		want tcpip.Address
	}{
		{
			addr: "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xa0",
			want: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x0e\x0f\xa0",
		},
		{
			addr: "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\xdd\x0e\x0f\xa0",
			want: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x0e\x0f\xa0",
		},
		{
			addr: "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\xdd\x01\x02\x03",
			want: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x01\x02\x03",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.addr), func(t *testing.T) {
			if got := header.SolicitedNodeAddr(test.addr); got != test.want {
				t.Fatalf("got header.SolicitedNodeAddr(%s) = %s, want = %s", test.addr, got, test.want)
			}
		})
	}
}

func TestV6MulticastScope(t *testing.T) {
	tests := []struct {
		addr tcpip.Address
		want header.IPv6MulticastScope
	}{
		{
			addr: "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6Reserved0MulticastScope,
		},
		{
			addr: "\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6InterfaceLocalMulticastScope,
		},
		{
			addr: "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6LinkLocalMulticastScope,
		},
		{
			addr: "\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6RealmLocalMulticastScope,
		},
		{
			addr: "\xff\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6AdminLocalMulticastScope,
		},
		{
			addr: "\xff\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6SiteLocalMulticastScope,
		},
		{
			addr: "\xff\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(6),
		},
		{
			addr: "\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(7),
		},
		{
			addr: "\xff\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6OrganizationLocalMulticastScope,
		},
		{
			addr: "\xff\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(9),
		},
		{
			addr: "\xff\x0a\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(10),
		},
		{
			addr: "\xff\x0b\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(11),
		},
		{
			addr: "\xff\x0c\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(12),
		},
		{
			addr: "\xff\x0d\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6MulticastScope(13),
		},
		{
			addr: "\xff\x0e\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6GlobalMulticastScope,
		},
		{
			addr: "\xff\x0f\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
			want: header.IPv6ReservedFMulticastScope,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.addr), func(t *testing.T) {
			if got := header.V6MulticastScope(test.addr); got != test.want {
				t.Fatalf("got header.V6MulticastScope(%s) = %d, want = %d", test.addr, got, test.want)
			}
		})
	}
}
