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
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")

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
	if got, want := header.LinkLocalAddr(linkAddr), tcpip.Address("\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x02\x03\xff\xfe\x04\x05\x06"); got != want {
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
			name: "Nil SecretKey",
			prefix: func() tcpip.Subnet {
				addrWithPrefix := tcpip.AddressWithPrefix{
					Address:   "\x01\x02\x03\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
					PrefixLen: header.IIDOffsetInIPv6Address * 8,
				}
				return addrWithPrefix.Subnet()
			}(),
			nicName:    "eth12",
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
			name:       "Nil SecretKey",
			nicName:    "eth12",
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
