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

package header_test

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/prependable"
)

func TestIPv4OptionsSerializer(t *testing.T) {
	optCases := []struct {
		name   string
		option []header.IPv4SerializableOption
		expect []byte
	}{
		{
			name: "NOP",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableNOPOption{},
			},
			expect: []byte{1, 0, 0, 0},
		},
		{
			name: "ListEnd",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableListEndOption{},
			},
			expect: []byte{0, 0, 0, 0},
		},
		{
			name: "RouterAlert",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableRouterAlertOption{},
			},
			expect: []byte{148, 4, 0, 0},
		}, {
			name: "NOP and RouterAlert",
			option: []header.IPv4SerializableOption{
				&header.IPv4SerializableNOPOption{},
				&header.IPv4SerializableRouterAlertOption{},
			},
			expect: []byte{1, 148, 4, 0, 0, 0, 0, 0},
		},
	}

	for _, opt := range optCases {
		t.Run(opt.name, func(t *testing.T) {
			s := header.IPv4OptionsSerializer(opt.option)
			l := s.Length()
			if got := len(opt.expect); got != int(l) {
				t.Fatalf("s.Length() = %d, want = %d", got, l)
			}
			b := make([]byte, l)
			for i := range b {
				// Fill the buffer with full bytes to ensure padding is being set
				// correctly.
				b[i] = 0xFF
			}
			if serializedLength := s.Serialize(b); serializedLength != l {
				t.Fatalf("s.Serialize(_) = %d, want %d", serializedLength, l)
			}
			if diff := cmp.Diff(opt.expect, b); diff != "" {
				t.Errorf("mismatched serialized option (-want +got):\n%s", diff)
			}
		})
	}
}

// TestIPv4Encode checks that ipv4.Encode correctly fills out the requested
// fields when options are supplied.
func TestIPv4EncodeOptions(t *testing.T) {
	tests := []struct {
		name           string
		numberOfNops   int
		encodedOptions header.IPv4Options // reply should look like this
		wantIHL        int
	}{
		{
			name:    "valid no options",
			wantIHL: header.IPv4MinimumSize,
		},
		{
			name:           "one byte options",
			numberOfNops:   1,
			encodedOptions: header.IPv4Options{1, 0, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "two byte options",
			numberOfNops:   2,
			encodedOptions: header.IPv4Options{1, 1, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "three byte options",
			numberOfNops:   3,
			encodedOptions: header.IPv4Options{1, 1, 1, 0},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "four byte options",
			numberOfNops:   4,
			encodedOptions: header.IPv4Options{1, 1, 1, 1},
			wantIHL:        header.IPv4MinimumSize + 4,
		},
		{
			name:           "five byte options",
			numberOfNops:   5,
			encodedOptions: header.IPv4Options{1, 1, 1, 1, 1, 0, 0, 0},
			wantIHL:        header.IPv4MinimumSize + 8,
		},
		{
			name:         "thirty nine byte options",
			numberOfNops: 39,
			encodedOptions: header.IPv4Options{
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 0,
			},
			wantIHL: header.IPv4MinimumSize + 40,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serializeOpts := header.IPv4OptionsSerializer(make([]header.IPv4SerializableOption, test.numberOfNops))
			for i := range serializeOpts {
				serializeOpts[i] = &header.IPv4SerializableNOPOption{}
			}
			paddedOptionLength := serializeOpts.Length()
			ipHeaderLength := int(header.IPv4MinimumSize + paddedOptionLength)
			if ipHeaderLength > header.IPv4MaximumHeaderSize {
				t.Fatalf("IP header length too large: got = %d, want <= %d ", ipHeaderLength, header.IPv4MaximumHeaderSize)
			}
			totalLen := uint16(ipHeaderLength)
			hdr := prependable.New(int(totalLen))
			ip := header.IPv4(hdr.Prepend(ipHeaderLength))
			// To check the padding works, poison the last byte of the options space.
			if paddedOptionLength != serializeOpts.Length() {
				ip.SetHeaderLength(uint8(ipHeaderLength))
				ip.Options()[paddedOptionLength-1] = 0xff
				ip.SetHeaderLength(0)
			}
			ip.Encode(&header.IPv4Fields{
				Options: serializeOpts,
			})
			options := ip.Options()
			wantOptions := test.encodedOptions
			if got, want := int(ip.HeaderLength()), test.wantIHL; got != want {
				t.Errorf("got IHL of %d, want %d", got, want)
			}

			// cmp.Diff does not consider nil slices equal to empty slices, but we do.
			if len(wantOptions) == 0 && len(options) == 0 {
				return
			}

			if diff := cmp.Diff(wantOptions, options); diff != "" {
				t.Errorf("options mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIsV4LinkLocalUnicastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "Valid (lowest)",
			addr:     "\xa9\xfe\x00\x00",
			expected: true,
		},
		{
			name:     "Valid (highest)",
			addr:     "\xa9\xfe\xff\xff",
			expected: true,
		},
		{
			name:     "Invalid (before subnet)",
			addr:     "\xa9\xfd\xff\xff",
			expected: false,
		},
		{
			name:     "Invalid (after subnet)",
			addr:     "\xa9\xff\x00\x00",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV4LinkLocalUnicastAddress(netip.AddrFrom4([4]byte([]byte(test.addr)))); got != test.expected {
				t.Errorf("got header.IsV4LinkLocalUnicastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}

func TestIsV4LinkLocalMulticastAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "Valid (lowest)",
			addr:     "\xe0\x00\x00\x00",
			expected: true,
		},
		{
			name:     "Valid (highest)",
			addr:     "\xe0\x00\x00\xff",
			expected: true,
		},
		{
			name:     "Invalid (before subnet)",
			addr:     "\xdf\xff\xff\xff",
			expected: false,
		},
		{
			name:     "Invalid (after subnet)",
			addr:     "\xe0\x00\x01\x00",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := header.IsV4LinkLocalMulticastAddress(netip.AddrFrom4([4]byte([]byte(test.addr)))); got != test.expected {
				t.Errorf("got header.IsV4LinkLocalMulticastAddress(%s) = %t, want = %t", test.addr, got, test.expected)
			}
		})
	}
}

func TestIPv4SubnetBroadcast(t *testing.T) {
	for _, test := range []struct {
		prefix    string
		last      string
		broadcast bool
	}{
		{"0.0.0.0/0", "255.255.255.255", true},
		{"192.0.2.129/24", "192.0.2.255", true},
		{"192.0.2.129/25", "192.0.2.255", true},
		{"192.0.2.128/30", "192.0.2.131", true},
		{"192.0.2.128/31", "192.0.2.129", false},
		{"192.0.2.128/32", "192.0.2.128", false},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(test.prefix)
			last := netip.MustParseAddr(test.last)
			if got := header.IPv4SubnetBroadcast(prefix); got != last {
				t.Errorf("IPv4SubnetBroadcast(%s) = %s, want %s", prefix, got, last)
			}
			if got := header.IsIPv4SubnetBroadcast(prefix, last); got != test.broadcast {
				t.Errorf("IsIPv4SubnetBroadcast(%s, %s) = %t, want %t", prefix, last, got, test.broadcast)
			}
			for _, addr := range []netip.Addr{prefix.Addr(), last.Next(), netip.AddrFrom16(last.As16()), {}} {
				if addr == last {
					continue
				}
				if header.IsIPv4SubnetBroadcast(prefix, addr) {
					t.Errorf("IsIPv4SubnetBroadcast(%s, %s) = true, want false", prefix, addr)
				}
			}
		})
	}
}
