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

package tcpip

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLimitedWriter_Write(t *testing.T) {
	var b bytes.Buffer
	l := LimitedWriter{
		W: &b,
		N: 5,
	}
	if n, err := l.Write([]byte{0, 1, 2}); err != nil {
		t.Errorf("got l.Write(3/5) = (_, %s), want nil", err)
	} else if n != 3 {
		t.Errorf("got l.Write(3/5) = (%d, _), want 3", n)
	}
	if n, err := l.Write([]byte{3, 4, 5}); err != io.ErrShortWrite {
		t.Errorf("got l.Write(3/2) = (_, %s), want io.ErrShortWrite", err)
	} else if n != 2 {
		t.Errorf("got l.Write(3/2) = (%d, _), want 2", n)
	}
	if l.N != 0 {
		t.Errorf("got l.N = %d, want 0", l.N)
	}
	l.N = 1
	if n, err := l.Write([]byte{5}); err != nil {
		t.Errorf("got l.Write(1/1) = (_, %s), want nil", err)
	} else if n != 1 {
		t.Errorf("got l.Write(1/1) = (%d, _), want 1", n)
	}
	if diff := cmp.Diff(b.Bytes(), []byte{0, 1, 2, 3, 4, 5}); diff != "" {
		t.Errorf("%T wrote incorrect data: (-want +got):\n%s", l, diff)
	}
}

func TestSubnetContains(t *testing.T) {
	tests := []struct {
		s    Address
		m    AddressMask
		a    Address
		want bool
	}{
		{"\xa0", "\xf0", "\x90", false},
		{"\xa0", "\xf0", "\xa0", true},
		{"\xa0", "\xf0", "\xa5", true},
		{"\xa0", "\xf0", "\xaf", true},
		{"\xa0", "\xf0", "\xb0", false},
		{"\xa0", "\xf0", "", false},
		{"\xa0", "\xf0", "\xa0\x00", false},
		{"\xc2\x80", "\xff\xf0", "\xc2\x80", true},
		{"\xc2\x80", "\xff\xf0", "\xc2\x00", false},
		{"\xc2\x00", "\xff\xf0", "\xc2\x00", true},
		{"\xc2\x00", "\xff\xf0", "\xc2\x80", false},
	}
	for _, tt := range tests {
		s, err := NewSubnet(tt.s, tt.m)
		if err != nil {
			t.Errorf("NewSubnet(%v, %v) = %v", tt.s, tt.m, err)
			continue
		}
		if got := s.Contains(tt.a); got != tt.want {
			t.Errorf("Subnet(%v).Contains(%v) = %v, want %v", s, tt.a, got, tt.want)
		}
	}
}

func TestSubnetBits(t *testing.T) {
	tests := []struct {
		a     AddressMask
		want1 int
		want0 int
	}{
		{"\x00", 0, 8},
		{"\x00\x00", 0, 16},
		{"\x36", 0, 8},
		{"\x5c", 0, 8},
		{"\x5c\x5c", 0, 16},
		{"\x5c\x36", 0, 16},
		{"\x36\x5c", 0, 16},
		{"\x36\x36", 0, 16},
		{"\xff", 8, 0},
		{"\xff\xff", 16, 0},
	}
	for _, tt := range tests {
		s := &Subnet{mask: tt.a}
		got1, got0 := s.Bits()
		if got1 != tt.want1 || got0 != tt.want0 {
			t.Errorf("Subnet{mask: %x}.Bits() = %d, %d, want %d, %d", tt.a, got1, got0, tt.want1, tt.want0)
		}
	}
}

func TestSubnetPrefix(t *testing.T) {
	tests := []struct {
		a    AddressMask
		want int
	}{
		{"\x00", 0},
		{"\x00\x00", 0},
		{"\x36", 0},
		{"\x86", 1},
		{"\xc5", 2},
		{"\xff\x00", 8},
		{"\xff\x36", 8},
		{"\xff\x8c", 9},
		{"\xff\xc8", 10},
		{"\xff", 8},
		{"\xff\xff", 16},
	}
	for _, tt := range tests {
		s := &Subnet{mask: tt.a}
		got := s.Prefix()
		if got != tt.want {
			t.Errorf("Subnet{mask: %x}.Bits() = %d want %d", tt.a, got, tt.want)
		}
	}
}

func TestSubnetCreation(t *testing.T) {
	tests := []struct {
		a    Address
		m    AddressMask
		want error
	}{
		{"\xa0", "\xf0", nil},
		{"\xa0\xa0", "\xf0", errSubnetLengthMismatch},
		{"\xaa", "\xf0", errSubnetAddressMasked},
		{"", "", nil},
	}
	for _, tt := range tests {
		if _, err := NewSubnet(tt.a, tt.m); err != tt.want {
			t.Errorf("NewSubnet(%v, %v) = %v, want %v", tt.a, tt.m, err, tt.want)
		}
	}
}

func TestAddressString(t *testing.T) {
	for _, want := range []string{
		// Taken from stdlib.
		"2001:db8::123:12:1",
		"2001:db8::1",
		"2001:db8:0:1:0:1:0:1",
		"2001:db8:1:0:1:0:1:0",
		"2001::1:0:0:1",
		"2001:db8:0:0:1::",
		"2001:db8::1:0:0:1",
		"2001:db8::a:b:c:d",

		// Leading zeros.
		"::1",
		// Trailing zeros.
		"8::",
		// No zeros.
		"1:1:1:1:1:1:1:1",
		// Longer sequence is after other zeros, but not at the end.
		"1:0:0:1::1",
		// Longer sequence is at the beginning, shorter sequence is at
		// the end.
		"::1:1:1:0:0",
		// Longer sequence is not at the beginning, shorter sequence is
		// at the end.
		"1::1:1:0:0",
		// Longer sequence is at the beginning, shorter sequence is not
		// at the end.
		"::1:1:0:0:1",
		// Neither sequence is at an end, longer is after shorter.
		"1:0:0:1::1",
		// Shorter sequence is at the beginning, longer sequence is not
		// at the end.
		"0:0:1:1::1",
		// Shorter sequence is at the beginning, longer sequence is at
		// the end.
		"0:0:1:1:1::",
		// Short sequences at both ends, longer one in the middle.
		"0:1:1::1:1:0",
		// Short sequences at both ends, longer one in the middle.
		"0:1::1:0:0",
		// Short sequences at both ends, longer one in the middle.
		"0:0:1::1:0",
		// Longer sequence surrounded by shorter sequences, but none at
		// the end.
		"1:0:1::1:0:1",
	} {
		addr := Address(net.ParseIP(want))
		if got := addr.String(); got != want {
			t.Errorf("Address(%x).String() = '%s', want = '%s'", addr, got, want)
		}
	}
}

func TestStatsString(t *testing.T) {
	got := fmt.Sprintf("%+v", Stats{}.FillIn())

	matchers := []string{
		// Print root-level stats correctly.
		"UnknownProtocolRcvdPackets:0",
		// Print protocol-specific stats correctly.
		"TCP:{ActiveConnectionOpenings:0",
	}

	for _, m := range matchers {
		if !strings.Contains(got, m) {
			t.Errorf("string.Contains(got, %q) = false", m)
		}
	}
	if t.Failed() {
		t.Logf(`got = fmt.Sprintf("%%+v", Stats{}.FillIn()) = %q`, got)
	}
}

func TestAddressWithPrefixSubnet(t *testing.T) {
	tests := []struct {
		addr       Address
		prefixLen  int
		subnetAddr Address
		subnetMask AddressMask
	}{
		{"\xaa\x55\x33\x42", -1, "\x00\x00\x00\x00", "\x00\x00\x00\x00"},
		{"\xaa\x55\x33\x42", 0, "\x00\x00\x00\x00", "\x00\x00\x00\x00"},
		{"\xaa\x55\x33\x42", 1, "\x80\x00\x00\x00", "\x80\x00\x00\x00"},
		{"\xaa\x55\x33\x42", 7, "\xaa\x00\x00\x00", "\xfe\x00\x00\x00"},
		{"\xaa\x55\x33\x42", 8, "\xaa\x00\x00\x00", "\xff\x00\x00\x00"},
		{"\xaa\x55\x33\x42", 24, "\xaa\x55\x33\x00", "\xff\xff\xff\x00"},
		{"\xaa\x55\x33\x42", 31, "\xaa\x55\x33\x42", "\xff\xff\xff\xfe"},
		{"\xaa\x55\x33\x42", 32, "\xaa\x55\x33\x42", "\xff\xff\xff\xff"},
		{"\xaa\x55\x33\x42", 33, "\xaa\x55\x33\x42", "\xff\xff\xff\xff"},
	}
	for _, tt := range tests {
		ap := AddressWithPrefix{Address: tt.addr, PrefixLen: tt.prefixLen}
		gotSubnet := ap.Subnet()
		wantSubnet, err := NewSubnet(tt.subnetAddr, tt.subnetMask)
		if err != nil {
			t.Errorf("NewSubnet(%q, %q) failed: %s", tt.subnetAddr, tt.subnetMask, err)
			continue
		}
		if gotSubnet != wantSubnet {
			t.Errorf("got subnet = %q, want = %q", gotSubnet, wantSubnet)
		}
	}
}

func TestAddressUnspecified(t *testing.T) {
	tests := []struct {
		addr        Address
		unspecified bool
	}{
		{
			addr:        "",
			unspecified: true,
		},
		{
			addr:        "\x00",
			unspecified: true,
		},
		{
			addr:        "\x01",
			unspecified: false,
		},
		{
			addr:        "\x00\x00",
			unspecified: true,
		},
		{
			addr:        "\x01\x00",
			unspecified: false,
		},
		{
			addr:        "\x00\x01",
			unspecified: false,
		},
		{
			addr:        "\x01\x01",
			unspecified: false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("addr=%s", test.addr), func(t *testing.T) {
			if got := test.addr.Unspecified(); got != test.unspecified {
				t.Fatalf("got addr.Unspecified() = %t, want = %t", got, test.unspecified)
			}
		})
	}
}

func TestAddressMatchingPrefix(t *testing.T) {
	tests := []struct {
		addrA  Address
		addrB  Address
		prefix uint8
	}{
		{
			addrA:  "\x01\x01",
			addrB:  "\x01\x01",
			prefix: 16,
		},
		{
			addrA:  "\x01\x01",
			addrB:  "\x01\x00",
			prefix: 15,
		},
		{
			addrA:  "\x01\x01",
			addrB:  "\x81\x00",
			prefix: 0,
		},
		{
			addrA:  "\x01\x01",
			addrB:  "\x01\x80",
			prefix: 8,
		},
		{
			addrA:  "\x01\x01",
			addrB:  "\x02\x80",
			prefix: 6,
		},
	}

	for _, test := range tests {
		if got := test.addrA.MatchingPrefix(test.addrB); got != test.prefix {
			t.Errorf("got (%s).MatchingPrefix(%s) = %d, want = %d", test.addrA, test.addrB, got, test.prefix)
		}
	}
}
