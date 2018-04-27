// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcpip

import (
	"testing"
)

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
		{"\x36", 4, 4},
		{"\x5c", 4, 4},
		{"\x5c\x5c", 8, 8},
		{"\x5c\x36", 8, 8},
		{"\x36\x5c", 8, 8},
		{"\x36\x36", 8, 8},
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

func TestRouteMatch(t *testing.T) {
	tests := []struct {
		d    Address
		m    Address
		a    Address
		want bool
	}{
		{"\xc2\x80", "\xff\xf0", "\xc2\x80", true},
		{"\xc2\x80", "\xff\xf0", "\xc2\x00", false},
		{"\xc2\x00", "\xff\xf0", "\xc2\x00", true},
		{"\xc2\x00", "\xff\xf0", "\xc2\x80", false},
	}
	for _, tt := range tests {
		r := Route{Destination: tt.d, Mask: tt.m}
		if got := r.Match(tt.a); got != tt.want {
			t.Errorf("Route(%v).Match(%v) = %v, want %v", r, tt.a, got, tt.want)
		}
	}
}
