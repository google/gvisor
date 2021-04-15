// Copyright 2021 The gVisor Authors.
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

// Package testutil provides helper functions for netstack unit tests.
package testutil

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// MustParse4 parses an IPv4 string (e.g. "192.168.1.1") into a tcpip.Address.
// Passing an IPv4-mapped IPv6 address will yield only the 4 IPv4 bytes.
func MustParse4(addr string) tcpip.Address {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		panic(fmt.Sprintf("Parse4 expects IPv4 addresses, but was passed %q", addr))
	}
	return tcpip.Address(ip)
}

// MustParse6 parses an IPv6 string (e.g. "fe80::1") into a tcpip.Address. Passing
// an IPv4 address will yield an IPv4-mapped IPv6 address.
func MustParse6(addr string) tcpip.Address {
	ip := net.ParseIP(addr).To16()
	if ip == nil {
		panic(fmt.Sprintf("Parse6 was passed malformed address %q", addr))
	}
	return tcpip.Address(ip)
}
