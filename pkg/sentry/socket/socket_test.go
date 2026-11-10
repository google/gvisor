// Copyright 2026 The gVisor Authors.
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

package socket

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestUnmarshalSockAddrLinkShort(t *testing.T) {
	want := linux.SockAddrLink{
		Family:          unix.AF_PACKET,
		Protocol:        0x0008,
		InterfaceIndex:  2,
		ARPHardwareType: 1,
		PacketType:      0,
		HardwareAddrLen: 6,
		HardwareAddr:    [8]byte{1, 2, 3, 4, 5, 6},
	}
	full := make([]byte, want.SizeBytes())
	want.MarshalUnsafe(full)

	// Older kernels' packet_recvmsg set the address length to
	// offsetof(struct sockaddr_ll, sll_addr) + sll_halen, which is 12 + 6 = 18
	// bytes for Ethernet, instead of the full 20-byte struct. Newer kernels
	// round it up to sizeof(struct sockaddr_ll).
	const ethernetLen = 18
	for _, n := range []int{0, 2, 14, ethernetLen, len(full), len(full) + 4} {
		data := make([]byte, n)
		copy(data, full)
		got, ok := UnmarshalSockAddr(unix.AF_PACKET, data).(*linux.SockAddrLink)
		if !ok {
			t.Fatalf("UnmarshalSockAddr(AF_PACKET, %d bytes) returned %T, want *linux.SockAddrLink", n, got)
		}
		var exp linux.SockAddrLink
		expBuf := make([]byte, exp.SizeBytes())
		copy(expBuf, data)
		exp.UnmarshalUnsafe(expBuf)
		if *got != exp {
			t.Errorf("UnmarshalSockAddr(AF_PACKET, %d bytes) = %+v, want %+v", n, *got, exp)
		}
		if n >= ethernetLen && *got != want {
			t.Errorf("UnmarshalSockAddr(AF_PACKET, %d bytes) = %+v, want %+v", n, *got, want)
		}
	}
}

func TestUnmarshalSockAddrShortAllFamilies(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_UNIX, unix.AF_NETLINK, unix.AF_PACKET} {
		// A family-only address must not panic.
		data := []byte{byte(family), byte(family >> 8)}
		addr := UnmarshalSockAddr(family, data)
		if addr == nil {
			t.Errorf("UnmarshalSockAddr(%d, 2 bytes) = nil", family)
		}
	}
}
