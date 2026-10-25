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

package netstack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestPortRequiresBindService(t *testing.T) {
	// prot is the Linux default unprivileged-port boundary, used unless a case
	// overrides it.
	const prot = uint16(linux.PROT_SOCK)
	for _, tc := range []struct {
		name     string
		family   int
		skType   linux.SockType
		protocol int
		port     uint16
		start    uint16
		want     bool
	}{
		// An ephemeral port request is always allowed: the kernel picks the
		// port, and it picks an unprivileged one.
		{"ephemeral port, stream", linux.AF_INET, linux.SOCK_STREAM, 0, 0, prot, false},
		{"ephemeral port, datagram", linux.AF_INET6, linux.SOCK_DGRAM, 0, 0, prot, false},

		// Privileged ports on inet stream and datagram sockets.
		{"port 1, v4 stream", linux.AF_INET, linux.SOCK_STREAM, 0, 1, prot, true},
		{"port 80, v4 stream", linux.AF_INET, linux.SOCK_STREAM, 0, 80, prot, true},
		{"port 80, v6 stream", linux.AF_INET6, linux.SOCK_STREAM, 0, 80, prot, true},
		{"port 53, v4 datagram", linux.AF_INET, linux.SOCK_DGRAM, 0, 53, prot, true},
		{"port 53, v6 datagram", linux.AF_INET6, linux.SOCK_DGRAM, 0, 53, prot, true},

		// An explicit TCP/UDP protocol is treated the same as the default.
		{"port 443, v4 stream IPPROTO_TCP", linux.AF_INET, linux.SOCK_STREAM, linux.IPPROTO_TCP, 443, prot, true},
		{"port 53, v4 datagram IPPROTO_UDP", linux.AF_INET, linux.SOCK_DGRAM, linux.IPPROTO_UDP, 53, prot, true},

		// The boundary: 1024 is the first unprivileged port.
		{"port 1023, last privileged", linux.AF_INET, linux.SOCK_STREAM, 0, 1023, prot, true},
		{"port 1024, first unprivileged", linux.AF_INET, linux.SOCK_STREAM, 0, 1024, prot, false},
		{"port 8080", linux.AF_INET, linux.SOCK_STREAM, 0, 8080, prot, false},
		{"port 65535", linux.AF_INET, linux.SOCK_STREAM, 0, 65535, prot, false},

		// Ping sockets (SOCK_DGRAM + IPPROTO_ICMP/ICMPV6): sin_port is the ICMP
		// Echo identifier, not a transport port. Linux does not require
		// CAP_NET_BIND_SERVICE here, even for an identifier below 1024.
		{"ping v4, low id", linux.AF_INET, linux.SOCK_DGRAM, linux.IPPROTO_ICMP, 80, prot, false},
		{"ping v6, low id", linux.AF_INET6, linux.SOCK_DGRAM, linux.IPPROTO_ICMPV6, 80, prot, false},

		// Raw sockets are gated by CAP_NET_RAW at creation, not here.
		{"port 80, raw", linux.AF_INET, linux.SOCK_RAW, 0, 80, prot, false},

		// Other families do not carry transport ports.
		{"AF_PACKET", linux.AF_PACKET, linux.SOCK_DGRAM, 0, 80, prot, false},
		{"AF_UNIX", linux.AF_UNIX, linux.SOCK_STREAM, 0, 80, prot, false},

		// A boundary of 0 (the Docker/containerd default) makes every port
		// unprivileged, disabling the check.
		{"start 0 disables, port 1", linux.AF_INET, linux.SOCK_STREAM, 0, 1, 0, false},
		{"start 0 disables, port 80", linux.AF_INET, linux.SOCK_STREAM, 0, 80, 0, false},

		// A custom boundary shifts where privilege ends.
		{"start 100, port 99 privileged", linux.AF_INET, linux.SOCK_STREAM, 0, 99, 100, true},
		{"start 100, port 100 unprivileged", linux.AF_INET, linux.SOCK_STREAM, 0, 100, 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := portRequiresBindService(tc.family, tc.skType, tc.protocol, tc.port, tc.start); got != tc.want {
				t.Errorf("portRequiresBindService(%d, %d, %d, %d, %d) = %t, want %t",
					tc.family, tc.skType, tc.protocol, tc.port, tc.start, got, tc.want)
			}
		})
	}
}
