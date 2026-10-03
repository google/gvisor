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
	for _, tc := range []struct {
		name   string
		family int
		skType linux.SockType
		port   uint16
		want   bool
	}{
		// An ephemeral port request is always allowed: the kernel picks the
		// port, and it picks an unprivileged one.
		{"ephemeral port, stream", linux.AF_INET, linux.SOCK_STREAM, 0, false},
		{"ephemeral port, datagram", linux.AF_INET6, linux.SOCK_DGRAM, 0, false},

		// Privileged ports on inet stream and datagram sockets.
		{"port 1, v4 stream", linux.AF_INET, linux.SOCK_STREAM, 1, true},
		{"port 80, v4 stream", linux.AF_INET, linux.SOCK_STREAM, 80, true},
		{"port 80, v6 stream", linux.AF_INET6, linux.SOCK_STREAM, 80, true},
		{"port 53, v4 datagram", linux.AF_INET, linux.SOCK_DGRAM, 53, true},
		{"port 53, v6 datagram", linux.AF_INET6, linux.SOCK_DGRAM, 53, true},

		// The boundary: 1024 is the first unprivileged port.
		{"port 1023, last privileged", linux.AF_INET, linux.SOCK_STREAM, 1023, true},
		{"port 1024, first unprivileged", linux.AF_INET, linux.SOCK_STREAM, 1024, false},
		{"port 8080", linux.AF_INET, linux.SOCK_STREAM, 8080, false},
		{"port 65535", linux.AF_INET, linux.SOCK_STREAM, 65535, false},

		// Raw sockets are gated by CAP_NET_RAW at creation, not here.
		{"port 80, raw", linux.AF_INET, linux.SOCK_RAW, 80, false},

		// Other families do not carry transport ports.
		{"AF_PACKET", linux.AF_PACKET, linux.SOCK_DGRAM, 80, false},
		{"AF_UNIX", linux.AF_UNIX, linux.SOCK_STREAM, 80, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := portRequiresBindService(tc.family, tc.skType, tc.port); got != tc.want {
				t.Errorf("portRequiresBindService(%d, %d, %d) = %t, want %t",
					tc.family, tc.skType, tc.port, got, tc.want)
			}
		})
	}
}
