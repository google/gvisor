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

package testutil

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// Who tests the testutils?

func TestMustParse4(t *testing.T) {
	tcs := []struct {
		str         string
		addr        tcpip.Address
		shouldPanic bool
	}{
		{
			str:  "127.0.0.1",
			addr: "\x7f\x00\x00\x01",
		}, {
			str:         "",
			shouldPanic: true,
		}, {
			str:         "fe80::1",
			shouldPanic: true,
		}, {
			// In an ideal world this panics too, but net.IP
			// doesn't distinguish between IPv4 and IPv4-mapped
			// addresses.
			str:  "::ffff:0.0.0.1",
			addr: "\x00\x00\x00\x01",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.str, func(t *testing.T) {
			if tc.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("panic expected, but did not occur")
					}
				}()
			}
			if got := MustParse4(tc.str); got != tc.addr {
				t.Errorf("got MustParse4(%s) = %s, want = %s", tc.str, got, tc.addr)
			}
		})
	}
}

func TestMustParse6(t *testing.T) {
	tcs := []struct {
		str         string
		addr        tcpip.Address
		shouldPanic bool
	}{
		{
			// In an ideal world this panics too, but net.IP
			// doesn't distinguish between IPv4 and IPv4-mapped
			// addresses.
			str:  "127.0.0.1",
			addr: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x7f\x00\x00\x01",
		}, {
			str:         "",
			shouldPanic: true,
		}, {
			str:  "fe80::1",
			addr: "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
		}, {
			str:  "::ffff:0.0.0.1",
			addr: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x01",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.str, func(t *testing.T) {
			if tc.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("panic expected, but did not occur")
					}
				}()
			}
			if got := MustParse6(tc.str); got != tc.addr {
				t.Errorf("got MustParse6(%s) = %s, want = %s", tc.str, got, tc.addr)
			}
		})
	}
}
