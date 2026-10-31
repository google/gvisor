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
	"net/netip"
	"testing"
)

// Who tests the testutils?

func TestMustParse4(t *testing.T) {
	tcs := []struct {
		str         string
		addr        string
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
				MustParse4(tc.str)
				return
			}
			if got := MustParse4(tc.str); got != netip.AddrFrom4([4]byte([]byte(tc.addr))) {
				t.Errorf("got MustParse4(%s) = %s, want = %s", tc.str, got, tc.addr)
			}
		})
	}
}

func TestMustParse6(t *testing.T) {
	tcs := []struct {
		str         string
		addr        string
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
				MustParse6(tc.str)
				return
			}
			if got := MustParse6(tc.str); got != netip.AddrFrom16([16]byte([]byte(tc.addr))) {
				t.Errorf("got MustParse6(%s) = %s, want = %s", tc.str, got, tc.addr)
			}
		})
	}
}

func TestMustParseSubnet4(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{"192.0.2.129/24", "192.0.2.0/24"},
		{"::ffff:192.0.2.129/24", "192.0.2.0/24"},
		{"192.0.2.129/32", "192.0.2.129/32"},
		{"192.0.2.129/33", ""},
		{"2001:db8::/32", ""},
		{"::ffff:192.0.2.129/120", ""},
		{"192.0.2.129", ""},
	} {
		t.Run(test.input, func(t *testing.T) {
			if test.want == "" {
				defer func() {
					if recover() == nil {
						t.Error("MustParseSubnet4 did not panic")
					}
				}()
			}
			got := MustParseSubnet4(test.input)
			if test.want != "" && got != netip.MustParsePrefix(test.want) {
				t.Errorf("MustParseSubnet4(%q) = %s, want %s", test.input, got, test.want)
			}
		})
	}
}
