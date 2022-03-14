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

package proc

import (
	"bytes"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/usermem"
)

func newIPv6TestStack() *inet.TestStack {
	s := inet.NewTestStack()
	s.SupportsIPv6Flag = true
	return s
}

func TestIfinet6NoAddresses(t *testing.T) {
	n := &ifinet6{stack: newIPv6TestStack()}
	var buf bytes.Buffer
	n.Generate(contexttest.Context(t), &buf)
	if buf.Len() > 0 {
		t.Errorf("n.Generate() generated = %v, want = %v", buf.Bytes(), []byte{})
	}
}

func TestIfinet6(t *testing.T) {
	s := newIPv6TestStack()
	s.InterfacesMap[1] = inet.Interface{Name: "eth0"}
	s.InterfaceAddrsMap[1] = []inet.InterfaceAddr{
		{
			Family:    linux.AF_INET6,
			PrefixLen: 128,
			Addr:      []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
		},
	}
	s.InterfacesMap[2] = inet.Interface{Name: "eth1"}
	s.InterfaceAddrsMap[2] = []inet.InterfaceAddr{
		{
			Family:    linux.AF_INET6,
			PrefixLen: 128,
			Addr:      []byte("\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
		},
	}
	want := map[string]struct{}{
		"000102030405060708090a0b0c0d0e0f 01 80 00 00     eth0\n": {},
		"101112131415161718191a1b1c1d1e1f 02 80 00 00     eth1\n": {},
	}

	n := &ifinet6{stack: s}
	contents := n.contents()
	if len(contents) != len(want) {
		t.Errorf("Got len(n.contents()) = %d, want = %d", len(contents), len(want))
	}
	got := map[string]struct{}{}
	for _, l := range contents {
		got[l] = struct{}{}
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got n.contents() = %v, want = %v", got, want)
	}
}

// TestIPForwarding tests the implementation of
// /proc/sys/net/ipv4/ip_forwarding
func TestConfigureIPForwarding(t *testing.T) {
	ctx := context.Background()
	s := inet.NewTestStack()

	var cases = []struct {
		comment string
		initial bool
		str     string
		final   bool
	}{
		{
			comment: `Forwarding is disabled; write 1 and enable forwarding`,
			initial: false,
			str:     "1",
			final:   true,
		},
		{
			comment: `Forwarding is disabled; write 0 and disable forwarding`,
			initial: false,
			str:     "0",
			final:   false,
		},
		{
			comment: `Forwarding is enabled; write 1 and enable forwarding`,
			initial: true,
			str:     "1",
			final:   true,
		},
		{
			comment: `Forwarding is enabled; write 0 and disable forwarding`,
			initial: true,
			str:     "0",
			final:   false,
		},
		{
			comment: `Forwarding is disabled; write 2404 and enable forwarding`,
			initial: false,
			str:     "2404",
			final:   true,
		},
		{
			comment: `Forwarding is enabled; write 2404 and enable forwarding`,
			initial: true,
			str:     "2404",
			final:   true,
		},
	}
	for _, c := range cases {
		t.Run(c.comment, func(t *testing.T) {
			s.IPForwarding = c.initial

			file := &ipForwarding{stack: s, enabled: c.initial}

			// Write the values.
			src := usermem.BytesIOSequence([]byte(c.str))
			if n, err := file.Write(ctx, nil, src, 0); n != int64(len(c.str)) || err != nil {
				t.Errorf("file.Write(ctx, nil, %q, 0) = (%d, %v); want (%d, nil)", c.str, n, err, len(c.str))
			}

			// Read the values from the stack and check them.
			if got, want := s.IPForwarding, c.final; got != want {
				t.Errorf("s.IPForwarding incorrect; got: %v, want: %v", got, want)
			}
		})
	}
}
