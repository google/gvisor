// Copyright 2018 Google LLC
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
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
)

func newIPv6TestStack() *inet.TestStack {
	s := inet.NewTestStack()
	s.SupportsIPv6Flag = true
	return s
}

func TestIfinet6NoAddresses(t *testing.T) {
	n := &ifinet6{s: newIPv6TestStack()}
	if got := n.contents(); got != nil {
		t.Errorf("Got n.contents() = %v, want = %v", got, nil)
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

	n := &ifinet6{s: s}
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
