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
	"io"
	"net/netip"
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

func TestAddressMatchingPrefix(t *testing.T) {
	tests := []struct {
		addrA  netip.Addr
		addrB  netip.Addr
		prefix uint8
	}{
		{
			addrA:  netip.AddrFrom4([4]byte{1, 1}),
			addrB:  netip.AddrFrom4([4]byte{1, 1}),
			prefix: 32,
		},
		{
			addrA:  netip.AddrFrom4([4]byte{1, 1}),
			addrB:  netip.AddrFrom4([4]byte{1, 0}),
			prefix: 15,
		},
		{
			addrA:  netip.AddrFrom4([4]byte{1, 1}),
			addrB:  netip.AddrFrom4([4]byte{129, 0}),
			prefix: 0,
		},
		{
			addrA:  netip.AddrFrom4([4]byte{1, 1}),
			addrB:  netip.AddrFrom4([4]byte{1, 128}),
			prefix: 8,
		},
		{
			addrA:  netip.AddrFrom4([4]byte{1, 1}),
			addrB:  netip.AddrFrom4([4]byte{2, 128}),
			prefix: 6,
		},
		{addrA: netip.Addr{}, addrB: netip.Addr{}, prefix: 0},
		{addrA: netip.AddrFrom16([16]byte{15: 1}), addrB: netip.AddrFrom16([16]byte{15: 1}), prefix: 128},
		{addrA: netip.AddrFrom16([16]byte{15: 1}), addrB: netip.AddrFrom16([16]byte{15: 3}), prefix: 126},
	}

	for _, test := range tests {
		if got := MatchingPrefix(test.addrA, test.addrB); got != test.prefix {
			t.Errorf("got MatchingPrefix(%s, %s) = %d, want = %d", test.addrA, test.addrB, got, test.prefix)
		}
	}
}
