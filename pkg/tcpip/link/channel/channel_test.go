// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package channel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestSetLinkAddress(t *testing.T) {
	addrs := []tcpip.LinkAddress{"abc", "def"}
	size, mtu, linkAddr := 10, uint32(2000), tcpip.LinkAddress("xyz")
	e := New(size, mtu, linkAddr)
	defer e.Close()
	for _, addr := range addrs {
		e.SetLinkAddress(addr)

		if want, v := addr, e.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}

func TestSetMTU(t *testing.T) {
	expectedMTU := []uint32{1000, 3000}
	size, mtu := 10, uint32(2000)
	e := New(size, mtu, tcpip.LinkAddress("xyz"))
	defer e.Close()
	for _, mtu := range expectedMTU {
		e.SetMTU(mtu)

		if want, v := mtu, e.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}
