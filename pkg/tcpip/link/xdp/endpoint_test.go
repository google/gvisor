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
package xdp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestSetAddress(t *testing.T) {
	ep := &endpoint{
		addr: "xyz",
	}
	addrs := []tcpip.LinkAddress{"abc", "def"}
	for _, addr := range addrs {
		ep.SetLinkAddress(addr)

		if want, v := addr, ep.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}
