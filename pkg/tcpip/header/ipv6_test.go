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

package header_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const linkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")

func TestEthernetAdddressToModifiedEUI64(t *testing.T) {
	expectedIID := [header.IIDSize]byte{0, 2, 3, 255, 254, 4, 5, 6}

	if diff := cmp.Diff(expectedIID, header.EthernetAddressToModifiedEUI64(linkAddr)); diff != "" {
		t.Errorf("EthernetAddressToModifiedEUI64(%s) mismatch (-want +got):\n%s", linkAddr, diff)
	}

	var buf [header.IIDSize]byte
	header.EthernetAdddressToModifiedEUI64IntoBuf(linkAddr, buf[:])
	if diff := cmp.Diff(expectedIID, buf); diff != "" {
		t.Errorf("EthernetAddressToModifiedEUI64IntoBuf(%s, _) mismatch (-want +got):\n%s", linkAddr, diff)
	}
}

func TestLinkLocalAddr(t *testing.T) {
	if got, want := header.LinkLocalAddr(linkAddr), tcpip.Address("\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x02\x03\xff\xfe\x04\x05\x06"); got != want {
		t.Errorf("got LinkLocalAddr(%s) = %s, want = %s", linkAddr, got, want)
	}
}
