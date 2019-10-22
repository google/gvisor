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

package header

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestIsValidUnicastEthernetAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     tcpip.LinkAddress
		expected bool
	}{
		{
			"Nil",
			tcpip.LinkAddress([]byte(nil)),
			false,
		},
		{
			"Empty",
			tcpip.LinkAddress(""),
			false,
		},
		{
			"InvalidLength",
			tcpip.LinkAddress("\x01\x02\x03"),
			false,
		},
		{
			"Unspecified",
			unspecifiedEthernetAddress,
			false,
		},
		{
			"Multicast",
			tcpip.LinkAddress("\x01\x02\x03\x04\x05\x06"),
			false,
		},
		{
			"Valid",
			tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06"),
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsValidUnicastEthernetAddress(test.addr); got != test.expected {
				t.Fatalf("got IsValidUnicastEthernetAddress = %t, want = %t", got, test.expected)
			}
		})
	}
}
