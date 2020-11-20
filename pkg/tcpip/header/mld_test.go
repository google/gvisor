// Copyright 2020 The gVisor Authors.
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
	"encoding/binary"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestMLD(t *testing.T) {
	b := []byte{
		// Maximum Response Delay
		0, 0,

		// Reserved
		0, 0,

		// MulticastAddress
		1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
	}

	const maxRespDelay = 513
	binary.BigEndian.PutUint16(b, maxRespDelay)

	mld := MLD(b)

	if got, want := mld.MaximumResponseDelay(), maxRespDelay*time.Millisecond; got != want {
		t.Errorf("got mld.MaximumResponseDelay() = %s, want = %s", got, want)
	}

	const newMaxRespDelay = 1234
	mld.SetMaximumResponseDelay(newMaxRespDelay)
	if got, want := mld.MaximumResponseDelay(), newMaxRespDelay*time.Millisecond; got != want {
		t.Errorf("got mld.MaximumResponseDelay() = %s, want = %s", got, want)
	}

	if got, want := mld.MulticastAddress(), tcpip.Address([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}); got != want {
		t.Errorf("got mld.MulticastAddress() = %s, want = %s", got, want)
	}

	multicastAddress := tcpip.Address([]byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0})
	mld.SetMulticastAddress(multicastAddress)
	if got := mld.MulticastAddress(); got != multicastAddress {
		t.Errorf("got mld.MulticastAddress() = %s, want = %s", got, multicastAddress)
	}
}
