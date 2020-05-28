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

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

func TestDisabledRxStatsWhenNICDisabled(t *testing.T) {
	// When the NIC is disabled, the only field that matters is the stats field.
	// This test is limited to stats counter checks.
	nic := NIC{
		stats: makeNICStats(),
	}

	if got := nic.stats.DisabledRx.Packets.Value(); got != 0 {
		t.Errorf("got DisabledRx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.DisabledRx.Bytes.Value(); got != 0 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}

	if t.Failed() {
		t.FailNow()
	}

	nic.DeliverNetworkPacket("", "", 0, PacketBuffer{Data: buffer.View([]byte{1, 2, 3, 4}).ToVectorisedView()})

	if got := nic.stats.DisabledRx.Packets.Value(); got != 1 {
		t.Errorf("got DisabledRx.Packets = %d, want = 1", got)
	}
	if got := nic.stats.DisabledRx.Bytes.Value(); got != 4 {
		t.Errorf("got DisabledRx.Bytes = %d, want = 4", got)
	}
	if got := nic.stats.Rx.Packets.Value(); got != 0 {
		t.Errorf("got Rx.Packets = %d, want = 0", got)
	}
	if got := nic.stats.Rx.Bytes.Value(); got != 0 {
		t.Errorf("got Rx.Bytes = %d, want = 0", got)
	}
}
