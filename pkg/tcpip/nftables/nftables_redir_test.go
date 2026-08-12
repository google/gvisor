// Copyright 2026 The gVisor Authors.
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

package nftables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// TestNewRedirOp verifies parsing of the redir port registers, including the
// max-defaults-to-min behavior and the no-port case.
func TestNewRedirOp(t *testing.T) {
	// Port register set, max unset: max should default to min.
	rd, err := newRedirOp(int(linux.NFT_REG32_00), -1, 0)
	if err != nil {
		t.Fatalf("newRedirOp(min set, max unset): %v", err)
	}
	if rd.sregProtoMinIdx < 0 {
		t.Errorf("sregProtoMinIdx = %d, want a valid (>=0) register index", rd.sregProtoMinIdx)
	}
	if rd.sregProtoMaxIdx != rd.sregProtoMinIdx {
		t.Errorf("sregProtoMaxIdx = %d, want it to default to min (%d)", rd.sregProtoMaxIdx, rd.sregProtoMinIdx)
	}

	// Distinct min/max registers must map to distinct indices.
	rd, err = newRedirOp(int(linux.NFT_REG32_00), int(linux.NFT_REG32_01), 0)
	if err != nil {
		t.Fatalf("newRedirOp(min, max): %v", err)
	}
	if rd.sregProtoMinIdx == rd.sregProtoMaxIdx {
		t.Errorf("expected distinct min/max register indices, both = %d", rd.sregProtoMinIdx)
	}

	// No port register: the redirect keeps the original destination port.
	rd, err = newRedirOp(-1, -1, 0)
	if err != nil {
		t.Fatalf("newRedirOp(no port): %v", err)
	}
	if rd.sregProtoMinIdx != -1 {
		t.Errorf("sregProtoMinIdx = %d, want -1 (unset)", rd.sregProtoMinIdx)
	}
	if rd.sregProtoMaxIdx != -1 {
		t.Errorf("sregProtoMaxIdx = %d, want -1 (unset)", rd.sregProtoMaxIdx)
	}
}
