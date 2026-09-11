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
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestMetaLoadMark verifies that `meta mark` (NFT_META_MARK) loads the packet
// mark into the destination register as a 4-byte host-order value.
func TestMetaLoadMark(t *testing.T) {
	op, err := newMetaLoad(linux.NFT_META_MARK, linux.NFT_REG32_00)
	if err != nil {
		t.Fatalf("newMetaLoad(NFT_META_MARK): %v", err)
	}

	const mark = uint32(0x2a)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()
	pkt.Mark = mark

	var regs registerSet
	op.evaluate(&regs, opEvalCtx{pkt: pkt})

	if got := binary.NativeEndian.Uint32(regs.data[0:4]); got != mark {
		t.Errorf("meta mark loaded %#x into the destination register, want %#x", got, mark)
	}
}
