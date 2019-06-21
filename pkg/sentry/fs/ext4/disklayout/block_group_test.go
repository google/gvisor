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

package disklayout

import (
	"testing"

	"gvisor.dev/gvisor/pkg/binary"
)

// TestBlockGroupSize tests the fact that the block group struct for
// 32-bit ext filesystems should be exactly 32 bytes big and for 64-bit fs it
// should be 64 bytes.
func TestBlockGroupSize(t *testing.T) {
	if got, want := int(binary.Size(BlockGroup32Bit{})), 32; got != want {
		t.Errorf("BlockGroup32Bit should be exactly 32 bytes but is %d bytes", got)
	}

	if got, want := int(binary.Size(BlockGroup64Bit{})), 64; got != want {
		t.Errorf("BlockGroup64Bit should be exactly 64 bytes but is %d bytes", got)
	}
}
