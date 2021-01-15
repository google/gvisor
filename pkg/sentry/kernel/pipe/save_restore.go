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

package pipe

import (
	"gvisor.dev/gvisor/pkg/safemem"
)

// afterLoad is called by stateify.
func (p *Pipe) afterLoad() {
	p.bufBlocks[0] = safemem.BlockFromSafeSlice(p.buf)
	p.bufBlocks[1] = p.bufBlocks[0]
	p.bufBlockSeq = safemem.BlockSeqFromSlice(p.bufBlocks[:])
}
