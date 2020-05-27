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

package pipe

import (
	"sync/atomic"
	"unsafe"
)

func (p *pipe) write(idx uint64, v uint64) {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	*ptr = v
}

func (p *pipe) writeAtomic(idx uint64, v uint64) {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	atomic.StoreUint64(ptr, v)
}

func (p *pipe) readAtomic(idx uint64) uint64 {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	return atomic.LoadUint64(ptr)
}
