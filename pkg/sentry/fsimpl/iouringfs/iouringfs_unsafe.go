// Copyright 2022 The gVisor Authors.
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

package iouringfs

import (
	"fmt"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/gohacks"
)

func atomicUint32AtOffset(buf []byte, offset int) *atomicbitops.Uint32 {
	const sizeOfUint32 int = 4
	if offset+sizeOfUint32 > len(buf) || offset < 0 {
		panic(fmt.Sprintf("cast at offset %d for slice of len %d would result in overrun", offset, len(buf)))
	}
	if offset%sizeOfUint32 != 0 {
		panic(fmt.Sprintf("cast at offset %d would produce unaligned pointer", offset))
	}
	hdr := (*gohacks.SliceHeader)(unsafe.Pointer(&buf))
	return (*atomicbitops.Uint32)(unsafe.Add(hdr.Data, offset))
}
