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

// +build linux

package fdbased

import (
	"reflect"
	"unsafe"
)

const virtioNetHdrSize = int(unsafe.Sizeof(virtioNetHdr{}))

func vnetHdrToByteSlice(hdr *virtioNetHdr) (slice []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	sh.Data = uintptr(unsafe.Pointer(hdr))
	sh.Len = virtioNetHdrSize
	sh.Cap = virtioNetHdrSize
	return
}
