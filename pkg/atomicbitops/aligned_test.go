// Copyright 2021 The gVisor Authors.
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

package atomicbitops

import (
	"testing"
	"unsafe"
)

func TestAtomiciInt64(t *testing.T) {
	v := struct {
		v8  int8
		v64 Int64
	}{}
	v.v64.Add(1)
}

func TestAtomicUint64(t *testing.T) {
	v := struct {
		v8  uint8
		v64 Uint64
	}{}
	v.v64.Add(1)
}

func TestSize(t *testing.T) {
	if size := unsafe.Sizeof(Int32{}); size != 4 {
		t.Errorf("Int32 should be 4 bytes in size, but is %d bytes", size)
	}
	if size := unsafe.Sizeof(Uint32{}); size != 4 {
		t.Errorf("Uint32 should be 4 bytes in size, but is %d bytes", size)
	}
	if size := unsafe.Sizeof(Int64{}); size != 8 {
		t.Errorf("Int32 should be 8 bytes in size, but is %d bytes", size)
	}
	if size := unsafe.Sizeof(Uint64{}); size != 8 {
		t.Errorf("Int32 should be 8 bytes in size, but is %d bytes", size)
	}
}
