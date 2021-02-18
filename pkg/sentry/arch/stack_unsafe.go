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

package arch

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/usermem"
)

// pushAddrSliceAndTerminator copies a slices of addresses to the stack, and
// also pushes an extra null address element at the end of the slice.
//
// Internally, we unsafely transmute the slice type from the arch-dependent
// []usermem.Addr type, to a slice of fixed-sized ints so that we can pass it to
// go-marshal.
//
// On error, the contents of the stack and the bottom cursor are undefined.
func (s *Stack) pushAddrSliceAndTerminator(src []usermem.Addr) (int, error) {
	// Note: Stack grows upwards, so push the terminator first.
	switch s.Arch.Width() {
	case 8:
		nNull, err := primitive.CopyUint64Out(s, StackBottomMagic, 0)
		if err != nil {
			return 0, err
		}
		srcAsUint64 := *(*[]uint64)(unsafe.Pointer(&src))
		n, err := primitive.CopyUint64SliceOut(s, StackBottomMagic, srcAsUint64)
		return n + nNull, err
	case 4:
		nNull, err := primitive.CopyUint32Out(s, StackBottomMagic, 0)
		if err != nil {
			return 0, err
		}
		srcAsUint32 := *(*[]uint32)(unsafe.Pointer(&src))
		n, err := primitive.CopyUint32SliceOut(s, StackBottomMagic, srcAsUint32)
		return n + nNull, err
	default:
		panic("Unsupported arch width")
	}
}
