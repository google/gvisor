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

package lisafs

import (
	"math/rand"

	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// MsgSimple is a sample packed struct which can be used to test message passing.
//
// +marshal slice:Msg1Slice
type MsgSimple struct {
	A uint16
	B uint16
	C uint32
	D uint64
}

// Randomize randomizes the contents of m.
func (m *MsgSimple) Randomize() {
	m.A = uint16(rand.Uint32())
	m.B = uint16(rand.Uint32())
	m.C = rand.Uint32()
	m.D = rand.Uint64()
}

// MsgDynamic is a sample dynamic struct which can be used to test message passing.
//
// +marshal dynamic
type MsgDynamic struct {
	N   primitive.Uint32
	Arr []MsgSimple
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MsgDynamic) SizeBytes() int {
	return m.N.SizeBytes() +
		(int(m.N) * (*MsgSimple)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MsgDynamic) MarshalBytes(dst []byte) []byte {
	dst = m.N.MarshalUnsafe(dst)
	return MarshalUnsafeMsg1Slice(m.Arr, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsgDynamic) UnmarshalBytes(src []byte) []byte {
	src = m.N.UnmarshalUnsafe(src)
	m.Arr = make([]MsgSimple, m.N)
	return UnmarshalUnsafeMsg1Slice(m.Arr, src)
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (m *MsgDynamic) CheckedUnmarshal(src []byte) ([]byte, bool) {
	m.Arr = m.Arr[:0]
	if m.SizeBytes() > len(src) {
		return nil, false
	}
	src = m.N.UnmarshalUnsafe(src)
	if int(m.N) > cap(m.Arr) {
		m.Arr = make([]MsgSimple, m.N)
	} else {
		m.Arr = m.Arr[:m.N]
	}
	if int(m.N)*(*MsgSimple)(nil).SizeBytes() > len(src) {
		return nil, false
	}
	return UnmarshalUnsafeMsg1Slice(m.Arr, src), true
}

// Randomize randomizes the contents of m.
func (m *MsgDynamic) Randomize(arrLen int) {
	m.N = primitive.Uint32(arrLen)
	m.Arr = make([]MsgSimple, arrLen)
	for i := 0; i < arrLen; i++ {
		m.Arr[i].Randomize()
	}
}

// P9Version mimics p9.TVersion and p9.Rversion.
type P9Version struct {
	MSize   primitive.Uint32
	Version string
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (v *P9Version) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + (*primitive.Uint16)(nil).SizeBytes() + len(v.Version)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (v *P9Version) MarshalBytes(dst []byte) []byte {
	dst = v.MSize.MarshalUnsafe(dst)
	versionLen := primitive.Uint16(len(v.Version))
	dst = versionLen.MarshalUnsafe(dst)
	return dst[copy(dst, v.Version):]
}

// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.
func (v *P9Version) CheckedUnmarshal(src []byte) ([]byte, bool) {
	v.Version = ""
	if v.SizeBytes() > len(src) {
		return nil, false
	}
	src = v.MSize.UnmarshalUnsafe(src)
	var versionLen primitive.Uint16
	src = versionLen.UnmarshalUnsafe(src)
	if int(versionLen) > len(src) {
		return nil, false
	}
	v.Version = string(src[:versionLen])
	return src[versionLen:], true
}
