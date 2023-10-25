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

package bpf

import (
	"encoding/binary"
)

// Input represents a source of input data for a BPF program. (BPF
// documentation sometimes refers to the input data as the "packet" due to its
// origins as a packet processing DSL.)
// Unaligned loads are supported.
type Input struct {
	// Data is the data accessed through the Input interface.
	Data []byte

	// Order is the byte order the data is accessed with.
	Order binary.ByteOrder
}

// Load32 implements Input.Load32.
//
//go:nosplit
func (i *Input) Load32(off uint32) (uint32, bool) {
	if uint64(off)+4 > uint64(len(i.Data)) {
		return 0, false
	}
	return i.Order.Uint32(i.Data[int(off):]), true
}

// Load16 implements Input.Load16.
//
//go:nosplit
func (i *Input) Load16(off uint32) (uint16, bool) {
	if uint64(off)+2 > uint64(len(i.Data)) {
		return 0, false
	}
	return i.Order.Uint16(i.Data[int(off):]), true
}

// Load8 implements Input.Load8.
//
//go:nosplit
func (i *Input) Load8(off uint32) (uint8, bool) {
	if uint64(off)+1 > uint64(len(i.Data)) {
		return 0, false
	}
	return i.Data[int(off)], true
}

// Length implements Input.Length.
//
//go:nosplit
func (i *Input) Length() uint32 {
	return uint32(len(i.Data))
}
