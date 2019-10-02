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

package flipcall

import (
	"reflect"
	"unsafe"

	"gvisor.dev/gvisor/third_party/gvsync"
)

// Packets consist of a 16-byte header followed by an arbitrarily-sized
// datagram. The header consists of:
//
// - A 4-byte native-endian connection state.
//
// - A 4-byte native-endian datagram length in bytes.
//
// - 8 reserved bytes.
const (
	// PacketHeaderBytes is the size of a flipcall packet header in bytes. The
	// maximum datagram size supported by a flipcall connection is equal to the
	// length of the packet window minus PacketHeaderBytes.
	//
	// PacketHeaderBytes is exported to support its use in constant
	// expressions. Non-constant expressions may prefer to use
	// PacketWindowLengthForDataCap().
	PacketHeaderBytes = 16
)

func (ep *Endpoint) connState() *uint32 {
	return (*uint32)((unsafe.Pointer)(ep.packet))
}

func (ep *Endpoint) dataLen() *uint32 {
	return (*uint32)((unsafe.Pointer)(ep.packet + 4))
}

// Data returns the datagram part of ep's packet window as a byte slice.
//
// Note that the packet window is shared with the potentially-untrusted peer
// Endpoint, which may concurrently mutate the contents of the packet window.
// Thus:
//
// - Readers must not assume that two reads of the same byte in Data() will
// return the same result. In other words, readers should read any given byte
// in Data() at most once.
//
// - Writers must not assume that they will read back the same data that they
// have written. In other words, writers should avoid reading from Data() at
// all.
func (ep *Endpoint) Data() []byte {
	var bs []byte
	bsReflect := (*reflect.SliceHeader)((unsafe.Pointer)(&bs))
	bsReflect.Data = ep.packet + PacketHeaderBytes
	bsReflect.Len = int(ep.dataCap)
	bsReflect.Cap = int(ep.dataCap)
	return bs
}

// ioSync is a dummy variable used to indicate synchronization to the Go race
// detector. Compare syscall.ioSync.
var ioSync int64

func raceBecomeActive() {
	if gvsync.RaceEnabled {
		gvsync.RaceAcquire((unsafe.Pointer)(&ioSync))
	}
}

func raceBecomeInactive() {
	if gvsync.RaceEnabled {
		gvsync.RaceReleaseMerge((unsafe.Pointer)(&ioSync))
	}
}
