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

package marshal

import (
	"io"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// StubMarshallable implements the Marshallable interface.
// StubMarshallable is a convenient embeddable type for satisfying the
// marshallable interface, but provides no actual implementation. It is
// useful when the marshallable interface needs to be implemented manually,
// but the caller doesn't require the full marshallable interface.
type StubMarshallable struct{}

// WriteTo implements Marshallable.WriteTo.
func (StubMarshallable) WriteTo(w io.Writer) (n int64, err error) {
	panic("Please implement your own WriteTo function")
}

// SizeBytes implements Marshallable.SizeBytes.
func (StubMarshallable) SizeBytes() int {
	panic("Please implement your own SizeBytes function")
}

// MarshalBytes implements Marshallable.MarshalBytes.
func (StubMarshallable) MarshalBytes(dst []byte) {
	panic("Please implement your own MarshalBytes function")
}

// UnmarshalBytes implements Marshallable.UnmarshalBytes.
func (StubMarshallable) UnmarshalBytes(src []byte) {
	panic("Please implement your own UnmarshalBytes function")
}

// Packed implements Marshallable.Packed.
func (StubMarshallable) Packed() bool {
	panic("Please implement your own Packed function")
}

// MarshalUnsafe implements Marshallable.MarshalUnsafe.
func (StubMarshallable) MarshalUnsafe(dst []byte) {
	panic("Please implement your own MarshalUnsafe function")
}

// UnmarshalUnsafe implements Marshallable.UnmarshalUnsafe.
func (StubMarshallable) UnmarshalUnsafe(src []byte) {
	panic("Please implement your own UnmarshalUnsafe function")
}

// CopyIn implements Marshallable.CopyIn.
func (StubMarshallable) CopyIn(cc CopyContext, addr hostarch.Addr) (int, error) {
	panic("Please implement your own CopyIn function")
}

// CopyOut implements Marshallable.CopyOut.
func (StubMarshallable) CopyOut(cc CopyContext, addr hostarch.Addr) (int, error) {
	panic("Please implement your own CopyOut function")
}

// CopyOutN implements Marshallable.CopyOutN.
func (StubMarshallable) CopyOutN(cc CopyContext, addr hostarch.Addr, limit int) (int, error) {
	panic("Please implement your own CopyOutN function")
}
