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

// Package fpu provides basic floating point helpers.
package fpu

import (
	"fmt"
	"reflect"
)

// State represents floating point state.
//
// This is a simple byte slice, but may have architecture-specific methods
// attached to it.
type State []byte

// ErrLoadingState indicates a failed restore due to unusable floating point
// state.
type ErrLoadingState struct {
	// supported is the supported floating point state.
	supportedFeatures uint64

	// saved is the saved floating point state.
	savedFeatures uint64
}

// Error returns a sensible description of the restore error.
func (e ErrLoadingState) Error() string {
	return fmt.Sprintf("floating point state contains unsupported features; supported: %#x saved: %#x", e.supportedFeatures, e.savedFeatures)
}

// alignedBytes returns a slice of size bytes, aligned in memory to the given
// alignment. This is used because we require certain structures to be aligned
// in a specific way (for example, the X86 floating point data).
func alignedBytes(size, alignment uint) []byte {
	data := make([]byte, size+alignment-1)
	offset := uint(reflect.ValueOf(data).Index(0).Addr().Pointer() % uintptr(alignment))
	if offset == 0 {
		return data[:size:size]
	}
	return data[alignment-offset:][:size:size]
}
