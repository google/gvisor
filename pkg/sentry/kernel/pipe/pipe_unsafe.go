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

package pipe

import (
	"unsafe"
)

// lockTwoPipes locks both x.mu and y.mu in an order that is guaranteed to be
// consistent for both lockTwoPipes(x, y) and lockTwoPipes(y, x), such that
// concurrent calls cannot deadlock.
//
// Preconditions: x != y.
// +checklocksacquire:x.mu
// +checklocksacquire:y.mu
func lockTwoPipes(x, y *Pipe) {
	// Lock the two pipes in order of increasing address.
	if uintptr(unsafe.Pointer(x)) < uintptr(unsafe.Pointer(y)) {
		x.mu.Lock()
		y.mu.Lock()
	} else {
		y.mu.Lock()
		x.mu.Lock()
	}
}
