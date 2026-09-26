// Copyright 2026 The gVisor Authors.
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

package test1

import "unsafe"

// The call on the conversion's line is unrelated to pointer instrumentation.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concretePointerConversion(p unsafe.Pointer) *int {
	return (*int)(concretePointerIdentity(p))
}

//go:noinline
//go:nosplit
func concretePointerIdentity(p unsafe.Pointer) unsafe.Pointer {
	return p
}

// Generic compilation cannot rule out checkptr instrumentation.
// +mustescape:local,dynamic
//
//go:nosplit
func genericPointerConversion[T ~*int](p unsafe.Pointer) T {
	return T(p)
}
