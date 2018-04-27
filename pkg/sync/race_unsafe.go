// Copyright 2018 Google Inc.
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

// +build race

package sync

import (
	"runtime"
	"unsafe"
)

// RaceEnabled is true if the Go data race detector is enabled.
const RaceEnabled = true

// RaceDisable has the same semantics as runtime.RaceDisable.
func RaceDisable() {
	runtime.RaceDisable()
}

// RaceEnable has the same semantics as runtime.RaceEnable.
func RaceEnable() {
	runtime.RaceEnable()
}

// RaceAcquire has the same semantics as runtime.RaceAcquire.
func RaceAcquire(addr unsafe.Pointer) {
	runtime.RaceAcquire(addr)
}

// RaceRelease has the same semantics as runtime.RaceRelease.
func RaceRelease(addr unsafe.Pointer) {
	runtime.RaceRelease(addr)
}

// RaceReleaseMerge has the same semantics as runtime.RaceReleaseMerge.
func RaceReleaseMerge(addr unsafe.Pointer) {
	runtime.RaceReleaseMerge(addr)
}
