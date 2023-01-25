// Copyright 2023 The gVisor Authors.
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

// Only test on amd64 and arm64, as only those architectures have defined the
// constant.

//go:build amd64 || arm64

package sync

import (
	"testing"
	"unsafe"
)

// TestMaptypeHasherOffset verifies that maptype.hasher is at the same offset
// as runtime.maptype.hasher.
func TestMaptypeHasherOffset(t *testing.T) {
	want := uintptr(maptypeHasherOffset)
	if got := unsafe.Offsetof(maptype{}.hasher); got != want {
		t.Errorf("maptype.hasher offset got %d want %d; type changed in Go standard library?", got, want)
	}
}
