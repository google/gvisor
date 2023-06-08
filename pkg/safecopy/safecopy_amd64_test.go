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

//go:build amd64 || i386
// +build amd64 i386

package safecopy_x_test

import (
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/safecopy"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

func TestCheckXstateFault(t *testing.T) {
	cpuid.Initialize()
	state := fpu.NewState()
	state.SetMXCSR(0xffffff) // Invalid value
	err := safecopy.CheckXstate(state.BytePointer())
	if want := (safecopy.SegvError{uintptr(unsafe.Pointer(state.BytePointer()))}); err != want {
		t.Errorf("Unexpected error: got %v, want %v", err, want)
	}
}

func TestCheckXstateSuccess(t *testing.T) {
	cpuid.Initialize()
	if !cpuid.HostFeatureSet().UseXsave() {
		t.Skip("xsave isn't supported")
	}
	state := fpu.NewState()
	err := safecopy.CheckXstate(state.BytePointer())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}
