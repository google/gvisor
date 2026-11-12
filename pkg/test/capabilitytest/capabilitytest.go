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

// Package capabilitytest controls the capabilities of a test's thread.
//
// Importing it locks the main goroutine to the initial OS thread so tests
// that change capabilities run on threads that can be discarded.
package capabilitytest

import (
	"runtime"
	"testing"

	"github.com/moby/sys/capability"
)

func init() {
	// Reserve the initial thread for main so tests use threads that can exit.
	runtime.LockOSThread()
}

// DropEffective pins t's goroutine to a thread without c. Operations that
// require c to be absent must run on that goroutine.
func DropEffective(t *testing.T, c capability.Cap) {
	t.Helper()
	runtime.LockOSThread()
	caps, err := capability.NewPid2(0)
	if err != nil {
		t.Fatalf("reading thread capabilities: %v", err)
	}
	if err := caps.Load(); err != nil {
		t.Fatalf("loading thread capabilities: %v", err)
	}
	if !caps.Get(capability.EFFECTIVE, c) {
		t.Cleanup(runtime.UnlockOSThread)
		return
	}
	caps.Unset(capability.EFFECTIVE, c)
	if err := caps.Apply(capability.CAPS); err != nil {
		t.Fatalf("dropping effective %v: %v", c, err)
	}
	// Leaving the goroutine locked discards the modified thread when t exits.
}
