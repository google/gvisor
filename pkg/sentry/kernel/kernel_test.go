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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
)

// fixedCPUPlatform wraps a platform.Platform to force HasCPUNumbers() to
// report true, simulating a platform with a fixed-size vCPU pool (e.g. KVM).
type fixedCPUPlatform struct {
	platform.Platform
}

// HasCPUNumbers overrides the wrapped platform's implementation.
func (fixedCPUPlatform) HasCPUNumbers() bool { return true }

func TestSetApplicationCores(t *testing.T) {
	p, err := ptrace.New()
	if err != nil {
		t.Fatalf("ptrace.New: %v", err)
	}
	k := &Kernel{Platform: p}
	k.applicationCores.Store(2)

	if err := k.SetApplicationCores(4); err != nil {
		t.Fatalf("SetApplicationCores(4) failed: %v", err)
	}
	if got := k.ApplicationCores(); got != 4 {
		t.Errorf("ApplicationCores() = %d, want 4", got)
	}

	// A no-op call (same value) must succeed.
	if err := k.SetApplicationCores(4); err != nil {
		t.Errorf("SetApplicationCores(4) (no-op) failed: %v", err)
	}

	if err := k.SetApplicationCores(0); err == nil {
		t.Error("SetApplicationCores(0) succeeded, want error")
	}
	if got := k.ApplicationCores(); got != 4 {
		t.Errorf("ApplicationCores() = %d after rejected call, want unchanged 4", got)
	}

	// A value beyond the sanity ceiling is rejected, including one that
	// would wrap from a negative int32 (see SetCPUCountArgs callers).
	if err := k.SetApplicationCores(maxApplicationCores + 1); err == nil {
		t.Error("SetApplicationCores(maxApplicationCores+1) succeeded, want error")
	}
	if got := k.ApplicationCores(); got != 4 {
		t.Errorf("ApplicationCores() = %d after rejected out-of-range call, want unchanged 4", got)
	}

	// Shrinking is rejected; the value must be left unchanged.
	if err := k.SetApplicationCores(2); err == nil {
		t.Error("SetApplicationCores(2) (shrink) succeeded, want error")
	}
	if got := k.ApplicationCores(); got != 4 {
		t.Errorf("ApplicationCores() = %d after rejected shrink, want unchanged 4", got)
	}
}

func TestSetApplicationCoresFixedCPUPlatform(t *testing.T) {
	p, err := ptrace.New()
	if err != nil {
		t.Fatalf("ptrace.New: %v", err)
	}
	k := &Kernel{Platform: fixedCPUPlatform{p}}
	k.applicationCores.Store(4)

	if err := k.SetApplicationCores(8); err == nil {
		t.Error("SetApplicationCores on a HasCPUNumbers() platform succeeded, want error")
	}
	if got := k.ApplicationCores(); got != 4 {
		t.Errorf("ApplicationCores() = %d after rejected call, want unchanged 4", got)
	}
}
