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

package extension

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
)

type fakeExtension struct {
	name string
}

func (f fakeExtension) Name() string {
	return f.name
}

func (fakeExtension) TryHandleMount(*specs.Spec, *specs.Mount, string, bool) (lisafs.ConnectionImpl, lisafs.ConnectionOpts, error) {
	return nil, lisafs.ConnectionOpts{}, nil
}

func (fakeExtension) SeccompRules() seccomp.SyscallRules {
	return seccomp.NewSyscallRules()
}

func TestRegisterAndRegistered(t *testing.T) {
	registered = nil

	e1 := fakeExtension{name: "first"}
	e2 := fakeExtension{name: "second"}
	Register(e1)
	Register(e2)

	got := Registered()
	if len(got) != 2 {
		t.Fatalf("len(Registered()) = %d, want 2", len(got))
	}
	if got[0] != e1 || got[1] != e2 {
		t.Fatalf("Registered() = %v, want [%v %v]", got, e1, e2)
	}
}
