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

package usage

import (
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp/example"
)

// comparePrograms verifies that the precompiled and freshly-compiled programs
// match byte-for-byte. If not, it prints them side-by-side.
func comparePrograms(t *testing.T, precompiled, freshlyCompiled []bpf.Instruction) {
	t.Helper()
	if !slices.Equal(precompiled, freshlyCompiled) {
		t.Error("Precompiled and freshly-compiled versions of the program do not match:")
		t.Errorf("     Offset | %-32s | %-32s", "Freshly-compiled", "Compiled")
		for i := 0; i < max(len(precompiled), len(freshlyCompiled)); i++ {
			switch {
			case i < len(precompiled) && i < len(freshlyCompiled):
				if reflect.DeepEqual(precompiled[i], freshlyCompiled[i]) {
					t.Errorf("    OK %04d | %-32s | %-32s", i, freshlyCompiled[i].String(), precompiled[i].String())
				} else {
					t.Errorf("  DIFF %04d | %-32s | %-32s", i, freshlyCompiled[i].String(), precompiled[i].String())
				}
			case i < len(precompiled):
				t.Errorf("  DIFF %04d | %-32s | %-32s", i, "(end)", precompiled[i].String())
			case i < len(freshlyCompiled):
				t.Errorf("  DIFF %04d | %-32s | %-32s", i, freshlyCompiled[i].String(), "(end)")
			}
		}
	}
}

// TestProgram1 verifies that the precompiled version of the Program1 program
// matches a freshly-compiled version byte-for-byte.
func TestProgram1(t *testing.T) {
	fd1 := rand.Uint32()
	fd2 := fd1 + 1
	precompiled := LoadProgram1(fd1, fd2)
	prog := example.Program1(precompiledseccomp.Values{
		example.FD1: fd1,
		example.FD2: fd2,
	})
	freshlyCompiled, _, err := seccomp.BuildProgram(prog.Rules, prog.SeccompOptions)
	if err != nil {
		t.Fatalf("cannot freshly compile the program: %v", err)
	}
	comparePrograms(t, precompiled, freshlyCompiled)
}

// TestProgram2 verifies that the precompiled version of the Program2 program
// matches a freshly-compiled version byte-for-byte.
func TestProgram2(t *testing.T) {
	fd1 := rand.Uint32()
	fd2 := fd1 + 1
	precompiled := LoadProgram2(fd1, fd2)
	prog := example.Program2(precompiledseccomp.Values{
		example.FD1: fd1,
		example.FD2: fd2,
	})
	freshlyCompiled, _, err := seccomp.BuildProgram(prog.Rules, prog.SeccompOptions)
	if err != nil {
		t.Fatalf("cannot freshly compile the program: %v", err)
	}
	comparePrograms(t, precompiled, freshlyCompiled)
}

// TestNonExistentProgram verifies that invalid program names don't exist.
func TestNonExistentProgram(t *testing.T) {
	const nonExistentProgram = "this program name does not exist"
	got, found := GetPrecompiled(nonExistentProgram)
	if found {
		t.Fatalf("unexpectedly found program named %q: %v", nonExistentProgram, got)
	}
}
