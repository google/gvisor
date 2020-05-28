// Copyright 2020 The gVisor Authors.
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

package cleanup

import "testing"

func testCleanupHelper(clean, cleanAdd *bool, release bool) func() {
	cu := Make(func() {
		*clean = true
	})
	cu.Add(func() {
		*cleanAdd = true
	})
	defer cu.Clean()
	if release {
		return cu.Release()
	}
	return nil
}

func TestCleanup(t *testing.T) {
	clean := false
	cleanAdd := false
	testCleanupHelper(&clean, &cleanAdd, false)
	if !clean {
		t.Fatalf("cleanup function was not called.")
	}
	if !cleanAdd {
		t.Fatalf("added cleanup function was not called.")
	}
}

func TestRelease(t *testing.T) {
	clean := false
	cleanAdd := false
	cleaner := testCleanupHelper(&clean, &cleanAdd, true)

	// Check that clean was not called after release.
	if clean {
		t.Fatalf("cleanup function was called.")
	}
	if cleanAdd {
		t.Fatalf("added cleanup function was called.")
	}

	// Call the cleaner function and check that both cleanup functions are called.
	cleaner()
	if !clean {
		t.Fatalf("cleanup function was not called.")
	}
	if !cleanAdd {
		t.Fatalf("added cleanup function was not called.")
	}
}
