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

package garbage

import (
	gcdebug "runtime/debug"
	"testing"
)

// gcPercent returns the current garbage collection target percentage.
func gcPercent() int {
	p := gcdebug.SetGCPercent(100)
	gcdebug.SetGCPercent(p)
	return p
}

func TestSuspendResume(t *testing.T) {
	orig := gcdebug.SetGCPercent(37)
	defer gcdebug.SetGCPercent(orig)
	Suspend()
	Resume()
	if got := gcPercent(); got != 37 {
		t.Errorf("after Resume: got GC percent %d, want 37", got)
	}
}

func TestSuspendNests(t *testing.T) {
	orig := gcPercent()
	Suspend()
	Suspend()
	Resume()
	if got := gcPercent(); got != -1 {
		t.Errorf("after releasing one of two suspensions: got GC percent %d, want -1", got)
	}
	Resume()
	if got := gcPercent(); got != orig {
		t.Errorf("after releasing all suspensions: got GC percent %d, want %d", got, orig)
	}
}

func TestUnmatchedResumePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Resume without a matching Suspend did not panic")
		}
	}()
	Resume()
}
