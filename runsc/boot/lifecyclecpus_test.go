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

package boot

import (
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/gomaxprocs"
)

func TestLifecycleCPUs(t *testing.T) {
	initial := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		gomaxprocs.SetBase(initial)
	})

	check := func(want int) {
		t.Helper()
		if got := runtime.GOMAXPROCS(0); got != want {
			t.Errorf("GOMAXPROCS = %d, want %d", got, want)
		}
	}

	gomaxprocs.SetBase(2)
	var c lifecycleCPUs
	c.init(5, 2)

	// Restore holds are idempotent.
	c.holdForRestore()
	check(5)
	c.holdForRestore()
	check(5)
	c.releaseForRestore()
	check(2)
	c.releaseForRestore()
	check(2)

	// Overlapping checkpoints share the temporary GOMAXPROCS.
	c.hold()
	check(5)
	c.hold()
	check(5)
	c.release()
	check(5)
	c.release()
	check(2)

	// Restore and checkpoint holds share the temporary GOMAXPROCS.
	c.holdForRestore()
	c.hold()
	check(5)
	c.releaseForRestore()
	check(5)
	c.release()
	check(2)
}

func TestLifecycleCPUsInit(t *testing.T) {
	for _, tc := range []struct {
		name               string
		num, base          int
		wantNum, wantProcs int
	}{
		{name: "unset", num: 0, base: 2, wantNum: 2, wantProcs: 0},
		{name: "below base", num: 1, base: 2, wantNum: 2, wantProcs: 0},
		{name: "above base", num: 5, base: 2, wantNum: 5, wantProcs: 3},
		{name: "capped procs", num: 48, base: 2, wantNum: 48, wantProcs: maxLifecycleProcs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c lifecycleCPUs
			c.init(tc.num, tc.base)
			if c.num != tc.wantNum || c.procs != tc.wantProcs {
				t.Errorf("init(%d, %d): got num=%d procs=%d, want num=%d procs=%d", tc.num, tc.base, c.num, c.procs, tc.wantNum, tc.wantProcs)
			}
		})
	}
}
