// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestState(t *testing.T) {
	tmpdir := t.TempDir()
	s := State{
		Rootfs: "rootfs_path",
		Options: Options{
			ShimCgroup: "shim_cgroup",
			IoUID:      123,
			IoGID:      456,
			BinaryName: "runsc",
			Root:       "runsc_root",
			LogLevel:   "info",
			LogPath:    "logpath",
			RunscConfig: map[string]string{
				"flag1": "value1",
				"flag2": "value2",
			},
		},
	}
	if err := s.Save(tmpdir); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	var s2 State
	if err := s2.Load(tmpdir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if diff := cmp.Diff(s, s2); diff != "" {
		t.Errorf("State is not equal, wanted:\n%v\ngot:\n%v\n", s, s2)
	}
}
