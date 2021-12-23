// Copyright 2021 The gVisor Authors.
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
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestHintsCheckCompatible(t *testing.T) {
	for _, tc := range []struct {
		name        string
		masterOpts  []string
		replicaOpts []string
		err         string
	}{
		{
			name: "empty",
		},
		{
			name:        "same",
			masterOpts:  []string{"ro", "noatime", "noexec"},
			replicaOpts: []string{"ro", "noatime", "noexec"},
		},
		{
			name:        "compatible",
			masterOpts:  []string{"rw", "atime", "exec"},
			replicaOpts: []string{"ro", "noatime", "noexec"},
		},
		{
			name:        "unsupported",
			masterOpts:  []string{"nofoo", "nodev"},
			replicaOpts: []string{"foo", "dev"},
		},
		{
			name:        "incompatible-ro",
			masterOpts:  []string{"ro"},
			replicaOpts: []string{"rw"},
			err:         "read-write",
		},
		{
			name:        "incompatible-atime",
			masterOpts:  []string{"noatime"},
			replicaOpts: []string{"atime"},
			err:         "noatime",
		},
		{
			name:        "incompatible-exec",
			masterOpts:  []string{"noexec"},
			replicaOpts: []string{"exec"},
			err:         "noexec",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master := mountHint{mount: specs.Mount{Options: tc.masterOpts}}
			replica := specs.Mount{Options: tc.replicaOpts}
			if err := master.checkCompatibleVFS2(&replica); err != nil {
				if !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("wrong error, want: %q, got: %q", tc.err, err)
				}
			} else {
				if len(tc.err) > 0 {
					t.Fatalf("error %q expected", tc.err)
				}
			}
		})
	}
}
