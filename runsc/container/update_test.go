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

package container

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestMemoryLimit(t *testing.T) {
	limit := func(v int64) *specs.LinuxResources {
		return &specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &v}}
	}
	for _, test := range []struct {
		name    string
		res     *specs.LinuxResources
		want    uint64
		wantSet bool
	}{
		{name: "positive limit", res: limit(2 << 30), want: 2 << 30, wantSet: true},
		{name: "unlimited", res: limit(-1)},
		{name: "unset limit", res: limit(0)},
		{name: "no limit field", res: &specs.LinuxResources{Memory: &specs.LinuxMemory{}}},
		{name: "no memory", res: &specs.LinuxResources{}},
		{name: "no resources", res: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, gotSet := memoryLimit(test.res)
			if got != test.want || gotSet != test.wantSet {
				t.Errorf("memoryLimit() = (%d, %t), want (%d, %t)", got, gotSet, test.want, test.wantSet)
			}
		})
	}
}
