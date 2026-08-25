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

package sandbox

import (
	"math"
	"testing"
)

func TestTotalMemForLimit(t *testing.T) {
	const totalSysMem = uint64(16) << 30
	for _, test := range []struct {
		name     string
		memLimit uint64
		want     uint64
	}{
		{name: "limit below host memory", memLimit: 2 << 30, want: 2 << 30},
		{name: "limit above host memory caps", memLimit: 32 << 30, want: totalSysMem},
		{name: "cgroup v2 unlimited caps", memLimit: math.MaxUint64, want: totalSysMem},
		{name: "limit equal to host memory", memLimit: totalSysMem, want: totalSysMem},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := totalMemForLimit(test.memLimit, totalSysMem); got != test.want {
				t.Errorf("totalMemForLimit(%d, %d) = %d, want %d", test.memLimit, totalSysMem, got, test.want)
			}
		})
	}
}
