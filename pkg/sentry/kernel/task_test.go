// Copyright 2018 The gVisor Authors.
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

	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/sched"
)

func TestTaskCPU(t *testing.T) {
	for _, test := range []struct {
		mask sched.CPUSet
		tid  ThreadID
		cpu  int32
	}{
		{
			mask: []byte{0xff},
			tid:  1,
			cpu:  0,
		},
		{
			mask: []byte{0xff},
			tid:  10,
			cpu:  1,
		},
		{
			// more than 8 cpus.
			mask: []byte{0xff, 0xff},
			tid:  10,
			cpu:  9,
		},
		{
			// missing the first cpu.
			mask: []byte{0xfe},
			tid:  1,
			cpu:  1,
		},
		{
			mask: []byte{0xfe},
			tid:  10,
			cpu:  3,
		},
		{
			// missing the fifth cpu.
			mask: []byte{0xef},
			tid:  10,
			cpu:  2,
		},
	} {
		assigned := assignCPU(test.mask, test.tid)
		if test.cpu != assigned {
			t.Errorf("assignCPU(%v, %v) got %v, want %v", test.mask, test.tid, assigned, test.cpu)
		}
	}

}
