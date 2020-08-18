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

package base

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

type testCase struct {
	name string
	test tools.Sysbench
}

// BenchmarSysbench runs sysbench on the runtime.
func BenchmarkSysbench(b *testing.B) {

	testCases := []testCase{
		testCase{
			name: "CPU",
			test: &tools.SysbenchCPU{
				Base: tools.SysbenchBase{
					Threads: 1,
					Time:    5,
				},
				MaxPrime: 50000,
			},
		},
		testCase{
			name: "Memory",
			test: &tools.SysbenchMemory{
				Base: tools.SysbenchBase{
					Threads: 1,
				},
				BlockSize: "1M",
				TotalSize: "500G",
			},
		},
		testCase{
			name: "Mutex",
			test: &tools.SysbenchMutex{
				Base: tools.SysbenchBase{
					Threads: 8,
				},
				Loops: 1,
				Locks: 10000000,
				Num:   4,
			},
		},
	}

	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {

			ctx := context.Background()
			sysbench := machine.GetContainer(ctx, b)
			defer sysbench.CleanUp(ctx)

			out, err := sysbench.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/sysbench",
			}, tc.test.MakeCmd()...)
			if err != nil {
				b.Fatalf("failed to run sysbench: %v: logs:%s", err, out)
			}
			tc.test.Report(b, out)
		})
	}
}
