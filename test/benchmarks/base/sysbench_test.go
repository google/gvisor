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

package sysbench_test

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
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
				SysbenchBase: tools.SysbenchBase{
					Threads: 1,
				},
			},
		},
		testCase{
			name: "Memory",
			test: &tools.SysbenchMemory{
				SysbenchBase: tools.SysbenchBase{
					Threads: 1,
				},
			},
		},
		testCase{
			name: "Mutex",
			test: &tools.SysbenchMutex{
				SysbenchBase: tools.SysbenchBase{
					Threads: 8,
				},
			},
		},
	}

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for _, tc := range testCases {
		param := tools.Parameter{
			Name:  "testname",
			Value: tc.name,
		}
		name, err := tools.ParametersToName(param)
		if err != nil {
			b.Fatalf("Failed to parse params: %v", err)
		}
		b.Run(name, func(b *testing.B) {
			ctx := context.Background()
			sysbench := machine.GetContainer(ctx, b)
			defer sysbench.CleanUp(ctx)

			cmd := tc.test.MakeCmd(b)
			b.ResetTimer()
			out, err := sysbench.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/sysbench",
			}, cmd...)
			if err != nil {
				b.Fatalf("failed to run sysbench: %v: logs:%s", err, out)
			}
			b.StopTimer()
			tc.test.Report(b, out)
		})
	}
}
