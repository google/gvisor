// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hackbench_test

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarHackbench runs hackbench on the runtime.
func BenchmarkHackbench(b *testing.B) {
	testCases := []tools.Hackbench{
		{
			IpcMode:     "pipe",
			ProcessMode: "thread",
		},
		{
			IpcMode:     "socket",
			ProcessMode: "process",
		},
	}

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for _, tc := range testCases {
		ipcMode := tools.Parameter{
			Name:  "ipcMode",
			Value: tc.IpcMode,
		}
		processMode := tools.Parameter{
			Name:  "processMode",
			Value: tc.ProcessMode,
		}
		name, err := tools.ParametersToName(ipcMode, processMode)
		if err != nil {
			b.Fatalf("Failed to parse params: %v", err)
		}
		b.Run(name, func(b *testing.B) {
			ctx := context.Background()
			container := machine.GetContainer(ctx, b)
			defer container.CleanUp(ctx)

			if err := container.Spawn(
				ctx, dockerutil.RunOpts{
					Image: "benchmarks/hackbench",
				},
				"sleep", "24h",
			); err != nil {
				b.Fatalf("run failed with: %v", err)
			}

			cmd := tc.MakeCmd(b)
			b.ResetTimer()
			out, err := container.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
			if err != nil {
				b.Fatalf("failed to run hackbench: %v, logs:%s", err, out)
			}
			tc.Report(b, out)
		})
	}
}

// TestMain is the main method for this package.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
