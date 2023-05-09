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

package syscallbench_test

import (
	"context"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarSyscallbench runs a syscall b.N times on the runtime.
func BenchmarkSyscallbench(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for _, tc := range []struct {
		param      tools.Parameter
		syscallArg int
	}{
		{
			param: tools.Parameter{
				Name:  "syscall",
				Value: "getpid",
			},
		},
		{
			param: tools.Parameter{
				Name:  "syscall",
				Value: "getpidopt",
			},
			syscallArg: 1,
		},
	} {
		name, err := tools.ParametersToName(tc.param)
		if err != nil {
			b.Fatalf("Failed to parse params: %v", err)
		}

		func() {
			container := machine.GetContainer(ctx, b)
			defer container.CleanUp(ctx)
			if err := container.Spawn(
				ctx, dockerutil.RunOpts{
					Image: "benchmarks/syscallbench",
				},
				"sleep", "24h",
			); err != nil {
				b.Fatalf("run failed with: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				cmd := []string{"syscallbench", fmt.Sprintf("--loops=%d", b.N), fmt.Sprintf("--syscall=%d", tc.syscallArg)}
				b.ResetTimer()
				out, err := container.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
				if err != nil {
					b.Fatalf("failed to run syscallbench: %v, logs:%s", err, out)
				}
			})
		}()
	}

}
