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

package bun_spawn_test

import (
	"context"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/metricsviz"
)

// BenchmarkBunSpawn measures synchronous child spawns in Bun.
// One Bun process runs all b.N spawns, amortizing its startup cost.
func BenchmarkBunSpawn(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatal(err)
	}
	defer machine.CleanUp()

	container := machine.GetContainer(ctx, b)
	defer container.CleanUp(ctx)
	if err := container.Spawn(ctx, dockerutil.RunOpts{
		Image:      "benchmarks/bun-spawn",
		CpusetCpus: harness.ServerCPUSet(),
	}, "sh", "-c", "trap 'exit 0' TERM; sleep 24h & wait"); err != nil {
		b.Fatal(err)
	}
	defer metricsviz.FromContainerLogs(ctx, b, container)
	iterations := fmt.Sprintf("%d", b.N)
	b.ResetTimer()
	out, err := container.Exec(ctx, dockerutil.ExecOpts{}, "bun", "/spawn.js", iterations)
	b.StopTimer()
	if err != nil {
		b.Fatalf("Bun spawns failed: %v, output: %s", err, out)
	}
}
