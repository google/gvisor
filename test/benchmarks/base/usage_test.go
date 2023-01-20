// Copyright 2023 The gVisor Authors.
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

package usage_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/base"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkSizeEmpty creates N alpine containers and reads memory usage using `docker stats`.
func BenchmarkSizeEmpty(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	var sumMemoryUsage uint64

	// Make N containers.
	for i := 0; i < b.N; i++ {
		container := machine.GetContainer(ctx, b)
		defer container.CleanUp(ctx)
		if err := container.Spawn(ctx, dockerutil.RunOpts{
			Image: "benchmarks/alpine",
		}, "sh", "-c", "echo Hello && sleep 1000"); err != nil {
			b.Fatalf("failed to run container: %v", err)
		}
		if _, err := container.WaitForOutputSubmatch(ctx, "Hello", 5*time.Second); err != nil {
			b.Fatalf("failed to read container output: %v", err)
		}

		stats, err := container.Stats(ctx)
		if err != nil {
			b.Fatalf("failed to get container stats: %v", err)
		}
		if err := validateStats(stats); err != nil {
			b.Fatalf("failed to validate container stats: %v", err)
		}
		sumMemoryUsage += stats.Stats.MemoryStats.Usage
	}
	reportMemoryUsage(b, sumMemoryUsage)
}

// BenchmarkSizeNginx starts N containers running Nginx, checks that they're
// serving, and checks memory usage from `docker stats`.
func BenchmarkSizeNginx(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	// Make N Nginx containers.
	runOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}
	const port = 80
	var sumMemoryUsage uint64
	for i := 0; i < b.N; i++ {
		server, err := base.StartServer(ctx, b,
			base.ServerArgs{
				Machine: machine,
				Port:    port,
				RunOpts: runOpts,
				Cmd:     []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"},
			})
		if err != nil {
			b.Fatalf("failed to start server: %v", err)
		}
		defer server.CleanUp(ctx)
		stats, err := server.Stats(ctx)
		if err != nil {
			b.Fatalf("failed to get container stats: %v", err)
		}
		if err := validateStats(stats); err != nil {
			b.Fatalf("failed to validate container stats: %v", err)
		}
		sumMemoryUsage += stats.Stats.MemoryStats.Usage
	}
	reportMemoryUsage(b, sumMemoryUsage)
}

// BenchmarkSizeNode starts N containers running a Node app, checks that
// they're serving, and checks memory used based on /proc/meminfo.
func BenchmarkSizeNode(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	// Make a redis instance for Node to connect.
	redis := base.RedisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)

	// Create N Node servers.
	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}
	nodeCmd := []string{"node", "index.js", "redis"}
	const port = 8080
	var sumMemoryUsage uint64
	for i := 0; i < b.N; i++ {
		server, err := base.StartServer(ctx, b,
			base.ServerArgs{
				Machine: machine,
				Port:    port,
				RunOpts: runOpts,
				Cmd:     nodeCmd,
			})
		if err != nil {
			b.Fatalf("failed to start server: %v", err)
		}
		defer server.CleanUp(ctx)
		stats, err := server.Stats(ctx)
		if err != nil {
			b.Fatalf("failed to get container stats: %v", err)
		}
		if err := validateStats(stats); err != nil {
			b.Fatalf("failed to validate container stats: %v", err)
		}
		sumMemoryUsage += stats.Stats.MemoryStats.Usage
	}
	reportMemoryUsage(b, sumMemoryUsage)
}

func validateStats(stats *types.StatsJSON) error {
	// The runc empty container is on the order of multiple kB, so if this is smaller than that,
	// there is probably something wrong.
	var memoryAtLeast uint64 = 1000
	if stats.MemoryStats.Usage < memoryAtLeast {
		return fmt.Errorf("reported memory usage below sanity check minimum: %d:  reported: %d", memoryAtLeast, stats.MemoryStats.Usage)
	}
	return nil
}

func reportMemoryUsage(b *testing.B, sumMemoryUsage uint64) {
	averageUsage := float64(sumMemoryUsage) / float64(b.N)
	tools.ReportCustomMetric(b, averageUsage, "average_container_memory_usage", "bytes")
}

// TestMain is the main method for this package.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
