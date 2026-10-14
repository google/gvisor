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

	"github.com/docker/docker/api/types/container"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/base"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
	"gvisor.dev/gvisor/test/metricsviz"
)

// containerMemoryMetrics holds sampled cgroup memory metrics for a container.
type containerMemoryMetrics struct {
	workingSet uint64
	totalUsage uint64
	anon       uint64
}

// workingSetMemory computes the resident working set memory of a container
// by subtracting reclaimable file cache (inactive_file) from total usage,
// following the exact methodology used by Docker CLI `docker stats`.
func workingSetMemory(stats *container.StatsResponse) uint64 {
	usage := stats.MemoryStats.Usage
	if stats.MemoryStats.Stats == nil {
		return usage
	}
	// cgroup v2
	if inactiveFile, ok := stats.MemoryStats.Stats["inactive_file"]; ok {
		if usage > inactiveFile {
			return usage - inactiveFile
		}
	}
	// cgroup v1
	if totalInactiveFile, ok := stats.MemoryStats.Stats["total_inactive_file"]; ok {
		if usage > totalInactiveFile {
			return usage - totalInactiveFile
		}
	} else if cache, ok := stats.MemoryStats.Stats["cache"]; ok {
		if usage > cache {
			return usage - cache
		}
	}
	return usage
}

// anonMemory returns the anonymous memory usage (heap, stacks, anonymous mmap)
// if reported by cgroups, or 0 if not available.
func anonMemory(stats *container.StatsResponse) uint64 {
	if stats.MemoryStats.Stats == nil {
		return 0
	}
	if anon, ok := stats.MemoryStats.Stats["anon"]; ok {
		return anon
	}
	if rss, ok := stats.MemoryStats.Stats["rss"]; ok {
		return rss
	}
	return 0
}

func validateStats(stats *container.StatsResponse) error {
	if stats == nil {
		return fmt.Errorf("stats response is nil")
	}
	// The runc empty container is on the order of multiple kB, so if this is smaller than that,
	// there is probably something wrong.
	var memoryAtLeast uint64 = 1000
	if stats.MemoryStats.Usage < memoryAtLeast {
		return fmt.Errorf("reported memory usage below sanity check minimum: %d: reported: %d", memoryAtLeast, stats.MemoryStats.Usage)
	}
	return nil
}

func reportMemoryMetrics(b *testing.B, metrics containerMemoryMetrics, count int) {
	b.Helper()
	if count <= 0 {
		return
	}
	avgWorkingSet := float64(metrics.workingSet) / float64(count)
	avgTotal := float64(metrics.totalUsage) / float64(count)

	// Primary metric: resident working set (matches docker stats CLI and true memory footprint).
	tools.ReportCustomMetric(b, avgWorkingSet, "average_container_memory_usage", "bytes")
	tools.ReportCustomMetric(b, avgWorkingSet, "working_set_memory", "bytes")
	tools.ReportCustomMetric(b, avgTotal, "total_memory_usage", "bytes")

	if metrics.anon > 0 {
		avgAnon := float64(metrics.anon) / float64(count)
		tools.ReportCustomMetric(b, avgAnon, "anon_memory", "bytes")
	}
}

// BenchmarkSizeEmpty creates N alpine containers and reads memory usage using `docker stats`.
// Each container is isolated to its own iteration and cleaned up promptly to avoid
// host resource accumulation across benchmark calibration runs.
func BenchmarkSizeEmpty(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	var sumMetrics containerMemoryMetrics

	// Make N containers.
	for i := 0; i < b.N; i++ {
		m, err := func() (containerMemoryMetrics, error) {
			container := machine.GetContainer(ctx, b)
			defer container.CleanUp(ctx)
			if err := container.Spawn(ctx, dockerutil.RunOpts{
				Image: "benchmarks/alpine",
			}, "sh", "-c", "echo Hello && sleep 1000"); err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to run container: %v", err)
			}
			if i == 0 {
				defer metricsviz.FromContainerLogs(ctx, b, container)
			}
			if _, err := container.WaitForOutputSubmatch(ctx, "Hello", 5*time.Second); err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to read container output: %v", err)
			}

			// Allow transient process spawn allocations to settle.
			time.Sleep(200 * time.Millisecond)

			stats, err := container.Stats(ctx)
			if err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to get container stats: %v", err)
			}
			if err := validateStats(stats); err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to validate container stats: %v", err)
			}
			return containerMemoryMetrics{
				workingSet: workingSetMemory(stats),
				totalUsage: stats.MemoryStats.Usage,
				anon:       anonMemory(stats),
			}, nil
		}()
		if err != nil {
			b.Fatalf("iteration %d failed: %v", i, err)
		}
		sumMetrics.workingSet += m.workingSet
		sumMetrics.totalUsage += m.totalUsage
		sumMetrics.anon += m.anon
	}
	reportMemoryMetrics(b, sumMetrics, b.N)
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

	runOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}
	const port = 80
	var sumMetrics containerMemoryMetrics
	for i := 0; i < b.N; i++ {
		m, err := func() (containerMemoryMetrics, error) {
			server, err := base.StartServer(ctx, b,
				base.ServerArgs{
					Machine: machine,
					Port:    port,
					RunOpts: runOpts,
					Cmd:     []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"},
				})
			if err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to start server: %v", err)
			}
			defer server.CleanUp(ctx)
			if i == 0 {
				defer metricsviz.FromContainerLogs(ctx, b, server)
			}

			// Wait for server to reach steady state after initial connection check.
			time.Sleep(300 * time.Millisecond)

			stats, err := server.Stats(ctx)
			if err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to get container stats: %v", err)
			}
			if err := validateStats(stats); err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to validate container stats: %v", err)
			}
			return containerMemoryMetrics{
				workingSet: workingSetMemory(stats),
				totalUsage: stats.MemoryStats.Usage,
				anon:       anonMemory(stats),
			}, nil
		}()
		if err != nil {
			b.Fatalf("iteration %d failed: %v", i, err)
		}
		sumMetrics.workingSet += m.workingSet
		sumMetrics.totalUsage += m.totalUsage
		sumMetrics.anon += m.anon
	}
	reportMemoryMetrics(b, sumMetrics, b.N)
}

// BenchmarkSizeNode starts N containers running a Node app, checks that
// they're serving, and checks memory used based on `docker stats`.
func BenchmarkSizeNode(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	// Make a native redis instance for Node to connect.
	redis := base.RedisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)

	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}
	nodeCmd := []string{"node", "index.js", "redis"}
	const port = 8080
	var sumMetrics containerMemoryMetrics
	for i := 0; i < b.N; i++ {
		m, err := func() (containerMemoryMetrics, error) {
			server, err := base.StartServer(ctx, b,
				base.ServerArgs{
					Machine: machine,
					Port:    port,
					RunOpts: runOpts,
					Cmd:     nodeCmd,
				})
			if err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to start server: %v", err)
			}
			defer server.CleanUp(ctx)
			if i == 0 {
				defer metricsviz.FromContainerLogs(ctx, b, server)
			}

			// Wait for V8 runtime and Redis client initialization to settle.
			time.Sleep(300 * time.Millisecond)

			stats, err := server.Stats(ctx)
			if err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to get container stats: %v", err)
			}
			if err := validateStats(stats); err != nil {
				return containerMemoryMetrics{}, fmt.Errorf("failed to validate container stats: %v", err)
			}
			return containerMemoryMetrics{
				workingSet: workingSetMemory(stats),
				totalUsage: stats.MemoryStats.Usage,
				anon:       anonMemory(stats),
			}, nil
		}()
		if err != nil {
			b.Fatalf("iteration %d failed: %v", i, err)
		}
		sumMetrics.workingSet += m.workingSet
		sumMetrics.totalUsage += m.totalUsage
		sumMetrics.anon += m.anon
	}
	reportMemoryMetrics(b, sumMetrics, b.N)
}

// BenchmarkCohortEmpty measures memory scaling and packing density of a cohort
// of 10 concurrent empty containers running simultaneously.
func BenchmarkCohortEmpty(b *testing.B) {
	ctx := context.Background()
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	const cohortSize = 10
	var sumMetrics containerMemoryMetrics

	for i := 0; i < b.N; i++ {
		m, err := func() (containerMemoryMetrics, error) {
			containers := make([]*dockerutil.Container, 0, cohortSize)
			defer base.CleanUpContainers(ctx, containers)

			for c := 0; c < cohortSize; c++ {
				container := machine.GetContainer(ctx, b)
				containers = append(containers, container)
				if err := container.Spawn(ctx, dockerutil.RunOpts{
					Image: "benchmarks/alpine",
				}, "sh", "-c", "echo Hello && sleep 1000"); err != nil {
					return containerMemoryMetrics{}, fmt.Errorf("failed to spawn container %d: %v", c, err)
				}
				if _, err := container.WaitForOutputSubmatch(ctx, "Hello", 5*time.Second); err != nil {
					return containerMemoryMetrics{}, fmt.Errorf("failed to read output for container %d: %v", c, err)
				}
			}

			time.Sleep(300 * time.Millisecond)

			var cohortMetrics containerMemoryMetrics
			for c, container := range containers {
				stats, err := container.Stats(ctx)
				if err != nil {
					return containerMemoryMetrics{}, fmt.Errorf("failed to get stats for container %d: %v", c, err)
				}
				if err := validateStats(stats); err != nil {
					return containerMemoryMetrics{}, fmt.Errorf("failed to validate stats for container %d: %v", c, err)
				}
				cohortMetrics.workingSet += workingSetMemory(stats)
				cohortMetrics.totalUsage += stats.MemoryStats.Usage
				cohortMetrics.anon += anonMemory(stats)
			}
			return cohortMetrics, nil
		}()
		if err != nil {
			b.Fatalf("cohort iteration %d failed: %v", i, err)
		}
		sumMetrics.workingSet += m.workingSet / cohortSize
		sumMetrics.totalUsage += m.totalUsage / cohortSize
		sumMetrics.anon += m.anon / cohortSize
	}
	reportMemoryMetrics(b, sumMetrics, b.N)
}

// TestMain is the main method for this package.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
