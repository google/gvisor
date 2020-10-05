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
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkSizeEmpty creates N empty containers and reads memory usage from
// /proc/meminfo.
func BenchmarkSizeEmpty(b *testing.B) {
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()
	meminfo := tools.Meminfo{}
	ctx := context.Background()
	containers := make([]*dockerutil.Container, 0, b.N)

	// DropCaches before the test.
	harness.DropCaches(machine)

	// Check available memory on 'machine'.
	cmd, args := meminfo.MakeCmd()
	before, err := machine.RunCommand(cmd, args...)
	if err != nil {
		b.Fatalf("failed to get meminfo: %v", err)
	}

	// Make N containers.
	for i := 0; i < b.N; i++ {
		container := machine.GetContainer(ctx, b)
		containers = append(containers, container)
		if err := container.Spawn(ctx, dockerutil.RunOpts{
			Image: "benchmarks/alpine",
		}, "sh", "-c", "echo Hello && sleep 1000"); err != nil {
			cleanUpContainers(ctx, containers)
			b.Fatalf("failed to run container: %v", err)
		}
		if _, err := container.WaitForOutputSubmatch(ctx, "Hello", 5*time.Second); err != nil {
			cleanUpContainers(ctx, containers)
			b.Fatalf("failed to read container output: %v", err)
		}
	}

	// Drop caches again before second measurement.
	harness.DropCaches(machine)

	// Check available memory after containers are up.
	after, err := machine.RunCommand(cmd, args...)
	cleanUpContainers(ctx, containers)
	if err != nil {
		b.Fatalf("failed to get meminfo: %v", err)
	}
	meminfo.Report(b, before, after)
}

// BenchmarkSizeNginx starts N containers running Nginx, checks that they're
// serving, and checks memory used based on /proc/meminfo.
func BenchmarkSizeNginx(b *testing.B) {
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	// DropCaches for the first measurement.
	harness.DropCaches(machine)

	// Measure MemAvailable before creating containers.
	meminfo := tools.Meminfo{}
	cmd, args := meminfo.MakeCmd()
	before, err := machine.RunCommand(cmd, args...)
	if err != nil {
		b.Fatalf("failed to run meminfo command: %v", err)
	}

	// Make N Nginx containers.
	ctx := context.Background()
	runOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}
	const port = 80
	servers := startServers(ctx, b,
		serverArgs{
			machine: machine,
			port:    port,
			runOpts: runOpts,
			cmd:     []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"},
		})
	defer cleanUpContainers(ctx, servers)

	// DropCaches after servers are created.
	harness.DropCaches(machine)
	// Take after measurement.
	after, err := machine.RunCommand(cmd, args...)
	if err != nil {
		b.Fatalf("failed to run meminfo command: %v", err)
	}
	meminfo.Report(b, before, after)
}

// BenchmarkSizeNode starts N containers running a Node app, checks that
// they're serving, and checks memory used based on /proc/meminfo.
func BenchmarkSizeNode(b *testing.B) {
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	// Make a redis instance for Node to connect.
	ctx := context.Background()
	redis, redisIP := redisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)

	// DropCaches after redis is created.
	harness.DropCaches(machine)

	// Take before measurement.
	meminfo := tools.Meminfo{}
	cmd, args := meminfo.MakeCmd()
	before, err := machine.RunCommand(cmd, args...)
	if err != nil {
		b.Fatalf("failed to run meminfo commend: %v", err)
	}

	// Create N Node servers.
	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}
	nodeCmd := []string{"node", "index.js", redisIP.String()}
	const port = 8080
	servers := startServers(ctx, b,
		serverArgs{
			machine: machine,
			port:    port,
			runOpts: runOpts,
			cmd:     nodeCmd,
		})
	defer cleanUpContainers(ctx, servers)

	// DropCaches after servers are created.
	harness.DropCaches(machine)
	// Take after measurement.
	cmd, args = meminfo.MakeCmd()
	after, err := machine.RunCommand(cmd, args...)
	if err != nil {
		b.Fatalf("failed to run meminfo command: %v", err)
	}
	meminfo.Report(b, before, after)
}

// serverArgs wraps args for startServers and runServerWorkload.
type serverArgs struct {
	machine harness.Machine
	port    int
	runOpts dockerutil.RunOpts
	cmd     []string
}

// startServers starts b.N containers defined by 'runOpts' and 'cmd' and uses
// 'machine' to check that each is up.
func startServers(ctx context.Context, b *testing.B, args serverArgs) []*dockerutil.Container {
	b.Helper()
	servers := make([]*dockerutil.Container, 0, b.N)

	// Create N servers and wait until each of them is serving.
	for i := 0; i < b.N; i++ {
		server := args.machine.GetContainer(ctx, b)
		servers = append(servers, server)
		if err := server.Spawn(ctx, args.runOpts, args.cmd...); err != nil {
			cleanUpContainers(ctx, servers)
			b.Fatalf("failed to spawn node instance: %v", err)
		}

		// Get the container IP.
		servingIP, err := server.FindIP(ctx, false)
		if err != nil {
			cleanUpContainers(ctx, servers)
			b.Fatalf("failed to get ip from server: %v", err)
		}

		// Wait until the server is up.
		if err := harness.WaitUntilServing(ctx, args.machine, servingIP, args.port); err != nil {
			cleanUpContainers(ctx, servers)
			b.Fatalf("failed to wait for serving")
		}
	}
	return servers
}

// cleanUpContainers cleans up a slice of containers.
func cleanUpContainers(ctx context.Context, containers []*dockerutil.Container) {
	for _, c := range containers {
		if c != nil {
			c.CleanUp(ctx)
		}
	}
}
