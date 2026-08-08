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

package startup_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/benchmarks/base"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/metricsviz"
)

// BenchmarkStartEmpty times startup time for an empty container.
func BenchmarkStartupEmpty(b *testing.B) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness.DebugLog(b, "Running container: %d", i)
		container := machine.GetContainer(ctx, b)
		b.StartTimer()
		if err := container.Spawn(ctx, dockerutil.RunOpts{
			Image: "benchmarks/alpine",
		}, "sleep", "100"); err != nil {
			b.Fatalf("failed to start container: %v", err)
		}
		b.StopTimer()
		if i == 0 {
			metricsviz.FromContainerLogs(ctx, b, container)
		}
		container.CleanUp(ctx)
		harness.DebugLog(b, "Ran container: %d", i)
	}
}

// BenchmarkStartupNginx times startup for a Nginx instance.
// Time is measured from start until the first request is served.
func BenchmarkStartupNginx(b *testing.B) {
	// The machine to hold Nginx and the Node Server.
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	runOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}
	runServerWorkload(ctx, b,
		base.ServerArgs{
			Machine: machine,
			RunOpts: runOpts,
			Port:    80,
			Cmd:     []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"},
		})
}

// BenchmarkStartupNode times startup for a Node application instance.
// Time is measured from start until the first request is served.
// Note that the Node app connects to a Redis instance before serving.
func BenchmarkStartupNode(b *testing.B) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	redis := base.RedisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)
	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}

	cmd := []string{"node", "index.js", "redis"}
	runServerWorkload(ctx, b,
		base.ServerArgs{
			Machine: machine,
			Port:    8080,
			RunOpts: runOpts,
			Cmd:     cmd,
		})
}

// runServerWorkload runs a server workload defined by 'runOpts' and 'cmd'.
// 'clientMachine' is used to connect to the server on 'serverMachine'.
func runServerWorkload(ctx context.Context, b *testing.B, args base.ServerArgs) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness.DebugLog(b, "Running iteration: %d", i)
		if err := func() error {
			server := args.Machine.GetContainer(ctx, b)
			defer func() {
				b.StopTimer()
				metricsviz.FromContainerLogs(ctx, b, server)
				// Cleanup servers as we run so that we can go indefinitely.
				server.CleanUp(ctx)
				b.StartTimer()
			}()
			harness.DebugLog(b, "Spawning container: %s", args.RunOpts.Image)
			if err := server.Spawn(ctx, args.RunOpts, args.Cmd...); err != nil {
				return fmt.Errorf("failed to spawn node instance: %v", err)
			}

			// Wait until the Client sees the server as up.
			harness.DebugLog(b, "Waiting for container to start.")
			if err := harness.WaitUntilContainerServing(ctx, args.Machine, server, args.Port); err != nil {
				return fmt.Errorf("failed to wait for serving: %v", err)
			}
			return nil
		}(); err != nil {
			b.Fatal(err)
		}
		harness.DebugLog(b, "Ran iteration: %d", i)
	}
}

func skipUnlessCheckpointSupported(b *testing.B) {
	if !testutil.IsCheckpointSupported() {
		b.Skip("Checkpoint is not supported on this runtime.")
	}
	if os.Getenv("RUNTIME") == "runc" {
		b.Skip("Skipping runc for Checkpoint latency benchmark.")
	}
}

// BenchmarkCheckpointEmpty times checkpoint creation for an empty container.
func BenchmarkCheckpointEmpty(b *testing.B) {
	skipUnlessCheckpointSupported(b)
	client, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer client.CleanUp()
	ctx := context.Background()
	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		func() {
			container := client.GetContainer(ctx, b)
			defer container.CleanUp(ctx)

			// Using host network mode to avoid Docker v28+ restore bug where
			// Moby attempts to bind-mount /proc/0/ns/net on bridge namespaces
			// (see https://github.com/moby/moby/issues/50750).
			if err := container.Spawn(ctx, dockerutil.RunOpts{
				Image:       "benchmarks/alpine",
				NetworkMode: "host",
			}, "sleep", "1000"); err != nil {
				b.Fatalf("failed to spawn container: %v", err)
			}

			status, err := container.Status(ctx)
			if err != nil {
				b.Fatalf("failed to get container status: %v", err)
			}
			if !status.Running {
				b.Fatalf("container is not running")
			}

			ckptName := fmt.Sprintf("ckpt-empty-%d", i)
			b.StartTimer()
			if err := container.Checkpoint(ctx, ckptName); err != nil {
				b.Fatalf("failed to checkpoint container: %v", err)
			}
			b.StopTimer()
		}()
	}
}

// BenchmarkRestoreEmpty times restoring an empty container from a checkpoint.
func BenchmarkRestoreEmpty(b *testing.B) {
	skipUnlessCheckpointSupported(b)
	client, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer client.CleanUp()
	ctx := context.Background()
	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		func() {
			container := client.GetContainer(ctx, b)
			defer container.CleanUp(ctx)

			// Using host network mode to avoid Docker v28+ restore bug where
			// Moby attempts to bind-mount /proc/0/ns/net on bridge namespaces
			// (see https://github.com/moby/moby/issues/50750).
			if err := container.Spawn(ctx, dockerutil.RunOpts{
				Image:       "benchmarks/alpine",
				NetworkMode: "host",
			}, "sleep", "1000"); err != nil {
				b.Fatalf("failed to spawn container: %v", err)
			}

			ckptName := fmt.Sprintf("ckpt-restore-empty-%d", i)
			if err := container.Checkpoint(ctx, ckptName); err != nil {
				b.Fatalf("failed to checkpoint container: %v", err)
			}

			time.Sleep(2 * time.Second)
			b.StartTimer()
			if err := container.Restore(ctx, ckptName); err != nil {
				b.Fatalf("failed to restore container: %v", err)
			}
			b.StopTimer()
		}()
	}
}

func waitUntilHostServing(ctx context.Context, server *dockerutil.Container, port int) error {
	serverUpChan := make(chan struct{})
	var upErr error
	hexPort := fmt.Sprintf(":%04X", port)
	cmd := "while ! grep -s -E '" + hexPort + "' /proc/net/tcp /proc/net/tcp6; do sleep 0.001; done"
	go func() {
		_, upErr = server.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd)
		if upErr == nil {
			close(serverUpChan)
		}
	}()

	select {
	case <-serverUpChan:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for server on port %d (%s): last err: %v", port, hexPort, upErr)
	}
}

func spawnServerWorkloadAndWait(ctx context.Context, b *testing.B, client harness.Machine, name string, port int) *dockerutil.Container {
	server := client.GetContainer(ctx, b)

	// Using host network mode to avoid Docker v28+ restore bug where
	// Moby attempts to bind-mount /proc/0/ns/net on bridge namespaces
	// (see https://github.com/moby/moby/issues/50750).
	opts := dockerutil.RunOpts{
		Image:       fmt.Sprintf("benchmarks/%s", name),
		NetworkMode: "host",
	}

	var cmd []string
	if name == "nginx" {
		cmd = []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"}
	}

	if err := server.Spawn(ctx, opts, cmd...); err != nil {
		server.CleanUp(ctx)
		b.Fatalf("failed to spawn %s: %v", name, err)
	}
	if err := waitUntilHostServing(ctx, server, port); err != nil {
		logs, _ := server.Logs(ctx)
		server.CleanUp(ctx)
		b.Fatalf("failed to wait for %s serving: %v\nServer logs:\n%s", name, err, logs)
	}
	return server
}

func runCheckpointServerWorkload(b *testing.B, name string, port int) {
	skipUnlessCheckpointSupported(b)
	client, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer client.CleanUp()
	ctx := context.Background()
	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		func() {
			server := spawnServerWorkloadAndWait(ctx, b, client, name, port)
			defer server.CleanUp(ctx)

			ckptName := fmt.Sprintf("ckpt-%s-%d", name, i)
			b.StartTimer()
			if err := server.Checkpoint(ctx, ckptName); err != nil {
				b.Fatalf("failed to checkpoint %s: %v", name, err)
			}
			b.StopTimer()
		}()
	}
}

func runRestoreServerWorkload(b *testing.B, name string, port int) {
	skipUnlessCheckpointSupported(b)
	client, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer client.CleanUp()
	ctx := context.Background()
	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		func() {
			server := spawnServerWorkloadAndWait(ctx, b, client, name, port)
			defer server.CleanUp(ctx)

			ckptName := fmt.Sprintf("ckpt-restore-%s-%d", name, i)
			if err := server.Checkpoint(ctx, ckptName); err != nil {
				b.Fatalf("failed to checkpoint %s: %v", name, err)
			}

			time.Sleep(2 * time.Second)
			b.StartTimer()
			if err := server.Restore(ctx, ckptName); err != nil {
				b.Fatalf("failed to restore %s: %v", name, err)
			}
			if err := waitUntilHostServing(ctx, server, port); err != nil {
				b.Fatalf("failed to wait for %s serving after restore: %v", name, err)
			}
			b.StopTimer()
		}()
	}
}

// BenchmarkCheckpointNginx times checkpoint creation for Nginx.
func BenchmarkCheckpointNginx(b *testing.B) {
	runCheckpointServerWorkload(b, "nginx", 80)
}

// BenchmarkRestoreNginx times restoring Nginx until serving HTTP.
func BenchmarkRestoreNginx(b *testing.B) {
	runRestoreServerWorkload(b, "nginx", 80)
}

// TestMain is the main method for package network.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
