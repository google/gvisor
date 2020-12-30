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

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/base"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// BenchmarkStartEmpty times startup time for an empty container.
func BenchmarkStartupEmpty(b *testing.B) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		harness.DebugLog(b, "Running container: %d", i)
		container := machine.GetContainer(ctx, b)
		defer container.CleanUp(ctx)
		if _, err := container.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/alpine",
		}, "true"); err != nil {
			b.Fatalf("failed to run container: %v", err)
		}
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
	redis, redisIP := base.RedisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)
	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}

	cmd := []string{"node", "index.js", redisIP.String()}
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
				// Cleanup servers as we run so that we can go indefinitely.
				server.CleanUp(ctx)
				b.StartTimer()
			}()
			harness.DebugLog(b, "Spawning container: %s", args.RunOpts.Image)
			if err := server.Spawn(ctx, args.RunOpts, args.Cmd...); err != nil {
				return fmt.Errorf("failed to spawn node instance: %v", err)
			}

			harness.DebugLog(b, "Finding Container IP")
			servingIP, err := server.FindIP(ctx, false)
			if err != nil {
				return fmt.Errorf("failed to get ip from server: %v", err)
			}

			// Wait until the Client sees the server as up.
			harness.DebugLog(b, "Waiting for container to start.")
			if err := harness.WaitUntilServing(ctx, args.Machine, servingIP, args.Port); err != nil {
				return fmt.Errorf("failed to wait for serving: %v", err)
			}
			return nil
		}(); err != nil {
			b.Fatal(err)
		}
		harness.DebugLog(b, "Ran iteration: %d", i)
	}
}

// TestMain is the main method for package network.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
