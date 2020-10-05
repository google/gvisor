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
	"fmt"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// BenchmarkStartEmpty times startup time for an empty container.
func BenchmarkStartupEmpty(b *testing.B) {
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		container := machine.GetContainer(ctx, b)
		defer container.CleanUp(ctx)
		if _, err := container.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/alpine",
		}, "true"); err != nil {
			b.Fatalf("failed to run container: %v", err)
		}
	}
}

// BenchmarkStartupNginx times startup for a Nginx instance.
// Time is measured from start until the first request is served.
func BenchmarkStartupNginx(b *testing.B) {
	// The machine to hold Nginx and the Node Server.
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	runOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}
	runServerWorkload(ctx, b,
		serverArgs{
			machine: machine,
			runOpts: runOpts,
			port:    80,
			cmd:     []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"},
		})
}

// BenchmarkStartupNode times startup for a Node application instance.
// Time is measured from start until the first request is served.
// Note that the Node app connects to a Redis instance before serving.
func BenchmarkStartupNode(b *testing.B) {
	machine, err := testHarness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	redis, redisIP := redisInstance(ctx, b, machine)
	defer redis.CleanUp(ctx)
	runOpts := dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
	}

	cmd := []string{"node", "index.js", redisIP.String()}
	runServerWorkload(ctx, b,
		serverArgs{
			machine: machine,
			port:    8080,
			runOpts: runOpts,
			cmd:     cmd,
		})
}

// redisInstance returns a Redis container and its reachable IP.
func redisInstance(ctx context.Context, b *testing.B, machine harness.Machine) (*dockerutil.Container, net.IP) {
	b.Helper()
	// Spawn a redis instance for the app to use.
	redis := machine.GetNativeContainer(ctx, b)
	if err := redis.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/redis",
	}); err != nil {
		redis.CleanUp(ctx)
		b.Fatalf("failed to spwan redis instance: %v", err)
	}

	if out, err := redis.WaitForOutput(ctx, "Ready to accept connections", 3*time.Second); err != nil {
		redis.CleanUp(ctx)
		b.Fatalf("failed to start redis server: %v %s", err, out)
	}
	redisIP, err := redis.FindIP(ctx, false)
	if err != nil {
		redis.CleanUp(ctx)
		b.Fatalf("failed to get IP from redis instance: %v", err)
	}
	return redis, redisIP
}

// runServerWorkload runs a server workload defined by 'runOpts' and 'cmd'.
// 'clientMachine' is used to connect to the server on 'serverMachine'.
func runServerWorkload(ctx context.Context, b *testing.B, args serverArgs) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := func() error {
			server := args.machine.GetContainer(ctx, b)
			defer func() {
				b.StopTimer()
				// Cleanup servers as we run so that we can go indefinitely.
				server.CleanUp(ctx)
				b.StartTimer()
			}()
			if err := server.Spawn(ctx, args.runOpts, args.cmd...); err != nil {
				return fmt.Errorf("failed to spawn node instance: %v", err)
			}

			servingIP, err := server.FindIP(ctx, false)
			if err != nil {
				return fmt.Errorf("failed to get ip from server: %v", err)
			}

			// Wait until the Client sees the server as up.
			if err := harness.WaitUntilServing(ctx, args.machine, servingIP, args.port); err != nil {
				return fmt.Errorf("failed to wait for serving: %v", err)
			}
			return nil
		}(); err != nil {
			b.Fatal(err)
		}
	}
}
