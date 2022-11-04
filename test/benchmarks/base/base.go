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

// Package base holds utility methods common to the base tests.
package base

import (
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// ServerArgs wraps args for startServers and runServerWorkload.
type ServerArgs struct {
	Machine harness.Machine
	Port    int
	RunOpts dockerutil.RunOpts
	Cmd     []string
}

// StartServers starts b.N containers defined by 'runOpts' and 'cmd' and uses
// 'machine' to check that each is up.
func StartServers(ctx context.Context, b *testing.B, args ServerArgs) []*dockerutil.Container {
	b.Helper()
	servers := make([]*dockerutil.Container, 0, b.N)

	// Create N servers and wait until each of them is serving.
	for i := 0; i < b.N; i++ {
		server := args.Machine.GetContainer(ctx, b)
		servers = append(servers, server)
		if err := server.Spawn(ctx, args.RunOpts, args.Cmd...); err != nil {
			CleanUpContainers(ctx, servers)
			b.Fatalf("failed to spawn node instance: %v", err)
		}

		// Wait until the server is up.
		if err := harness.WaitUntilContainerServing(ctx, args.Machine, server, args.Port); err != nil {
			CleanUpContainers(ctx, servers)
			b.Fatalf("failed to wait for serving")
		}
	}
	return servers
}

// CleanUpContainers cleans up a slice of containers.
func CleanUpContainers(ctx context.Context, containers []*dockerutil.Container) {
	for _, c := range containers {
		if c != nil {
			c.CleanUp(ctx)
		}
	}
}

// RedisInstance returns a Redis container and its reachable IP.
func RedisInstance(ctx context.Context, b *testing.B, machine harness.Machine) *dockerutil.Container {
	b.Helper()
	// Spawn a redis instance for the app to use.
	redis := machine.GetNativeContainer(ctx, b)
	if err := redis.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/redis",
	}); err != nil {
		redis.CleanUp(ctx)
		b.Fatalf("failed to spawn redis instance: %v", err)
	}

	if out, err := redis.WaitForOutput(ctx, "Ready to accept connections", 3*time.Second); err != nil {
		redis.CleanUp(ctx)
		b.Fatalf("failed to start redis server: %v %s", err, out)
	}
	return redis
}
