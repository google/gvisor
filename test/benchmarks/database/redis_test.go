// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 3.0 (the "License");
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

package database

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// All possible operations from redis. Note: "ping" will
// run both PING_INLINE and PING_BUILD.
var operations []string = []string{
	"PING_INLINE",
	"PING_BULK",
	"SET",
	"GET",
	"INCR",
	"LPUSH",
	"RPUSH",
	"LPOP",
	"RPOP",
	"SADD",
	"HSET",
	"SPOP",
	"LRANGE_100",
	"LRANGE_300",
	"LRANGE_500",
	"LRANGE_600",
	"MSET",
}

// BenchmarkAllRedisOperations runs redis-benchmark against a redis instance and reports
// data in queries per second. Each is reported by named operation (e.g. LPUSH).
func BenchmarkAllRedisOperations(b *testing.B) {
	doBenchmarkRedis(b, operations)
}

// BenchmarkRedisDashboard runs a subset of redis benchmarks for the performance dashboard.
func BenchmarkRedis(b *testing.B) {
	doBenchmarkRedis(b, []string{"SET", "LPUSH", "LRANGE_100"})
}

func doBenchmarkRedis(b *testing.B, ops []string) {
	clientMachine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer serverMachine.CleanUp()

	// Redis runs on port 6379 by default.
	port := 6379
	ctx := context.Background()
	server := serverMachine.GetContainer(ctx, b)
	defer server.CleanUp(ctx)

	// The redis docker container takes no arguments to run a redis server.
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/redis",
		Ports: []int{port},
	}); err != nil {
		b.Fatalf("failed to start redis server with: %v", err)
	}

	if out, err := server.WaitForOutput(ctx, "Ready to accept connections", 3*time.Second); err != nil {
		b.Fatalf("failed to start redis server: %v %s", err, out)
	}

	if err = harness.WaitUntilContainerServing(ctx, clientMachine, server, port); err != nil {
		b.Fatalf("failed to start redis with: %v", err)
	}
	for _, operation := range ops {
		param := tools.Parameter{
			Name:  "operation",
			Value: operation,
		}
		name, err := tools.ParametersToName(param)
		if err != nil {
			b.Fatalf("Failed to parse paramaters: %v", err)
		}

		b.Run(name, func(b *testing.B) {
			redis := tools.Redis{
				Operation: operation,
			}

			// Sometimes, the connection between the redis client and server can be
			// flaky such that the client returns infinity as the QPS measurement for
			// a give operation. If this happens, retry the client up to 3 times.
			out := "inf"
			for retries := 0; strings.Contains(out, "inf") && retries < 3; retries++ {
				b.ResetTimer()
				client := clientMachine.GetNativeContainer(ctx, b)
				defer client.CleanUp(ctx)

				out, err = client.Run(ctx, dockerutil.RunOpts{
					Image: "benchmarks/redis",
					Links: []string{server.MakeLink("redis")},
				}, redis.MakeCmd("redis", port, b.N /*requests*/)...)
			}

			if err != nil {
				b.Fatalf("redis-benchmark failed with: %v", err)
			}

			b.StopTimer()
			redis.Report(b, out)
		})
	}
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
