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

package database

import (
	"context"
	"os"
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

// BenchmarkRedis runs redis-benchmark against a redis instance and reports
// data in queries per second. Each is reported by named operation (e.g. LPUSH).
func BenchmarkRedis(b *testing.B) {
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
	for _, operation := range operations {
		param := tools.Parameter{
			Name:  "operation",
			Value: operation,
		}
		name, err := tools.ParametersToName(param)
		if err != nil {
			b.Fatalf("Failed to parse paramaters: %v", err)
		}
		b.Run(name, func(b *testing.B) {
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

			ip, err := serverMachine.IPAddress()
			if err != nil {
				b.Fatalf("failed to get IP from server: %v", err)
			}

			serverPort, err := server.FindPort(ctx, port)
			if err != nil {
				b.Fatalf("failed to get IP from server: %v", err)
			}

			if err = harness.WaitUntilServing(ctx, clientMachine, ip, serverPort); err != nil {
				b.Fatalf("failed to start redis with: %v", err)
			}

			client := clientMachine.GetNativeContainer(ctx, b)
			defer client.CleanUp(ctx)

			redis := tools.Redis{
				Operation: operation,
			}
			b.ResetTimer()
			out, err := client.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/redis",
			}, redis.MakeCmd(ip, serverPort, b.N /*requests*/)...)
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
