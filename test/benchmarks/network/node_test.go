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
package network

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

var h harness.Harness

// BenchmarkNode runs requests using 'hey' against a Node server run on
// 'runtime'. The server responds to requests by grabbing some data in a
// redis instance and returns the data in its reponse. The test loops through
// increasing amounts of concurency for requests.
func BenchmarkNode(b *testing.B) {
	concurrency := []int{1, 5, 10, 25}
	for _, c := range concurrency {
		param := tools.Parameter{
			Name:  "concurrency",
			Value: strconv.Itoa(c),
		}
		name, err := tools.ParametersToName(param)
		if err != nil {
			b.Fatalf("Failed to parse parameters: %v", err)
		}
		requests := b.N
		if requests < c {
			b.Logf("b.N is %d must be greater than threads %d. Consider running with --test.benchtime=Nx where N >= %d", b.N, c, c)
			requests = c
		}
		b.Run(name, func(b *testing.B) {
			hey := &tools.Hey{
				Requests:    requests,
				Concurrency: c,
			}
			runNode(b, hey)
		})
	}
}

// runNode runs the test for a given # of requests and concurrency.
func runNode(b *testing.B, hey *tools.Hey) {
	b.Helper()

	// The machine to hold Redis and the Node Server.
	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer serverMachine.CleanUp()

	// The machine to run 'hey'.
	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer clientMachine.CleanUp()

	ctx := context.Background()

	// Spawn a redis instance for the app to use.
	redis := serverMachine.GetNativeContainer(ctx, b)
	if err := redis.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/redis",
	}); err != nil {
		b.Fatalf("failed to spwan redis instance: %v", err)
	}
	defer redis.CleanUp(ctx)

	if out, err := redis.WaitForOutput(ctx, "Ready to accept connections", 3*time.Second); err != nil {
		b.Fatalf("failed to start redis server: %v %s", err, out)
	}
	redisIP, err := redis.FindIP(ctx, false)
	if err != nil {
		b.Fatalf("failed to get IP from redis instance: %v", err)
	}

	// Node runs on port 8080.
	port := 8080

	// Start-up the Node server.
	nodeApp := serverMachine.GetContainer(ctx, b)
	if err := nodeApp.Spawn(ctx, dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
		Ports:   []int{port},
	}, "node", "index.js", redisIP.String()); err != nil {
		b.Fatalf("failed to spawn node instance: %v", err)
	}
	defer nodeApp.CleanUp(ctx)

	servingIP, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to get ip from server: %v", err)
	}

	servingPort, err := nodeApp.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to port from node instance: %v", err)
	}

	// Wait until the Client sees the server as up.
	harness.WaitUntilServing(ctx, clientMachine, servingIP, servingPort)

	heyCmd := hey.MakeCmd(servingIP, servingPort)

	nodeApp.RestartProfiles()
	b.ResetTimer()

	// the client should run on Native.
	client := clientMachine.GetNativeContainer(ctx, b)
	out, err := client.Run(ctx, dockerutil.RunOpts{
		Image: "benchmarks/hey",
	}, heyCmd...)
	if err != nil {
		b.Fatalf("hey container failed: %v logs: %s", err, out)
	}

	// Stop the timer to parse the data and report stats.
	b.StopTimer()
	hey.Report(b, out)
}

func TestMain(m *testing.M) {
	h.Init()
	os.Exit(m.Run())
}
