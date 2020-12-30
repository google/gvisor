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
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkRuby runs requests using 'hey' against a ruby application server.
// On start, ruby app generates some random data and pushes it to a redis
// instance. On a request, the app grabs for random entries from the redis
// server, publishes it to a document, and returns the doc to the request.
func BenchmarkRuby(b *testing.B) {
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
		b.Run(name, func(b *testing.B) {
			hey := &tools.Hey{
				Requests:    b.N,
				Concurrency: c,
			}
			runRuby(b, hey)
		})
	}
}

// runRuby runs the test for a given # of requests and concurrency.
func runRuby(b *testing.B, hey *tools.Hey) {
	// The machine to hold Redis and the Ruby Server.
	serverMachine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer serverMachine.CleanUp()

	// The machine to run 'hey'.
	clientMachine, err := harness.GetMachine()
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

	// Ruby runs on port 9292.
	const port = 9292

	// Start-up the Ruby server.
	rubyApp := serverMachine.GetContainer(ctx, b)
	if err := rubyApp.Spawn(ctx, dockerutil.RunOpts{
		Image:   "benchmarks/ruby",
		WorkDir: "/app",
		Links:   []string{redis.MakeLink("redis")},
		Ports:   []int{port},
		Env: []string{
			fmt.Sprintf("PORT=%d", port),
			"WEB_CONCURRENCY=20",
			"WEB_MAX_THREADS=20",
			"RACK_ENV=production",
			fmt.Sprintf("HOST=%s", redisIP),
		},
		User: "nobody",
	}, "sh", "-c", "/usr/bin/puma"); err != nil {
		b.Fatalf("failed to spawn node instance: %v", err)
	}
	defer rubyApp.CleanUp(ctx)

	servingIP, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to get ip from server: %v", err)
	}

	servingPort, err := rubyApp.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to port from node instance: %v", err)
	}

	// Wait until the Client sees the server as up.
	if err := harness.WaitUntilServing(ctx, clientMachine, servingIP, servingPort); err != nil {
		b.Fatalf("failed to wait until  serving: %v", err)
	}
	heyCmd := hey.MakeCmd(servingIP, servingPort)

	// the client should run on Native.
	b.ResetTimer()
	client := clientMachine.GetNativeContainer(ctx, b)
	defer client.CleanUp(ctx)
	out, err := client.Run(ctx, dockerutil.RunOpts{
		Image: "benchmarks/hey",
	}, heyCmd...)
	if err != nil {
		b.Fatalf("hey container failed: %v logs: %s", err, out)
	}
	b.StopTimer()
	hey.Report(b, out)
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
