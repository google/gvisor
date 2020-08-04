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
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// see Dockerfile '//images/benchmarks/httpd'.
var docs = map[string]string{
	"notfound": "notfound",
	"1Kb":      "latin1k.txt",
	"10Kb":     "latin10k.txt",
	"100Kb":    "latin100k.txt",
	"1000Kb":   "latin1000k.txt",
	"1Mb":      "latin1024k.txt",
	"10Mb":     "latin10240k.txt",
}

// BenchmarkHttpdConcurrency iterates the concurrency argument and tests
// how well the runtime under test handles requests in parallel.
func BenchmarkHttpdConcurrency(b *testing.B) {
	// Grab a machine for the client and server.
	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get client: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get server: %v", err)
	}
	defer serverMachine.CleanUp()

	// The test iterates over client concurrency, so set other parameters.
	concurrency := []int{1, 25, 50, 100, 1000}

	for _, c := range concurrency {
		b.Run(fmt.Sprintf("%d", c), func(b *testing.B) {
			hey := &tools.Hey{
				Requests:    10000,
				Concurrency: c,
				Doc:         docs["10Kb"],
			}
			runHttpd(b, clientMachine, serverMachine, hey, false /* reverse */)
		})
	}
}

// BenchmarkHttpdDocSize iterates over different sized payloads, testing how
// well the runtime handles sending different payload sizes.
func BenchmarkHttpdDocSize(b *testing.B) {
	benchmarkHttpdDocSize(b, false /* reverse */)
}

// BenchmarkReverseHttpdDocSize iterates over different sized payloads, testing
// how well the runtime handles receiving different payload sizes.
func BenchmarkReverseHttpdDocSize(b *testing.B) {
	benchmarkHttpdDocSize(b, true /* reverse */)
}

func benchmarkHttpdDocSize(b *testing.B, reverse bool) {
	b.Helper()

	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer serverMachine.CleanUp()

	for name, filename := range docs {
		concurrency := []int{1, 25, 50, 100, 1000}
		for _, c := range concurrency {
			b.Run(fmt.Sprintf("%s_%d", name, c), func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    10000,
					Concurrency: c,
					Doc:         filename,
				}
				runHttpd(b, clientMachine, serverMachine, hey, reverse)
			})
		}
	}
}

// runHttpd runs a single test run.
func runHttpd(b *testing.B, clientMachine, serverMachine harness.Machine, hey *tools.Hey, reverse bool) {
	b.Helper()

	// Grab a container from the server.
	ctx := context.Background()
	var server *dockerutil.Container
	if reverse {
		server = serverMachine.GetNativeContainer(ctx, b)
	} else {
		server = serverMachine.GetContainer(ctx, b)
	}

	defer server.CleanUp(ctx)

	// Copy the docs to /tmp and serve from there.
	cmd := "mkdir -p /tmp/html; cp -r /local/* /tmp/html/.; apache2 -X"
	port := 80

	// Start the server.
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/httpd",
		Ports: []int{port},
		Env: []string{
			// Standard environmental variables for httpd.
			"APACHE_RUN_DIR=/tmp",
			"APACHE_RUN_USER=nobody",
			"APACHE_RUN_GROUP=nogroup",
			"APACHE_LOG_DIR=/tmp",
			"APACHE_PID_FILE=/tmp/apache.pid",
		},
	}, "sh", "-c", cmd); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}

	ip, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to find server ip: %v", err)
	}

	servingPort, err := server.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to find server port %d: %v", port, err)
	}

	// Check the server is serving.
	harness.WaitUntilServing(ctx, clientMachine, ip, servingPort)

	var client *dockerutil.Container
	// Grab a client.
	if reverse {
		client = clientMachine.GetContainer(ctx, b)
	} else {
		client = clientMachine.GetNativeContainer(ctx, b)
	}
	defer client.CleanUp(ctx)

	b.ResetTimer()
	server.RestartProfiles()
	for i := 0; i < b.N; i++ {
		out, err := client.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/hey",
		}, hey.MakeCmd(ip, servingPort)...)
		if err != nil {
			b.Fatalf("run failed with: %v", err)
		}

		b.StopTimer()
		hey.Report(b, out)
		b.StartTimer()
	}
}
