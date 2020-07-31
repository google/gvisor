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

// BenchmarkNginxConcurrency iterates the concurrency argument and tests
// how well the runtime under test handles requests in parallel.
// TODO(zkoopmans): Update with different doc sizes like Httpd.
func BenchmarkNginxConcurrency(b *testing.B) {
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

	concurrency := []int{1, 5, 10, 25}
	for _, c := range concurrency {
		b.Run(fmt.Sprintf("%d", c), func(b *testing.B) {
			hey := &tools.Hey{
				Requests:    1000,
				Concurrency: c,
			}
			runNginx(b, clientMachine, serverMachine, hey)
		})
	}
}

// runHttpd runs a single test run.
func runNginx(b *testing.B, clientMachine, serverMachine harness.Machine, hey *tools.Hey) {
	b.Helper()

	// Grab a container from the server.
	ctx := context.Background()
	server := serverMachine.GetContainer(ctx, b)
	defer server.CleanUp(ctx)

	port := 80
	// Start the server.
	if err := server.Spawn(ctx,
		dockerutil.RunOpts{
			Image: "benchmarks/nginx",
			Ports: []int{port},
		}); err != nil {
		b.Fatalf("server failed to start: %v", err)
	}

	ip, err := server.FindIP(ctx, false /* ipv6 */)
	if err != nil {
		b.Fatalf("failed to find server ip: %v", err)
	}

	// Check the server is serving.
	harness.WaitUntilServing(ctx, clientMachine, ip, port)

	// Grab a client.
	client := clientMachine.GetNativeContainer(ctx, b)
	defer client.CleanUp(ctx)

	b.ResetTimer()
	server.RestartProfiles()
	for i := 0; i < b.N; i++ {
		out, err := client.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/hey",
		}, hey.MakeCmd(ip, port)...)
		if err != nil {
			b.Fatalf("run failed with: %v", err)
		}
		b.StopTimer()
		hey.Report(b, out)
		b.StartTimer()
	}
}
