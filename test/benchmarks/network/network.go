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

// Package network holds benchmarks around raw network performance.
package network

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
	"gvisor.dev/gvisor/test/metricsviz"
)

// runStaticServer runs static serving workloads (httpd, nginx).
func runStaticServer(b *testing.B, serverOpts dockerutil.RunOpts, serverCmd []string, port int, hey *tools.Hey) {
	ctx := context.Background()

	// Get two machines: a client and server.
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

	// Make the containers.
	client := clientMachine.GetNativeContainer(ctx, b)
	defer client.CleanUp(ctx)
	server := serverMachine.GetContainer(ctx, b)
	defer server.CleanUp(ctx)
	defer metricsviz.FromContainerLogs(ctx, b, server)

	// Set CPU affinity if not already explicitly configured.
	if serverOpts.CpusetCpus == "" {
		serverOpts.CpusetCpus = harness.ServerCPUSet()
	}

	// Start the server.
	if err := server.Spawn(ctx, serverOpts, serverCmd...); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}

	// Make sure the server is serving.
	if err := harness.WaitUntilContainerServing(ctx, clientMachine, server, port); err != nil {
		b.Fatalf("server readiness failed: %v", err)
	}

	runHey(b, ctx, client, dockerutil.RunOpts{
		Image:      "benchmarks/hey",
		Links:      []string{server.MakeLink("server")},
		CpusetCpus: harness.ClientCPUSet(),
	}, hey, hey.MakeCmd("server", port)...)
}

// runHey stops timing before reading and reporting the client's output.
func runHey(b *testing.B, ctx context.Context, client *dockerutil.Container, opts dockerutil.RunOpts, hey *tools.Hey, args ...string) {
	b.Helper()
	b.ResetTimer()
	if err := client.Spawn(ctx, opts, args...); err != nil {
		b.Fatalf("failed to start hey: %v", err)
	}
	waitErr := client.Wait(ctx)
	b.StopTimer()
	stdout, stderr, err := client.OutputStreams(ctx)
	if err != nil {
		b.Fatalf("failed to read hey output: %v", err)
	}
	if stderr.Len() != 0 {
		b.Logf("hey stderr: %s", stderr)
	}
	if waitErr != nil {
		b.Fatalf("hey failed: %v\nstdout: %s", waitErr, stdout)
	}
	hey.Report(b, stdout.Bytes())
}
