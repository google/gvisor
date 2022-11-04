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

	// Start the server.
	if err := server.Spawn(ctx, serverOpts, serverCmd...); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}

	// Make sure the server is serving.
	harness.WaitUntilContainerServing(ctx, clientMachine, server, port)

	// Run the client.
	b.ResetTimer()
	out, err := client.Run(ctx, dockerutil.RunOpts{
		Image: "benchmarks/hey",
		Links: []string{server.MakeLink("server")},
	}, hey.MakeCmd("server", port)...)
	if err != nil {
		b.Fatalf("run failed with: %v", err)
	}
	b.StopTimer()
	hey.Report(b, out)
}
