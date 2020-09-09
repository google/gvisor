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
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// runStaticServer runs static serving workloads (httpd, nginx).
func runStaticServer(b *testing.B, serverOpts dockerutil.RunOpts, serverCmd []string, port int, hey *tools.Hey, reverse bool) {
	b.Helper()
	ctx := context.Background()

	// Get two machines: a client and server.
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

	// Make the containers. 'reverse=true' specifies that the client should use the
	// runtime under test.
	var client, server *dockerutil.Container
	if reverse {
		client = clientMachine.GetContainer(ctx, b)
		server = serverMachine.GetNativeContainer(ctx, b)
	} else {
		client = clientMachine.GetNativeContainer(ctx, b)
		server = serverMachine.GetContainer(ctx, b)
	}
	defer client.CleanUp(ctx)
	defer server.CleanUp(ctx)

	// Start the server.
	if err := server.Spawn(ctx, serverOpts, serverCmd...); err != nil {
		b.Fatalf("failed to start server: %v", err)
	}

	// Get its IP.
	ip, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to find server ip: %v", err)
	}

	// Get the published port.
	servingPort, err := server.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to find server port %d: %v", port, err)
	}

	// Make sure the server is serving.
	harness.WaitUntilServing(ctx, clientMachine, ip, servingPort)
	b.ResetTimer()
	server.RestartProfiles()
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
