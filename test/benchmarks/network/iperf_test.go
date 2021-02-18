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
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

func BenchmarkIperf(b *testing.B) {
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
	ctx := context.Background()
	for _, bm := range []struct {
		name       string
		clientFunc func(context.Context, testutil.Logger) *dockerutil.Container
		serverFunc func(context.Context, testutil.Logger) *dockerutil.Container
	}{
		// We are either measuring the server or the client. The other should be
		// runc. e.g. Upload sees how fast the runtime under test uploads to a native
		// server.
		{
			name:       "Upload",
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Download",
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
	} {
		name, err := tools.ParametersToName(tools.Parameter{
			Name:  "operation",
			Value: bm.name,
		})
		if err != nil {
			b.Fatalf("Failed to parse parameters: %v", err)
		}
		b.Run(name, func(b *testing.B) {
			// Set up the containers.
			server := bm.serverFunc(ctx, b)
			defer server.CleanUp(ctx)
			client := bm.clientFunc(ctx, b)
			defer client.CleanUp(ctx)

			// iperf serves on port 5001 by default.
			port := 5001

			// Start the server.
			if err := server.Spawn(ctx, dockerutil.RunOpts{
				Image: "benchmarks/iperf",
				Ports: []int{port},
			}, "iperf", "-s"); err != nil {
				b.Fatalf("failed to start server with: %v", err)
			}

			ip, err := serverMachine.IPAddress()
			if err != nil {
				b.Fatalf("failed to find server ip: %v", err)
			}

			servingPort, err := server.FindPort(ctx, port)
			if err != nil {
				b.Fatalf("failed to find port %d: %v", port, err)
			}

			// Make sure the server is up and serving before we run.
			if err := harness.WaitUntilServing(ctx, clientMachine, ip, servingPort); err != nil {
				b.Fatalf("failed to wait for server: %v", err)
			}

			iperf := tools.Iperf{
				Num: b.N, // KB for the client to send.
			}

			// Run the client.
			b.ResetTimer()
			out, err := client.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/iperf",
			}, iperf.MakeCmd(ip, servingPort)...)
			if err != nil {
				b.Fatalf("failed to run client: %v", err)
			}
			b.StopTimer()
			iperf.Report(b, out)
			b.StartTimer()
		})
	}
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
