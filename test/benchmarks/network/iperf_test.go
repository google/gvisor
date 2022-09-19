// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"testing"
	"time"

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
			if out, err := server.WaitForOutput(ctx, fmt.Sprintf("Server listening on TCP port %d", port), 10*time.Second); err != nil {
				b.Fatalf("failed to wait for iperf server: %v %s", err, out)
			}

			iperf := tools.Iperf{
				Num: b.N, // KB for the client to send.
			}

			// Run the client.
			b.ResetTimer()
			out, err := client.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/iperf",
				Links: []string{server.MakeLink("iperfsrv")},
			}, iperf.MakeCmd("iperfsrv", port)...)
			if err != nil {
				b.Fatalf("failed to run client: %v", err)
			}
			b.StopTimer()
			iperf.Report(b, out)
			b.StartTimer()
		})
	}
}

func BenchmarkIperfParameterized(b *testing.B) {
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
		length     int
		parallel   int
		clientFunc func(context.Context, testutil.Logger) *dockerutil.Container
		serverFunc func(context.Context, testutil.Logger) *dockerutil.Container
	}{
		// We are either measuring the server or the client. The other should be
		// runc. e.g. Upload sees how fast the runtime under test uploads to a native
		// server.
		{
			name:       "Upload",
			length:     4,
			parallel:   1,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Upload",
			length:     64,
			parallel:   1,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Upload",
			length:     1024,
			parallel:   1,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Upload",
			length:     4,
			parallel:   16,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Upload",
			length:     64,
			parallel:   16,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Upload",
			length:     1024,
			parallel:   16,
			clientFunc: clientMachine.GetContainer,
			serverFunc: serverMachine.GetNativeContainer,
		},
		{
			name:       "Download",
			length:     4,
			parallel:   1,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
		{
			name:       "Download",
			length:     64,
			parallel:   1,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
		{
			name:       "Download",
			length:     1024,
			parallel:   1,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
		{
			name:       "Download",
			length:     4,
			parallel:   16,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
		{
			name:       "Download",
			length:     64,
			parallel:   16,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
		{
			name:       "Download",
			length:     1024,
			parallel:   16,
			clientFunc: clientMachine.GetNativeContainer,
			serverFunc: serverMachine.GetContainer,
		},
	} {
		name, err := tools.ParametersToName(tools.Parameter{
			Name:  "operation",
			Value: bm.name,
		}, tools.Parameter{
			Name:  "length",
			Value: fmt.Sprintf("%dK", bm.length),
		}, tools.Parameter{
			Name:  "parallel",
			Value: fmt.Sprintf("%d", bm.parallel),
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
			if out, err := server.WaitForOutput(ctx, fmt.Sprintf("Server listening on TCP port %d", port), 10*time.Second); err != nil {
				b.Fatalf("failed to wait for iperf server: %v %s", err, out)
			}

			iperf := tools.Iperf{
				Num:      b.N,       // KB for the client to send.
				Length:   bm.length, // KB for length.
				Parallel: bm.parallel,
			}

			// Run the client.
			b.ResetTimer()
			out, err := client.Run(ctx, dockerutil.RunOpts{
				Image: "benchmarks/iperf",
				Links: []string{server.MakeLink("iperfsrv")},
			}, iperf.MakeCmd("iperfsrv", port)...)
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
