// Copyright 2024 The gVisor Authors.
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

package triton

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

const (
	tritonImage = "gpu/triton"
)

var (
	models = []string{
		"densenet_onnx",
		"inception_graphdef",
		"simple",
		"simple_dyna_sequence",
		// "simple_identity", // Doesn't work w/ perf_analyzer.
		"simple_int8",
		"simple_sequence",
		// "simple_string", // Doesn't work w/ perf_analyzer.
	}
)

// BenchmarkTritonSharedMemory runs a Triton workload with shared memory enabled.
// This takes the network overhead out of the loop showing a GPU bound workload.
// gVisor is expected to perform on par with native.
func BenchmarkTritonSharedMemory(b *testing.B) {
	ctx := context.Background()
	runTest(ctx, b, "system")
}

// BenchmarkTritonNetwork runs a Triton workload with shared memory disabled.
// This adds the network overhead to the loop showing a I/O bound workload.
// gVisor is expected to perform worse than native due to I/O overhead.
// For practical cases, this test isn't very useful since it is somewhat equivalent
// to a static serving benchmark (e.g. //test/benchmarks/network/nginx_test.go)
func BenchmarkTritonNetwork(b *testing.B) {
	ctx := context.Background()
	runTest(ctx, b, "none")
}

func runTest(ctx context.Context, b *testing.B, sharedMemory string) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("Failed to get server machine: %v", err)
	}
	defer machine.CleanUp()

	server := machine.GetContainer(ctx, b)
	defer server.CleanUp(ctx)
	// opts := dockerutil.GPURunOpts()
	opts := dockerutil.RunOpts{}
	opts.WorkDir = "/opt/tritonserver"
	args := "tritonserver --model-repository /opt/tritonserver/model_repository --load-model=* --model-control-mode=explicit"
	opts.Image = tritonImage
	if err := server.Spawn(ctx, opts, []string{"bash", "-c", args}...); err != nil {
		b.Fatalf("Failed to spawn server: %v", err)
	}

	if out, err := server.WaitForOutput(ctx, "Started Metrics Service at 0.0.0.0:8002", 20*time.Second); err != nil {
		b.Fatalf("Failed to wait for server to start: %v %s", err, out)
	}

	for _, model := range models {
		b.Run(model, func(b *testing.B) {
			runWorkload(ctx, b, model, server, sharedMemory)
		})
	}
}

func runWorkload(ctx context.Context, b *testing.B, model string, server *dockerutil.Container, sharedMemory string) {
	args := fmt.Sprintf("perf_analyzer -m %s --request-count %d --shared-memory %s", model, b.N, sharedMemory)
	out, err := server.Exec(ctx, dockerutil.ExecOpts{}, "bash", "-c", args)
	if err != nil {
		b.Fatalf("Failed to run workload: %v %s", err, out)
	}
	tools.ReportTriton(b, out)
}
