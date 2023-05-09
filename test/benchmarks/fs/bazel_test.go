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

// Package bazel_test benchmarks builds using bazel.
package bazel_test

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/test/benchmarks/fs/fsbench"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// Note: CleanCache versions of this test require running with root permissions.
func BenchmarkBuildABSL(b *testing.B) {
	runBuildBenchmark(b, "benchmarks/absl", "/abseil-cpp", "absl/base/...")
}

// Note: CleanCache versions of this test require running with root permissions.
// Note: This test takes on the order of 6m per permutation for runsc on kvm.
func BenchmarkBuildGRPC(b *testing.B) {
	runBuildBenchmark(b, "benchmarks/build-grpc", "/grpc", ":grpc")
}

func runBuildBenchmark(b *testing.B, image, workDir, target string) {
	b.Helper()
	ctx := context.Background()
	// Get a machine from the Harness on which to run.
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("Failed to get machine: %v", err)
	}
	defer machine.CleanUp()
	fsbench.RunWithDifferentFilesystems(ctx, b, machine, fsbench.FSBenchmark{
		Image:      image,
		WorkDir:    workDir,
		RunCmd:     []string{"bazel", "build", "-c", "opt", target},
		WantOutput: "Build completed successfully",
		CleanCmd:   []string{"blaze", "clean"},
	})
}

// TestMain is the main method for package fs.
func TestMain(m *testing.M) {
	harness.Init()
	harness.SetFixedBenchmarks()
	os.Exit(m.Run())
}
