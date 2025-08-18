// Copyright 2025 The gVisor Authors.
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

// Package cuda_12_8_test tests basic CUDA workloads for CUDA 12.8.
package cuda_12_8_test

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/gpu/cuda"
)

var testSuiteCompatibility = map[string]cuda.Compatibility{}

// TODO(b/388095023): Enable these tests once they are tested.
var skippedTestSuites = map[string]string{}

var testCompatibility = map[string]cuda.Compatibility{}

var flakyTests = map[string]struct{}{}

var exclusiveTests = map[string]struct{}{}

// TODO(zkoopmans): Enable these tests once they pass.
var alwaysSkippedTests = map[string]string{
	"4_CUDA_Libraries/cudaNvSci":           "TODO - Debug",
	"5_Domain_Specific/simpleD3D11":        "TODO - Debug",
	"5_Domain_Specific/simpleD3D12":        "TODO - Debug",
	"5_Domain_Specific/simpleD3D11Texture": "TODO - Debug",
	"7_libNVVM/syscalls":                   "TODO - Debug",
	"7_libNVVM/cuda-shared-memory":         "TODO - Debug",
	"7_libNVVM/device-side-launch":         "TODO - Debug",
}

// TestCuda12_8 tests basic CUDA workloads for CUDA 12.8.
func TestCuda12_8(t *testing.T) {
	ctx := context.Background()
	const image = "gpu/cuda-tests-12-8"

	cudaVersion, err := dockerutil.MaxSuportedCUDAVersion(ctx, t)
	if err != nil {
		t.Fatalf("failed to get CUDA version: %v", err)
	}
	if !cudaVersion.IsAtLeast(dockerutil.MustParseCudaVersion("12.8")) {
		t.Skipf("CUDA version %s is not at least 12.8, skipping test", cudaVersion)
	}
	args := &cuda.RunCudaTestArgs{
		TestSuiteCompatibility: testSuiteCompatibility,
		SkippedTestSuites:      skippedTestSuites,
		TestCompatibility:      testCompatibility,
		FlakyTests:             flakyTests,
		ExclusiveTests:         exclusiveTests,
		AlwaysSkippedTests:     alwaysSkippedTests,
		Image:                  image,
	}
	cuda.RunCudaTests(ctx, t, args)
}

// TestMain overrides the `test.parallel` flag.
func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	cuda.InitFlags()
	os.Exit(m.Run())
}
