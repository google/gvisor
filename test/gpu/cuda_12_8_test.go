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

var testSuiteCompatibility = map[string]cuda.Compatibility{
	"0_Introduction":            &cuda.NoCrossCompile{},
	"1_Utilities":               &cuda.NoCrossCompile{},
	"2_Concepts_and_Techniques": &cuda.NoCrossCompile{},
	"3_CUDA_Features":           &cuda.NoCrossCompile{},
	"4_CUDA_Libraries":          &cuda.NoCrossCompile{},
	"5_Domain_Specific":         &cuda.NoCrossCompile{},
	"6_Performance":             &cuda.NoCrossCompile{},
}

// TODO(b/388095023): Enable these tests once they are tested.
var skippedTestSuites = map[string]string{
	"1_Utilities":               "TODO: not yet tested",
	"2_Concepts_and_Techniques": "TODO: not yet tested",
	"3_CUDA_Features":           "TODO: not yet tested",
	"4_CUDA_Libraries":          "TODO: not yet tested",
	"5_Domain_Specific":         "TODO: not yet tested",
	"6_Performance":             "TODO: not yet tested",
}

var testCompatibility = map[string]cuda.Compatibility{
	"0_Introduction/simpleAttributes": cuda.RequiresFeatures(cuda.FeaturePersistentL2Caching),
	"0_Introduction/simpleCUDA2GL":    cuda.RequiresFeatures(cuda.FeatureGL),
	"0_Introduction/simpleP2P":        &cuda.RequiresP2P{},
}

var flakyTests = map[string]struct{}{}

var exclusiveTests = map[string]struct{}{
	// Can fail due to
	// "launch failed because launch would exceed cudaLimitDevRuntimePendingLaunchCount"
	// when running in parallel with other tests.
	"3_CUDA_Features/cdpAdvancedQuicksort": {},

	// Performance-intensive tests that tend to make other concurrent tests
	// flake due to their high resource usage.
	"6_Performance/alignedTypes":      {},
	"6_Performance/transpose":         {},
	"6_Performance/UnifiedMemoryPerf": {},
}

// alwaysSkippedTests don't run at all, ever, and are not verified when
// --cuda_verify_compatibility is set.
// Each test is mapped to a reason why it should be skipped.
var alwaysSkippedTests = map[string]string{}

func TestCuda12_8(t *testing.T) {
	ctx := context.Background()
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
		Image:                  "gpu/cuda-tests-12-8",
	}
	cuda.RunCudaTests(ctx, t, args)
}

// TestMain overrides the `test.parallel` flag.
func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	cuda.InitFlags()
	os.Exit(m.Run())
}
