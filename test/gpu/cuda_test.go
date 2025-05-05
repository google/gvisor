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

// Package cuda_test tests basic CUDA workloads.
package cuda_test

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

// testCompatibility maps test names to their compatibility data.
// Unmapped test names are assumed to be fully compatible.
var testCompatibility = map[string]cuda.Compatibility{
	"0_Introduction/simpleAttributes": cuda.RequiresFeatures(cuda.FeaturePersistentL2Caching),
	"0_Introduction/simpleCUDA2GL":    cuda.RequiresFeatures(cuda.FeatureGL),
	"0_Introduction/simpleP2P":        &cuda.RequiresP2P{},
	"2_Concepts_and_Techniques/cuHook": &cuda.BrokenEverywhere{
		Reason: "Requires ancient version of glibc (<=2.33)",
	},
	"2_Concepts_and_Techniques/EGLStream_CUDA_Interop": &cuda.BrokenEverywhere{
		Reason: "Requires newer version of EGL libraries than Ubuntu has (eglCreateStreamKHR)",
	},
	"2_Concepts_and_Techniques/EGLStream_CUDA_CrossGPU": cuda.MultiCompatibility(
		&cuda.RequiresMultiGPU{},
		&cuda.BrokenEverywhere{
			Reason: "Requires newer version of EGL libraries than Ubuntu has (eglCreateStreamKHR)",
		},
	),
	"2_Concepts_and_Techniques/EGLSync_CUDAEvent_Interop":  &cuda.OnlyOnWindows{},
	"2_Concepts_and_Techniques/streamOrderedAllocationIPC": &cuda.BrokenInGVisor{},
	"2_Concepts_and_Techniques/streamOrderedAllocationP2P": &cuda.RequiresP2P{},
	"3_CUDA_Features/bf16TensorCoreGemm":                   cuda.RequiresFeatures(cuda.FeatureTensorCores),
	"3_CUDA_Features/cdpAdvancedQuicksort":                 cuda.RequiresFeatures(cuda.FeatureDynamicParallelism),
	"3_CUDA_Features/cudaCompressibleMemory":               cuda.RequiresFeatures(cuda.FeatureCompressibleMemory),
	"3_CUDA_Features/dmmaTensorCoreGemm":                   cuda.RequiresFeatures(cuda.FeatureTensorCores),
	"3_CUDA_Features/memMapIPCDrv":                         &cuda.RequiresMultiGPU{},
	"3_CUDA_Features/tf32TensorCoreGemm":                   cuda.RequiresFeatures(cuda.FeatureTensorCores),
	"4_CUDA_Libraries/conjugateGradientMultiDeviceCG":      cuda.MultiCompatibility(&cuda.RequiresMultiGPU{}, &cuda.BrokenInGVisor{}),
	"4_CUDA_Libraries/cudaNvSci":                           &cuda.RequiresNvSci{},
	"4_CUDA_Libraries/cudaNvSciNvMedia":                    &cuda.RequiresNvSci{},
	"4_CUDA_Libraries/cuDLAErrorReporting":                 &cuda.OnlyOnWindows{},
	"4_CUDA_Libraries/cuDLAHybridMode":                     &cuda.OnlyOnWindows{},
	"4_CUDA_Libraries/cuDLAStandaloneMode":                 &cuda.OnlyOnWindows{},
	"4_CUDA_Libraries/cuDLALayerwiseStatsHybrid":           &cuda.OnlyOnWindows{},
	"4_CUDA_Libraries/cuDLALayerwiseStatsStandalone":       &cuda.OnlyOnWindows{},
	"4_CUDA_Libraries/simpleCUFFT_2d_MGPU":                 &cuda.RequiresMultiGPU{},
	"4_CUDA_Libraries/simpleCUFFT_MGPU":                    &cuda.RequiresMultiGPU{},
	"5_Domain_Specific/fluidsD3D9":                         &cuda.OnlyOnWindows{},
	"5_Domain_Specific/fluidsGL":                           cuda.RequiresFeatures(cuda.FeatureGL),
	"5_Domain_Specific/fluidsGLES":                         &cuda.OnlyOnWindows{},
	"5_Domain_Specific/nbody_opengles":                     &cuda.OnlyOnWindows{},
	"5_Domain_Specific/nbody_screen":                       &cuda.OnlyOnWindows{},
	"5_Domain_Specific/postProcessGL":                      cuda.RequiresFeatures(cuda.FeatureGL),
	"5_Domain_Specific/simpleD3D10":                        &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D10RenderTarget":            &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D10Texture":                 &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D11":                        &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D11Texture":                 &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D12":                        &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D9":                         &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleD3D9Texture":                  &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleGLES":                         &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleGLES_EGLOutput":               &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleGLES_screen":                  &cuda.OnlyOnWindows{},
	"5_Domain_Specific/simpleVulkan":                       cuda.RequiresFeatures(cuda.FeatureGL),
	"5_Domain_Specific/simpleVulkanMMAP":                   cuda.RequiresFeatures(cuda.FeatureGL),
	"5_Domain_Specific/SLID3D10Texture":                    &cuda.OnlyOnWindows{},
	"5_Domain_Specific/VFlockingD3D10":                     &cuda.OnlyOnWindows{},
	"5_Domain_Specific/vulkanImageCUDA":                    cuda.RequiresFeatures(cuda.FeatureGL),
}

// flakyTests is a list of tests that are flaky.
// These will be retried up to 3 times in parallel before running 3 times
// serially.
var flakyTests = map[string]struct{}{
	"3_CUDA_Features/cdpAdvancedQuicksort": {},
}

// exclusiveTests is a list of tests that must run exclusively (i.e. with
// no other test running on the machine at the same time), or they will
// likely fail. These tests are not attempted to be run in parallel.
// This is usually the case for performance tests or tests that use a lot
// of resources in general.
// This saves the trouble to run them in parallel, while also avoiding
// causing spurious failures for the tests that happen to be running in
// parallel with them.
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

// TestCUDA runs CUDA tests.
func TestCUDA(t *testing.T) {
	ctx := context.Background()
	args := &cuda.RunCudaTestArgs{
		TestSuiteCompatibility: testSuiteCompatibility,
		TestCompatibility:      testCompatibility,
		FlakyTests:             flakyTests,
		ExclusiveTests:         exclusiveTests,
		AlwaysSkippedTests:     alwaysSkippedTests,
		Image:                  "gpu/cuda-tests",
	}
	cuda.RunCudaTests(ctx, t, args)
}

// TestMain overrides the `test.parallel` flag.
func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	cuda.InitFlags()
	os.Exit(m.Run())
}
