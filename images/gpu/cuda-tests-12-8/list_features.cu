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

// This program lists the features of the CUDA device that are available.
// It is used as part of the list_features.sh script.
// Each line it outputs is a CUDA feature name, prefixed by either
// "PRESENT: " or "ABSENT: ".

#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>

#include "cuda_test_util.h"  // NOLINT(build/include)

void printFeature(const char* feature, bool have) {
  if (have) {
    printf("PRESENT: %s\n", feature);
  } else {
    printf("ABSENT: %s\n", feature);
  }
}

int main(int argc, char *argv[]) {
  int cuda_device;
  CHECK_CUDA(cudaGetDevice(&cuda_device));
  cudaDeviceProp properties;
  CHECK_CUDA(cudaGetDeviceProperties(&properties, cuda_device));
  bool cdpCapable =
      (properties.major == 3 && properties.minor >= 5) || properties.major >= 4;
  printFeature("DYNAMIC_PARALLELISM", cdpCapable);
  printFeature(
      "PERSISTENT_L2_CACHING", properties.persistingL2CacheMaxSize > 0);
  // Tensor cores are a thing in Volta (SM8X)
  printFeature("TENSOR_CORES", properties.major >= 8);
  int isCompressionAvailable;
  CHECK_CUDA_RESULT(
      cuDeviceGetAttribute(&isCompressionAvailable,
                           CU_DEVICE_ATTRIBUTE_GENERIC_COMPRESSION_SUPPORTED,
                           cuda_device));
  printFeature("COMPRESSIBLE_MEMORY", isCompressionAvailable != 0);
  bool p2pAvailable = false;
  int gpuCount = -1;
  CHECK_CUDA(cudaGetDeviceCount(&gpuCount));
  printf("// Number of GPUs: %d\n", gpuCount);
  if (gpuCount >= 2) {
    int canAccessAToB = -1;
    CHECK_CUDA(cudaDeviceCanAccessPeer(&canAccessAToB, 0, 1));
    printf("// CUDA P2P: 0 -> 1: %d\n", canAccessAToB);
    int canAccessBToA = -1;
    CHECK_CUDA(cudaDeviceCanAccessPeer(&canAccessBToA, 1, 0));
    printf("// CUDA P2P: 1 -> 0: %d\n", canAccessBToA);
    p2pAvailable = canAccessAToB > 0 && canAccessBToA > 0;
  }
  printFeature("P2P", p2pAvailable);
}
