// Copyright 2023 The gVisor Authors.
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

#ifndef THIRD_PARTY_GVISOR_IMAGES_GPU_CUDA_TESTS_CUDA_TEST_UTIL_H_
#define THIRD_PARTY_GVISOR_IMAGES_GPU_CUDA_TESTS_CUDA_TEST_UTIL_H_

#include <iostream>

#define CHECK_CUDA(expr)                                                     \
  do {                                                                       \
    cudaError_t code = (expr);                                               \
    if (code != cudaSuccess) {                                               \
      std::cout << "Check failed at " << __FILE__ << ":" << __LINE__ << ": " \
                << #expr << ": " << cudaGetErrorString(code) << std::endl;   \
      abort();                                                               \
    }                                                                        \
  } while (0)

#endif  // THIRD_PARTY_GVISOR_IMAGES_GPU_CUDA_TESTS_CUDA_TEST_UTIL_H_
