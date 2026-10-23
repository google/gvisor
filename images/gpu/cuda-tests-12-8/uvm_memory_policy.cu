// Copyright 2026 The gVisor Authors.
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

#include <cuda_runtime.h>
#include <sys/mman.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
void Check(cudaError_t error, const char* operation) {
  if (error != cudaSuccess) {
    std::fprintf(stderr, "FAIL: %s: %s\n", operation,
                 cudaGetErrorString(error));
    std::exit(1);
  }
}
#define CUDA_CHECK(call) Check((call), #call)
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2 || (std::strcmp(argv[1], "unset") != 0 &&
                    std::strcmp(argv[1], "migrate") != 0)) {
    std::fprintf(stderr, "usage: %s unset|migrate\n", argv[0]);
    return 1;
  }
  int ats;
  CUDA_CHECK(cudaDeviceGetAttribute(
      &ats, cudaDevAttrPageableMemoryAccessUsesHostPageTables, 0));
  if (!ats) {
    std::puts("SKIP: ATS pageable memory is unavailable");
    return 0;
  }
  constexpr size_t length = 4 * 1024 * 1024;
  auto* data =
      static_cast<unsigned char*>(mmap(nullptr, length, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (data == MAP_FAILED) {
    std::perror("mmap");
    return 1;
  }
  std::memset(data, 0x5a, length);
#if CUDART_VERSION >= 13000
  const cudaMemLocation cpu{cudaMemLocationTypeHost, 0};
  const cudaMemLocation gpu{cudaMemLocationTypeDevice, 0};
#else
  constexpr int cpu = cudaCpuDeviceId;
  constexpr int gpu = 0;
#endif
  if (std::strcmp(argv[1], "unset") == 0) {
    CUDA_CHECK(
        cudaMemAdvise(data, length, cudaMemAdviseSetPreferredLocation, cpu));
    CUDA_CHECK(
        cudaMemAdvise(data, length, cudaMemAdviseUnsetPreferredLocation, cpu));
  } else {
    // Guest anonymous memory is file-backed in the host address space. The
    // driver's migration fallback must execute in that same address space.
#if CUDART_VERSION >= 13000
    CUDA_CHECK(cudaMemPrefetchAsync(data, length, gpu, 0, 0));
    CUDA_CHECK(cudaMemPrefetchAsync(data, length, cpu, 0, 0));
#else
    CUDA_CHECK(cudaMemPrefetchAsync(data, length, gpu));
    CUDA_CHECK(cudaMemPrefetchAsync(data, length, cpu));
#endif
    CUDA_CHECK(cudaDeviceSynchronize());
  }
  for (size_t i = 0; i < length; ++i) {
    if (data[i] != 0x5a) {
      std::fprintf(stderr, "FAIL: memory contents changed at %zu\n", i);
      return 1;
    }
  }
  if (munmap(data, length) != 0) {
    std::perror("munmap");
    return 1;
  }
  std::printf("PASS: pageable memory %s\n", argv[1]);
}
