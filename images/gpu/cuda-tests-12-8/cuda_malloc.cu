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

#include <cuda_runtime.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <random>

#include "cuda_test_util.h"  // NOLINT(build/include)

__global__ void addKernel(std::uint32_t* data) {
  size_t index = blockIdx.x * blockDim.x + threadIdx.x;
  data[index] += static_cast<std::uint32_t>(index);
}

void TestMallocManagedRoundTrip(int device, unsigned int malloc_flags,
                                bool prefetch) {
  constexpr size_t kNumBlocks = 32;
  constexpr size_t kNumThreads = 64;
  constexpr size_t kNumElems = kNumBlocks * kNumThreads;

  std::uint32_t* data = nullptr;
  constexpr size_t kNumBytes = kNumElems * sizeof(*data);
  CHECK_CUDA(cudaMallocManaged(&data, kNumBytes, malloc_flags));

  // Initialize all elements in the array with a random value on the host.
  std::default_random_engine rd;
  const std::uint32_t init_val =
      std::uniform_int_distribution<std::uint32_t>()(rd);
  for (size_t i = 0; i < kNumElems; i++) {
    data[i] = init_val;
  }

  if (prefetch) {
    CHECK_CUDA(cudaMemPrefetchAsync(data, kNumBytes, device));
  }

  // Mutate the array on the device.
  addKernel<<<kNumBlocks, kNumThreads>>>(data);
  CHECK_CUDA(cudaGetLastError());
  CHECK_CUDA(cudaDeviceSynchronize());

  if (prefetch) {
    CHECK_CUDA(cudaMemPrefetchAsync(data, kNumBytes, cudaCpuDeviceId));
  }

  // Check that the array has the expected result.
  for (size_t i = 0; i < kNumElems; i++) {
    std::uint32_t want = init_val + static_cast<std::uint32_t>(i);
    if (data[i] != want) {
      std::cout << "data[" << i << "]: got " << data[i] << ", wanted " << want
                << " = " << init_val << " + " << i << std::endl;
      abort();
    }
  }

  CHECK_CUDA(cudaFree(data));
}

void TestMallocManagedReadWrite(int device) {
  constexpr size_t kNumBlocks = 32;
  constexpr size_t kNumThreads = 64;
  constexpr size_t kNumElems = kNumBlocks * kNumThreads;

  std::uint32_t* data = nullptr;
  constexpr size_t kNumBytes = kNumElems * sizeof(*data);
  CHECK_CUDA(cudaMallocManaged(&data, kNumBytes, cudaMemAttachGlobal));

  // Initialize all elements in the array with a random value on the host.
  std::default_random_engine rd;
  const std::uint32_t init_val =
      std::uniform_int_distribution<std::uint32_t>()(rd);
  for (size_t i = 0; i < kNumElems; i++) {
    data[i] = init_val;
  }

  // Write the array's contents to a temporary file.
  char filename[] = "/tmp/cudaMallocManagedTest.XXXXXX";
  int fd = mkstemp(filename);
  if (fd < 0) {
    err(1, "mkstemp");
  }
  size_t done = 0;
  while (done < kNumBytes) {
    ssize_t n = write(fd, reinterpret_cast<char*>(data) + done,
                      kNumBytes - done);
    if (n >= 0) {
      done += n;
    } else if (n < 0 && errno != EINTR) {
      err(1, "write");
    }
  }

  // Mutate the array on the device.
  addKernel<<<kNumBlocks, kNumThreads>>>(data);
  CHECK_CUDA(cudaGetLastError());
  CHECK_CUDA(cudaDeviceSynchronize());

  // Check that the array has the expected result.
  for (size_t i = 0; i < kNumElems; i++) {
    std::uint32_t want = init_val + static_cast<std::uint32_t>(i);
    if (data[i] != want) {
      std::cout << "data[" << i << "]: got " << data[i] << ", wanted " << want
                << " = " << init_val << " + " << i << std::endl;
      abort();
    }
  }

  // Read the array's original contents back from the temporary file.
  if (lseek(fd, 0, SEEK_SET) < 0) {
    err(1, "lseek");
  }
  done = 0;
  while (done < kNumBytes) {
    ssize_t n = read(fd, reinterpret_cast<char*>(data) + done,
                     kNumBytes - done);
    if (n > 0) {
      done += n;
    } else if (n == 0) {
      errx(1, "read: unexpected EOF after %zu bytes", done);
    } else if (n < 0 && errno != EINTR) {
      err(1, "read");
    }
  }

  // Check that the array matches what we originally wrote.
  for (size_t i = 0; i < kNumElems; i++) {
    std::uint32_t want = init_val;
    if (data[i] != want) {
      std::cout << "data[" << i << "]: got " << data[i] << ", wanted " << want
                << " = " << init_val << " + " << i << std::endl;
      abort();
    }
  }

  // Mutate the array on the device again.
  addKernel<<<kNumBlocks, kNumThreads>>>(data);
  CHECK_CUDA(cudaGetLastError());
  CHECK_CUDA(cudaDeviceSynchronize());

  // Check that the array has the expected result again.
  for (size_t i = 0; i < kNumElems; i++) {
    std::uint32_t want = init_val + static_cast<std::uint32_t>(i);
    if (data[i] != want) {
      std::cout << "data[" << i << "]: got " << data[i] << ", wanted " << want
                << " = " << init_val << " + " << i << std::endl;
      abort();
    }
  }

  close(fd);
  CHECK_CUDA(cudaFree(data));
}

int main() {
  int device;
  CHECK_CUDA(cudaGetDevice(&device));

  std::cout << "Testing cudaMallocManaged(flags=cudaMemAttachGlobal)"
            << std::endl;
  TestMallocManagedRoundTrip(device, cudaMemAttachGlobal, false);

  int cma = 0;
  CHECK_CUDA(
      cudaDeviceGetAttribute(&cma, cudaDevAttrConcurrentManagedAccess, device));
  if (!cma) {
    std::cout << "cudaDevAttrConcurrentManagedAccess not available"
              << std::endl;
  } else {
    std::cout << "Testing cudaMallocManaged(flags=cudaMemAttachGlobal) "
                 "with prefetching"
              << std::endl;
    TestMallocManagedRoundTrip(device, cudaMemAttachGlobal, true);
    std::cout << "Testing cudaMallocManaged(flags=cudaMemAttachHost)"
              << std::endl;
    TestMallocManagedRoundTrip(device, cudaMemAttachHost, false);
    std::cout << "Testing cudaMallocManaged(flags=cudaMemAttachHost) "
                 "with prefetching"
              << std::endl;
    TestMallocManagedRoundTrip(device, cudaMemAttachHost, true);
  }

  std::cout << "Testing read/write syscalls on cudaMallocManaged memory"
            << std::endl;
  TestMallocManagedReadWrite(device);

  std::cout << "All tests passed" << std::endl;
  return 0;
}
