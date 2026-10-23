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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// NVIDIA's UVM ioctl numbers and structures are independent of _IOC encoding.
constexpr unsigned long kUVMInitialize = 0x30000001;
constexpr unsigned long kUVMPopulatePageable = 71;
constexpr uint32_t kNVErrInvalidAddress = 0x1e;
struct InitializeParams {
  uint64_t flags;
  uint32_t status;
  uint32_t padding;
};
struct PopulateParams {
  uint64_t base;
  uint64_t length;
  uint32_t flags;
  uint32_t status;
};
static_assert(sizeof(InitializeParams) == 16);
static_assert(sizeof(PopulateParams) == 24);

[[noreturn]] void Fail(const char* operation) {
  std::fprintf(stderr, "FAIL: %s (errno=%d)\n", operation, errno);
  std::exit(1);
}

void CheckCUDA(cudaError_t error, const char* operation) {
  if (error != cudaSuccess) {
    std::fprintf(stderr, "FAIL: %s: %s\n", operation,
                 cudaGetErrorString(error));
    std::exit(1);
  }
}
#define CUDA_CHECK(call) CheckCUDA((call), #call)

void Populate(int fd, void* address, size_t length, uint32_t expected) {
  PopulateParams params{reinterpret_cast<uintptr_t>(address), length, 0,
                        UINT32_MAX};
  if (ioctl(fd, kUVMPopulatePageable, &params) != 0) {
    Fail("UVM_POPULATE_PAGEABLE ioctl");
  }
  if (params.status != expected) {
    std::fprintf(stderr, "FAIL: populate returned %#x, expected %#x\n",
                 params.status, expected);
    std::exit(1);
  }
}

void CheckBytes(const unsigned char* data, size_t length,
                unsigned char expected) {
  for (size_t i = 0; i < length; ++i) {
    if (data[i] != expected) {
      Fail("populate changed existing allocation contents");
    }
  }
}

void* Map(size_t length, int protection) {
  void* address =
      mmap(nullptr, length, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (address == MAP_FAILED) {
    Fail("mmap");
  }
  return address;
}

sigjmp_buf fault_return;
volatile sig_atomic_t write_faulted;

void HandleFault(int) {
  write_faulted = 1;
  siglongjmp(fault_return, 1);
}

void CheckManaged(int fd, size_t length) {
  unsigned char* managed;
  CUDA_CHECK(cudaMallocManaged(&managed, length));
  CUDA_CHECK(cudaMemset(managed, 0x5a, length));
  CUDA_CHECK(cudaDeviceSynchronize());
  CheckBytes(managed, length, 0x5a);

  // A managed VMA is not pageable CPU memory. Rejecting it must not replace
  // the driver's mapping, since closing that VMA discards the allocation.
  Populate(fd, managed, length, kNVErrInvalidAddress);
  CheckBytes(managed, length, 0x5a);
  std::vector<unsigned char> copied(length);
  CUDA_CHECK(
      cudaMemcpy(copied.data(), managed, length, cudaMemcpyDeviceToHost));
  CheckBytes(copied.data(), length, 0x5a);
  CUDA_CHECK(cudaFree(managed));
}

void CheckOrdinary(int fd, size_t page) {
  const size_t length = 4 * page;
  void* rw = Map(length, PROT_READ | PROT_WRITE);
  void* ro = Map(length, PROT_READ);
  void* wo = Map(length, PROT_WRITE);
  // Keep these mappings untouched until the driver populates them.
  Populate(fd, rw, length, 0);
  Populate(fd, ro, length, 0);
  Populate(fd, wo, length, 0);
  for (void* address : {rw, ro, wo}) {
    unsigned char residency[4] = {};
    if (mincore(address, length, residency) != 0) {
      Fail("mincore");
    }
    for (unsigned char state : residency) {
      if (!(state & 1)) {
        Fail("populate left a page absent");
      }
    }
  }
  static_cast<volatile unsigned char*>(rw)[0] = 0x3c;
  static_cast<volatile unsigned char*>(wo)[0] = 0x3c;
  struct sigaction handler{}, original{};
  handler.sa_handler = HandleFault;
  sigemptyset(&handler.sa_mask);
  if (sigaction(SIGSEGV, &handler, &original) != 0) {
    Fail("install SIGSEGV handler");
  }
  if (sigsetjmp(fault_return, 1) == 0) {
    static_cast<volatile unsigned char*>(ro)[0] = 0x3c;
  }
  if (sigaction(SIGSEGV, &original, nullptr) != 0 || !write_faulted) {
    Fail("populate made a read-only mapping writable");
  }
  if (munmap(rw, length) != 0 || munmap(ro, length) != 0 ||
      munmap(wo, length) != 0) {
    Fail("unmap ordinary memory");
  }
}

void CheckInvalid(int fd, size_t page) {
  auto* address =
      static_cast<unsigned char*>(Map(3 * page, PROT_READ | PROT_WRITE));
  std::memset(address, 0x3c, 3 * page);
  if (mprotect(address + page, page, PROT_EXEC) != 0) {
    Fail("mprotect execute-only");
  }
  Populate(fd, address, 3 * page, kNVErrInvalidAddress);
  CheckBytes(address, page, 0x3c);
  CheckBytes(address + 2 * page, page, 0x3c);
  if (mprotect(address + page, page, PROT_NONE) != 0) {
    Fail("mprotect");
  }
  Populate(fd, address, 3 * page, kNVErrInvalidAddress);
  CheckBytes(address, page, 0x3c);
  CheckBytes(address + 2 * page, page, 0x3c);
  if (munmap(address + page, page) != 0) {
    Fail("unmap middle page");
  }
  Populate(fd, address, 3 * page, kNVErrInvalidAddress);
  Populate(fd, address + page, page, kNVErrInvalidAddress);
  Populate(fd, address + 1, page, kNVErrInvalidAddress);
  Populate(fd, address, 0, kNVErrInvalidAddress);
  CheckBytes(address, page, 0x3c);
  CheckBytes(address + 2 * page, page, 0x3c);
  if (munmap(address, page) != 0 || munmap(address + 2 * page, page) != 0) {
    Fail("unmap invalid-range memory");
  }
}

}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  int devices;
  CUDA_CHECK(cudaGetDeviceCount(&devices));
  int selected = -1;
  for (int device = 0; device < devices; ++device) {
    int uses_host_page_tables;
    CUDA_CHECK(cudaDeviceGetAttribute(
        &uses_host_page_tables,
        cudaDevAttrPageableMemoryAccessUsesHostPageTables, device));
    if (uses_host_page_tables) {
      selected = device;
      break;
    }
  }
  if (selected == -1) {
    std::puts("SKIP: ATS pageable memory is unavailable");
    return 0;
  }
  CUDA_CHECK(cudaSetDevice(selected));
  int fd = open("/dev/nvidia-uvm", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    Fail("open /dev/nvidia-uvm");
  }
  InitializeParams init{};
  if (ioctl(fd, kUVMInitialize, &init) != 0 || init.status != 0) {
    Fail("UVM_INITIALIZE");
  }
  const size_t page = sysconf(_SC_PAGESIZE);
  CheckManaged(fd, 4 * page);
  CheckOrdinary(fd, page);
  CheckInvalid(fd, page);
  if (close(fd) != 0) {
    Fail("close /dev/nvidia-uvm");
  }
  std::puts(
      "PASS: UVM_POPULATE_PAGEABLE preserves managed memory and protections");
  return 0;
}
