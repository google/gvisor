// Copyright 2018 The gVisor Authors.
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

#include "test/util/test_util.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <ctime>
#include <iostream>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/time/time.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

#define TEST_ON_GVISOR "TEST_ON_GVISOR"

bool IsRunningOnGvisor() { return GvisorPlatform() != Platform::kNative; }

Platform GvisorPlatform() {
  // Set by runner.go.
  char* env = getenv(TEST_ON_GVISOR);
  if (!env) {
    return Platform::kNative;
  }
  if (strcmp(env, "ptrace") == 0) {
    return Platform::kPtrace;
  }
  if (strcmp(env, "kvm") == 0) {
    return Platform::kKVM;
  }
  std::cerr << "unknown platform " << env;
  abort();
}

// Inline cpuid instruction.  Preserve %ebx/%rbx register. In PIC compilations
// %ebx contains the address of the global offset table. %rbx is occasionally
// used to address stack variables in presence of dynamic allocas.
#if defined(__x86_64__)
#define GETCPUID(a, b, c, d, a_inp, c_inp) \
  asm("mov %%rbx, %%rdi\n"                 \
      "cpuid\n"                            \
      "xchg %%rdi, %%rbx\n"                \
      : "=a"(a), "=D"(b), "=c"(c), "=d"(d) \
      : "a"(a_inp), "2"(c_inp))
#endif  // defined(__x86_64__)

CPUVendor GetCPUVendor() {
  uint32_t eax, ebx, ecx, edx;
  std::string vendor_str;
  // Get vendor string (issue CPUID with eax = 0)
  GETCPUID(eax, ebx, ecx, edx, 0, 0);
  vendor_str.append(reinterpret_cast<char*>(&ebx), 4);
  vendor_str.append(reinterpret_cast<char*>(&edx), 4);
  vendor_str.append(reinterpret_cast<char*>(&ecx), 4);
  if (vendor_str == "GenuineIntel") {
    return CPUVendor::kIntel;
  } else if (vendor_str == "AuthenticAMD") {
    return CPUVendor::kAMD;
  }
  return CPUVendor::kUnknownVendor;
}

bool operator==(const KernelVersion& first, const KernelVersion& second) {
  return first.major == second.major && first.minor == second.minor &&
         first.micro == second.micro;
}

PosixErrorOr<KernelVersion> ParseKernelVersion(absl::string_view vers_str) {
  KernelVersion version = {};
  std::vector<std::string> values =
      absl::StrSplit(vers_str, absl::ByAnyChar(".-"));
  if (values.size() == 2) {
    ASSIGN_OR_RETURN_ERRNO(version.major, Atoi<int>(values[0]));
    ASSIGN_OR_RETURN_ERRNO(version.minor, Atoi<int>(values[1]));
    return version;
  } else if (values.size() >= 3) {
    ASSIGN_OR_RETURN_ERRNO(version.major, Atoi<int>(values[0]));
    ASSIGN_OR_RETURN_ERRNO(version.minor, Atoi<int>(values[1]));
    ASSIGN_OR_RETURN_ERRNO(version.micro, Atoi<int>(values[2]));
    return version;
  }
  return PosixError(EINVAL, absl::StrCat("Unknown kernel release: ", vers_str));
}

PosixErrorOr<KernelVersion> GetKernelVersion() {
  utsname buf;
  RETURN_ERROR_IF_SYSCALL_FAIL(uname(&buf));
  return ParseKernelVersion(buf.release);
}

void SetupGvisorDeathTest() {
}

std::string CPUSetToString(const cpu_set_t& set, size_t cpus) {
  std::string str = "cpuset[";
  for (unsigned int n = 0; n < cpus; n++) {
    if (CPU_ISSET(n, &set)) {
      if (n != 0) {
        absl::StrAppend(&str, " ");
      }
      absl::StrAppend(&str, n);
    }
  }
  absl::StrAppend(&str, "]");
  return str;
}

// An overloaded operator<< makes it easy to dump the value of an OpenFd.
std::ostream& operator<<(std::ostream& out, OpenFd const& ofd) {
  out << ofd.fd << " -> " << ofd.link;
  return out;
}

// An overloaded operator<< makes it easy to dump a vector of OpenFDs.
std::ostream& operator<<(std::ostream& out, std::vector<OpenFd> const& v) {
  for (const auto& ofd : v) {
    out << ofd << std::endl;
  }
  return out;
}

PosixErrorOr<std::vector<OpenFd>> GetOpenFDs() {
  // Get the results from /proc/self/fd.
  ASSIGN_OR_RETURN_ERRNO(auto dir_list,
                         ListDir("/proc/self/fd", /*skipdots=*/true));

  std::vector<OpenFd> ret_fds;
  for (const auto& str_fd : dir_list) {
    OpenFd open_fd = {};
    ASSIGN_OR_RETURN_ERRNO(open_fd.fd, Atoi<int>(str_fd));
    std::string path = absl::StrCat("/proc/self/fd/", open_fd.fd);

    // Resolve the link.
    char buf[PATH_MAX] = {};
    int ret = readlink(path.c_str(), buf, sizeof(buf));
    if (ret < 0) {
      if (errno == ENOENT) {
        // The FD may have been closed, let's be resilient.
        continue;
      }

      return PosixError(
          errno, absl::StrCat("readlink of ", path, " returned errno ", errno));
    }
    open_fd.link = std::string(buf, ret);
    ret_fds.emplace_back(std::move(open_fd));
  }
  return ret_fds;
}

PosixErrorOr<uint64_t> Links(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st)) {
    return PosixError(errno, absl::StrCat("Failed to stat ", path));
  }
  return static_cast<uint64_t>(st.st_nlink);
}

void RandomizeBuffer(void* buffer, size_t len) {
  struct timespec ts = {};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint32_t seed = static_cast<uint32_t>(ts.tv_nsec);
  char* const buf = static_cast<char*>(buffer);
  for (size_t i = 0; i < len; i++) {
    buf[i] = rand_r(&seed) % 255;
  }
}

std::vector<std::vector<struct iovec>> GenerateIovecs(uint64_t total_size,
                                                      void* buf,
                                                      size_t buflen) {
  std::vector<std::vector<struct iovec>> result;
  for (uint64_t offset = 0; offset < total_size;) {
    auto& iovec_array = *result.emplace(result.end());

    for (; offset < total_size && iovec_array.size() < IOV_MAX;
         offset += buflen) {
      struct iovec iov = {};
      iov.iov_base = buf;
      iov.iov_len = std::min<uint64_t>(total_size - offset, buflen);
      iovec_array.push_back(iov);
    }
  }

  return result;
}

uint64_t Megabytes(uint64_t n) {
  // Overflow check, upper 20 bits in n shouldn't be set.
  TEST_CHECK(!(0xfffff00000000000 & n));
  return n << 20;
}

bool Equivalent(uint64_t current, uint64_t target, double tolerance) {
  auto abs_diff = target > current ? target - current : current - target;
  return abs_diff <= static_cast<uint64_t>(tolerance * target);
}

void TestInit(int* argc, char*** argv) {
  ::testing::InitGoogleTest(argc, *argv);
  ::gflags::ParseCommandLineFlags(argc, argv, true);

  // Always mask SIGPIPE as it's common and tests aren't expected to handle it.
  struct sigaction sa = {};
  sa.sa_handler = SIG_IGN;
  TEST_CHECK(sigaction(SIGPIPE, &sa, nullptr) == 0);
}
   gvisor:case-end

}  // namespace testing
}  // namespace gvisor
