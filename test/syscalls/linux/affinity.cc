// Copyright 2018 Google LLC
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

#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

// These tests are for both the sched_getaffinity(2) and sched_setaffinity(2)
// syscalls.
class AffinityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EXPECT_THAT(
        // Needs use the raw syscall to get the actual size.
        cpuset_size_ = syscall(SYS_sched_getaffinity, /*pid=*/0,
                               sizeof(cpu_set_t), &mask_),
        SyscallSucceeds());
    // Lots of tests rely on having more than 1 logical processor available.
    EXPECT_GT(CPU_COUNT(&mask_), 1);
  }

  static PosixError ClearLowestBit(cpu_set_t* mask, size_t cpus) {
    const size_t mask_size = CPU_ALLOC_SIZE(cpus);
    for (size_t n = 0; n < cpus; ++n) {
      if (CPU_ISSET_S(n, mask_size, mask)) {
        CPU_CLR_S(n, mask_size, mask);
        return NoError();
      }
    }
    return PosixError(EINVAL, "No bit to clear, mask is empty");
  }

  PosixError ClearLowestBit() { return ClearLowestBit(&mask_, CPU_SETSIZE); }

  // Stores the initial cpu mask for this process.
  cpu_set_t mask_ = {};
  int cpuset_size_ = 0;
};

// sched_getaffinity(2) is implemented.
TEST_F(AffinityTest, SchedGetAffinityImplemented) {
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &mask_),
              SyscallSucceeds());
}

// PID is not found.
TEST_F(AffinityTest, SchedGetAffinityInvalidPID) {
  // Flaky, but it's tough to avoid a race condition when finding an unused pid
  EXPECT_THAT(sched_getaffinity(/*pid=*/INT_MAX - 1, sizeof(cpu_set_t), &mask_),
              SyscallFailsWithErrno(ESRCH));
}

// PID is not found.
TEST_F(AffinityTest, SchedSetAffinityInvalidPID) {
  // Flaky, but it's tough to avoid a race condition when finding an unused pid
  EXPECT_THAT(sched_setaffinity(/*pid=*/INT_MAX - 1, sizeof(cpu_set_t), &mask_),
              SyscallFailsWithErrno(ESRCH));
}

TEST_F(AffinityTest, SchedSetAffinityZeroMask) {
  CPU_ZERO(&mask_);
  EXPECT_THAT(sched_setaffinity(/*pid=*/0, sizeof(cpu_set_t), &mask_),
              SyscallFailsWithErrno(EINVAL));
}

// N.B. This test case relies on cpuset_size_ larger than the actual number of
// of all existing CPUs. Check your machine if the test fails.
TEST_F(AffinityTest, SchedSetAffinityNonexistentCPUDropped) {
  cpu_set_t mask = mask_;
  // Add a nonexistent CPU.
  //
  // The number needs to be larger than the possible number of CPU available,
  // but smaller than the number of the CPU that the kernel claims to support --
  // it's implicitly returned by raw sched_getaffinity syscall.
  CPU_SET(cpuset_size_ * 8 - 1, &mask);
  EXPECT_THAT(
      // Use raw syscall because it will be rejected by the libc wrapper
      // otherwise.
      syscall(SYS_sched_setaffinity, /*pid=*/0, sizeof(cpu_set_t), &mask),
      SyscallSucceeds())
      << "failed with cpumask : " << CPUSetToString(mask)
      << ", cpuset_size_ : " << cpuset_size_;
  cpu_set_t newmask;
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &newmask),
              SyscallSucceeds());
  EXPECT_TRUE(CPU_EQUAL(&mask_, &newmask))
      << "got: " << CPUSetToString(newmask)
      << " != expected: " << CPUSetToString(mask_);
}

TEST_F(AffinityTest, SchedSetAffinityOnlyNonexistentCPUFails) {
  // Make an empty cpu set.
  CPU_ZERO(&mask_);
  // Add a nonexistent CPU.
  //
  // The number needs to be larger than the possible number of CPU available,
  // but smaller than the number of the CPU that the kernel claims to support --
  // it's implicitly returned by raw sched_getaffinity syscall.
  int cpu = cpuset_size_ * 8 - 1;
  if (cpu <= NumCPUs()) {
    LOG(INFO) << "Skipping test: cpu " << cpu << " exists";
    return;
  }
  CPU_SET(cpu, &mask_);
  EXPECT_THAT(
      // Use raw syscall because it will be rejected by the libc wrapper
      // otherwise.
      syscall(SYS_sched_setaffinity, /*pid=*/0, sizeof(cpu_set_t), &mask_),
      SyscallFailsWithErrno(EINVAL));
}

TEST_F(AffinityTest, SchedSetAffinityInvalidSize) {
  EXPECT_GT(cpuset_size_, 0);
  // Not big enough.
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, cpuset_size_ - 1, &mask_),
              SyscallFailsWithErrno(EINVAL));
  // Not a multiple of word size.
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, cpuset_size_ + 1, &mask_),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(AffinityTest, Sanity) {
  ASSERT_NO_ERRNO(ClearLowestBit());
  EXPECT_THAT(sched_setaffinity(/*pid=*/0, sizeof(cpu_set_t), &mask_),
              SyscallSucceeds());
  cpu_set_t newmask;
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &newmask),
              SyscallSucceeds());
  EXPECT_TRUE(CPU_EQUAL(&mask_, &newmask))
      << "got: " << CPUSetToString(newmask)
      << " != expected: " << CPUSetToString(mask_);
}

TEST_F(AffinityTest, NewThread) {
  ASSERT_NO_ERRNO(ClearLowestBit());
  ASSERT_NO_ERRNO(ClearLowestBit());
  EXPECT_THAT(sched_setaffinity(/*pid=*/0, sizeof(cpu_set_t), &mask_),
              SyscallSucceeds());
  ScopedThread([this]() {
    cpu_set_t child_mask;
    ASSERT_THAT(sched_getaffinity(/*pid=*/0, sizeof(cpu_set_t), &child_mask),
                SyscallSucceeds());
    ASSERT_TRUE(CPU_EQUAL(&child_mask, &mask_))
        << "child cpu mask: " << CPUSetToString(child_mask)
        << " != parent cpu mask: " << CPUSetToString(mask_);
  });
}

TEST_F(AffinityTest, ConsistentWithProcCpuInfo) {
  // Count how many cpus are shown in /proc/cpuinfo.
  std::string cpuinfo = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/cpuinfo"));
  int count = 0;
  for (auto const& line : absl::StrSplit(cpuinfo, '\n')) {
    if (absl::StartsWith(line, "processor")) {
      count++;
    }
  }
  EXPECT_GE(count, CPU_COUNT(&mask_));
}

TEST_F(AffinityTest, ConsistentWithProcStat) {
  // Count how many cpus are shown in /proc/stat.
  std::string stat = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/stat"));
  int count = 0;
  for (auto const& line : absl::StrSplit(stat, '\n')) {
    if (absl::StartsWith(line, "cpu") && !absl::StartsWith(line, "cpu ")) {
      count++;
    }
  }
  EXPECT_GE(count, CPU_COUNT(&mask_));
}

TEST_F(AffinityTest, SmallCpuMask) {
  const int num_cpus = NumCPUs();
  const size_t mask_size = CPU_ALLOC_SIZE(num_cpus);
  cpu_set_t* mask = CPU_ALLOC(num_cpus);
  ASSERT_NE(mask, nullptr);
  const auto free_mask = Cleanup([&] { CPU_FREE(mask); });

  CPU_ZERO_S(mask_size, mask);
  ASSERT_THAT(sched_getaffinity(0, mask_size, mask), SyscallSucceeds());
}

TEST_F(AffinityTest, LargeCpuMask) {
  // Allocate mask bigger than cpu_set_t normally allocates.
  const size_t cpus = CPU_SETSIZE * 8;
  const size_t mask_size = CPU_ALLOC_SIZE(cpus);

  cpu_set_t* large_mask = CPU_ALLOC(cpus);
  auto free_mask = Cleanup([large_mask] { CPU_FREE(large_mask); });
  CPU_ZERO_S(mask_size, large_mask);

  // Check that get affinity with large mask works as expected.
  ASSERT_THAT(sched_getaffinity(/*pid=*/0, mask_size, large_mask),
              SyscallSucceeds());
  EXPECT_TRUE(CPU_EQUAL(&mask_, large_mask))
      << "got: " << CPUSetToString(*large_mask, cpus)
      << " != expected: " << CPUSetToString(mask_);

  // Check that set affinity with large mask works as expected.
  ASSERT_NO_ERRNO(ClearLowestBit(large_mask, cpus));
  EXPECT_THAT(sched_setaffinity(/*pid=*/0, mask_size, large_mask),
              SyscallSucceeds());

  cpu_set_t* new_mask = CPU_ALLOC(cpus);
  auto free_new_mask = Cleanup([new_mask] { CPU_FREE(new_mask); });
  CPU_ZERO_S(mask_size, new_mask);
  EXPECT_THAT(sched_getaffinity(/*pid=*/0, mask_size, new_mask),
              SyscallSucceeds());

  EXPECT_TRUE(CPU_EQUAL_S(mask_size, large_mask, new_mask))
      << "got: " << CPUSetToString(*new_mask, cpus)
      << " != expected: " << CPUSetToString(*large_mask, cpus);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
