// Copyright 2022 The gVisor Authors.
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

#include <asm-generic/errno-base.h>
#include <bits/types/siginfo_t.h>
#include <bits/types/struct_iovec.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <csignal>
#include <cstddef>
#include <functional>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class TestIovecs {
 public:
  TestIovecs(std::vector<std::string>& data) {
    data_ = std::vector<std::string>(data.size());
    initial_ = std::vector<std::string>(data.size());
    for (int i = 0; i < data.size(); ++i) {
      data_[i] = data[i];
      initial_[i] = data[i];
      struct iovec iov;
      iov.iov_len = data_[i].size();
      iov.iov_base = data_[i].data();
      iovecs_.push_back(iov);
      bytes_ += data[i].size();
    }
  }

  bool compare(std::vector<std::string> other) {
    auto want = absl::StrJoin(other, "");
    auto got = absl::StrJoin(data_, "");
    // If the other buffer is smaller than this, make sure the remaining bytes
    // haven't been overwritten.
    if (want.size() < got.size()) {
      auto initial = absl::StrJoin(initial_, "");
      want = absl::StrCat(want, initial.substr(want.size()));
    }
    // If the other buffer is smaller, truncate it so we can compare the two.
    if (want.size() > got.size()) {
      want = want.substr(0, got.size());
    }
    if (want != got) {
      std::cerr << "Mismatch buffers:\n want: " << want << "\n got: " << got
                << std::endl;
      return false;
    }

    return true;
  }

  std::vector<struct iovec*> marshal() {
    std::vector<struct iovec*> ret(iovecs_.size());
    for (int i = 0; i < iovecs_.size(); ++i) {
      ret[i] = &iovecs_[i];
    }
    return ret;
  }

  ssize_t total_bytes() { return bytes_; }

 private:
  ssize_t bytes_ = 0;
  std::vector<std::string> data_;
  std::vector<std::string> initial_;
  std::vector<struct iovec> iovecs_;
};

struct ProcessVMTestCase {
  std::string test_name;
  std::vector<std::string> local_data;
  std::vector<std::string> remote_data;
};

using ProcessVMTest = ::testing::TestWithParam<ProcessVMTestCase>;

bool ProcessVMCallsNotSupported() {
  struct iovec iov;
  // Flags should be 0.
  ssize_t ret = process_vm_readv(0, &iov, 1, &iov, 1, 10);
  if (ret != 0 && errno == ENOSYS) return true;

  ret = process_vm_writev(0, &iov, 1, &iov, 1, 10);
  return ret != 0 && errno == ENOSYS;
}

// TestReadvSameProcess calls process_vm_readv in the same process with
// various local/remote buffers.
TEST_P(ProcessVMTest, TestReadvSameProcess) {
  SKIP_IF(ProcessVMCallsNotSupported());
  auto local_data = GetParam().local_data;
  auto remote_data = GetParam().remote_data;
  TestIovecs local_iovecs(local_data);
  TestIovecs remote_iovecs(remote_data);

  auto local = local_iovecs.marshal();
  auto remote = remote_iovecs.marshal();
  auto expected_bytes =
      std::min(remote_iovecs.total_bytes(), local_iovecs.total_bytes());
  EXPECT_THAT(process_vm_readv(getpid(), *(local.data()), local.size(),
                               *(remote.data()), remote.size(), 0),
              SyscallSucceedsWithValue(expected_bytes));
  EXPECT_TRUE(local_iovecs.compare(remote_data));
}

// TestReadvSubProcess repeats the previous test in a forked process.
TEST_P(ProcessVMTest, TestReadvSubProcess) {
  SKIP_IF(ProcessVMCallsNotSupported());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE((HaveCapability(CAP_SYS_PTRACE))));
  auto local_data = GetParam().local_data;
  auto remote_data = GetParam().remote_data;

  TestIovecs remote_iovecs(remote_data);
  auto remote = remote_iovecs.marshal();
  auto remote_ptr = remote[0];
  auto remote_size = remote.size();
  auto remote_total_bytes = remote_iovecs.total_bytes();

  const std::function<void()> fn = [local_data, remote_data, remote_ptr,
                                    remote_size, remote_total_bytes] {
    std::vector<std::string> local_fn_data = local_data;
    TestIovecs local_iovecs(local_fn_data);
    auto local = local_iovecs.marshal();
    int ret = process_vm_readv(getppid(), local[0], local.size(), remote_ptr,
                               remote_size, 0);
    auto expected_bytes =
        std::min(remote_total_bytes, local_iovecs.total_bytes());
    TEST_CHECK_MSG(
        ret == expected_bytes,
        absl::StrCat("want: ", expected_bytes, " got: ", ret).c_str());
    TEST_CHECK(local_iovecs.compare(remote_data));
  };
  EXPECT_THAT(InForkedProcess(fn), IsPosixErrorOkAndHolds(0));
}

// TestWritevSameProcess calls process_vm_writev in the same process with
// various local/remote buffers.
TEST_P(ProcessVMTest, TestWritevSameProcess) {
  SKIP_IF(ProcessVMCallsNotSupported());
  auto local_data = GetParam().local_data;
  auto remote_data = GetParam().remote_data;

  TestIovecs local_iovecs(local_data);
  TestIovecs remote_iovecs(remote_data);

  auto local = local_iovecs.marshal();
  auto remote = remote_iovecs.marshal();
  auto expected_bytes =
      std::min(remote_iovecs.total_bytes(), local_iovecs.total_bytes());
  EXPECT_THAT(process_vm_writev(getpid(), remote[0], remote.size(), local[0],
                                local.size(), 0),
              SyscallSucceedsWithValue(expected_bytes));
  EXPECT_TRUE(local_iovecs.compare(remote_data));
}

// TestWritevSubProcess repeats the previous test in a forked process.
TEST_P(ProcessVMTest, TestWritevSubProcess) {
  SKIP_IF(ProcessVMCallsNotSupported());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE((HaveCapability(CAP_SYS_PTRACE))));
  auto local_data = GetParam().local_data;
  auto remote_data = GetParam().remote_data;
  TestIovecs remote_iovecs(remote_data);
  auto remote = remote_iovecs.marshal();
  auto remote_ptr = remote[0];
  auto remote_size = remote.size();
  auto remote_total_bytes = remote_iovecs.total_bytes();

  const std::function<void()> fn = [local_data, remote_ptr, remote_size,
                                    remote_total_bytes] {
    std::vector<std::string> local_fn_data = local_data;
    TestIovecs local_iovecs(local_fn_data);
    auto local = local_iovecs.marshal();
    int ret = process_vm_writev(getppid(), local[0], local.size(), remote_ptr,
                                remote_size, 0);
    auto expected_bytes =
        std::min(remote_total_bytes, local_iovecs.total_bytes());
    TEST_CHECK_MSG(
        ret == expected_bytes,
        absl::StrCat("want: ", expected_bytes, " got: ", ret).c_str());
  };

  EXPECT_THAT(InForkedProcess(fn), IsPosixErrorOkAndHolds(0));
  EXPECT_TRUE(remote_iovecs.compare(local_data));
}

INSTANTIATE_TEST_SUITE_P(
    ProcessVMTests, ProcessVMTest,
    ::testing::ValuesIn<ProcessVMTestCase>(
        {{"BothEmpty" /*test name*/,
          {""} /*local buffer*/,
          {""} /*remote buffer*/},
         {"EmptyLocal", {""}, {"All too easy."}},
         {"EmptyRemote", {"Impressive. Most impressive."}, {""}},
         {"SingleChar", {"l"}, {"r"}},
         {"LargerRemoteBuffer",
          {"OK, I'll try"},
          {"No!", "Try not", "Do...or do not", "There is no try."}},
         {"LargerLocalBuffer",
          {"Look!", "The cave is collapsing!"},
          {"This is no cave."}},
         {"BothWithMultipleIovecs",
          {"Obi-wan never told you what happened to your father.",
           "He told me enough...he told me you killed him."},
          {"No...I am your father.", "No. No.", "That's not true.",
           "That's impossible!"}}}),
    [](const ::testing::TestParamInfo<ProcessVMTest::ParamType>& info) {
      return info.param.test_name;
    });

TEST(ProcessVMInvalidTest, NonZeroFlags) {
  SKIP_IF(ProcessVMCallsNotSupported());
  struct iovec iov;
  // Flags should be 0.
  EXPECT_THAT(process_vm_readv(0, &iov, 1, &iov, 1, 10),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(process_vm_writev(0, &iov, 1, &iov, 1, 10),
              SyscallFailsWithErrno(EINVAL));
}

TEST(ProcessVMInvalidTest, NullLocalIovec) {
  SKIP_IF(ProcessVMCallsNotSupported());
  struct iovec iov;
  pid_t child = fork();
  if (child == 0) {
    while (true) {
      sleep(1);
    }
  }

  EXPECT_THAT(process_vm_readv(child, nullptr, 1, &iov, 1, 0),
              SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(process_vm_writev(child, nullptr, 1, &iov, 1, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(kill(child, SIGKILL), SyscallSucceeds());
  EXPECT_THAT(waitpid(child, 0, 0), SyscallSucceeds());
}

TEST(ProcessVMInvalidTest, NULLRemoteIovec) {
  SKIP_IF(ProcessVMCallsNotSupported());
  const std::function<void()> fn = [] {
    std::string contents = "3263827";
    struct iovec child_iov;
    child_iov.iov_base = contents.data();
    child_iov.iov_len = contents.size();

    pid_t parent = getppid();
    int ret =
        process_vm_readv(parent, &child_iov, contents.length(), nullptr, 1, 0);
    TEST_CHECK(ret == -1);
    TEST_CHECK(errno == EFAULT || errno == EINVAL);

    ret =
        process_vm_writev(parent, &child_iov, contents.length(), nullptr, 1, 0);
    TEST_CHECK(ret == -1);
    TEST_CHECK(errno == EFAULT || errno == EINVAL);
  };
  ASSERT_THAT(InForkedProcess(fn), IsPosixErrorOkAndHolds(0));
}

TEST(ProcessVMInvalidTest, ProcessNoExist) {
  SKIP_IF(ProcessVMCallsNotSupported());
  struct iovec iov;
  EXPECT_THAT(process_vm_readv(-1, &iov, 1, &iov, 1, 0),
              SyscallFailsWithErrno(::testing::AnyOf(ESRCH, EFAULT)));
  EXPECT_THAT(process_vm_writev(-1, &iov, 1, &iov, 1, 0),
              SyscallFailsWithErrno(::testing::AnyOf(ESRCH, EFAULT)));
}

TEST(ProcessVMInvalidTest, GreaterThanIOV_MAX) {
  SKIP_IF(ProcessVMCallsNotSupported());
  std::string contents = "3263827";
  struct iovec iov;
  iov.iov_base = contents.data();
  auto iov_addr = &iov;
  const std::function<void()> fn = [=] {
    struct iovec child_iov;
    std::string contents = "3263827";
    child_iov.iov_base = contents.data();
    child_iov.iov_len = contents.size();

    pid_t parent = getppid();
    TEST_CHECK_MSG(-1 == process_vm_readv(parent, &child_iov, 1, iov_addr,
                                          IOV_MAX + 1, 0) &&
                       errno == EINVAL,
                   "read remote_process_over_IOV_MAX");

    TEST_CHECK_MSG(-1 == process_vm_writev(parent, &child_iov, 1, iov_addr,
                                           IOV_MAX + 3, 0) &&
                       errno == EINVAL,
                   "write remote process over IOV_MAX");

    TEST_CHECK_MSG(-1 == process_vm_readv(parent, &child_iov, IOV_MAX + 2,
                                          iov_addr, 1, 0) &&
                       errno == EINVAL,
                   "read local process over IOV_MAX");

    TEST_CHECK_MSG(-1 == process_vm_writev(parent, &child_iov, IOV_MAX + 8,
                                           iov_addr, 1, 0) &&
                       errno == EINVAL,
                   "write local process over IOV_MAX");
  };
  EXPECT_THAT(InForkedProcess(fn), IsPosixErrorOkAndHolds(0));
}

TEST(ProcessVMInvalidTest, PartialReadWrite) {
  SKIP_IF(ProcessVMCallsNotSupported());
  std::string iov_content_1 = "1138";
  std::string iov_content_2 = "3720";
  struct iovec iov[2];
  iov[0].iov_base = iov_content_1.data();
  iov[0].iov_len = iov_content_1.size();
  iov[1].iov_base = iov_content_2.data();
  iov[1].iov_len = iov_content_2.size();

  std::string iov_corrupted_content_1 = iov_content_1;
  struct iovec corrupted_iov[2];
  corrupted_iov[0].iov_base = iov_corrupted_content_1.data();
  corrupted_iov[0].iov_len = iov_corrupted_content_1.size();
  corrupted_iov[1].iov_base = (void*)0xDEADBEEF;
  corrupted_iov[1].iov_len = 42;

  EXPECT_THAT(
      RetryEINTR(process_vm_writev)(getpid(), iov, 2, corrupted_iov, 2, 0),
      SyscallSucceedsWithValue(iov_content_1.size()));
  EXPECT_THAT(
      RetryEINTR(process_vm_readv)(getpid(), corrupted_iov, 2, iov, 2, 0),
      SyscallSucceedsWithValue(iov_content_1.size()));
  EXPECT_THAT(
      RetryEINTR(process_vm_writev)(getpid(), corrupted_iov, 2, iov, 2, 0),
      SyscallSucceedsWithValue(iov_content_1.size()));
  EXPECT_THAT(
      RetryEINTR(process_vm_readv)(getpid(), iov, 2, corrupted_iov, 2, 0),
      SyscallSucceedsWithValue(iov_content_1.size()));
}

TEST(ProcessVMTest, WriteToZombie) {
  SKIP_IF(ProcessVMCallsNotSupported());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE((HaveCapability(CAP_SYS_PTRACE))));
  char* data = {0};
  pid_t child;
  ASSERT_THAT(child = fork(), SyscallSucceeds());
  if (child == 0) {
    _exit(0);
  }
  siginfo_t siginfo = {};
  ASSERT_THAT(RetryEINTR(waitid)(P_PID, child, &siginfo, WEXITED | WNOWAIT),
              SyscallSucceeds());
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = sizeof(data);
  ASSERT_THAT(process_vm_writev(child, &iov, 1, &iov, 1, 0),
              SyscallFailsWithErrno(ESRCH));
}
}  // namespace
}  // namespace testing
}  // namespace gvisor
