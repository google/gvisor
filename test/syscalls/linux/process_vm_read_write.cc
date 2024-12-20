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
#include <linux/futex.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

class TestIovecs {
 public:
  TestIovecs(std::vector<std::string> data) {
    data_.resize(data.size());
    iovecs_.resize(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
      data_[i] = data[i];
      bytes_ += data[i].size();
      iovecs_[i].iov_len = data_[i].size();
      iovecs_[i].iov_base = data_[i].data();
    }
  }

  void erase() {
    for (size_t i = 0; i < data_.size(); i++) {
      data_[i].clear();
    }
  }

  // Backing data that will be read/written.
  std::vector<std::string> data_;

  // Total size of data_.
  ssize_t bytes_ = 0;

  // Iovec structs that point into data_
  std::vector<iovec> iovecs_;
};

// bytes_match checks that the two TestIovecs are at least min_bytes in length,
// and that they agree in the first min_bytes.
bool bytes_match(TestIovecs first_iov, TestIovecs second_iov,
                 size_t min_bytes) {
  auto first = absl::StrJoin(first_iov.data_, "");
  if (first.size() < min_bytes) {
    std::cout << "First buffer smaller than min_bytes: " << min_bytes
              << " buffer: " << first << std::endl;
    return false;
  }
  first = first.substr(0, min_bytes);

  auto second = absl::StrJoin(second_iov.data_, "");
  if (second.size() < min_bytes) {
    std::cout << "First buffer smaller than min_bytes: " << min_bytes
              << " buffer: " << second << std::endl;
    return false;
  }
  second = second.substr(0, min_bytes);

  if (first != second) {
    std::cout << "Mismatch buffers:\n first: " << first
              << "\n second: " << second << std::endl;
    return false;
  }

  return true;
}

struct ProcessVMTestCase {
  std::string test_name;
  std::vector<std::string> local_data;
  std::vector<std::string> remote_data;
};

using ProcessVMTest = ::testing::TestWithParam<ProcessVMTestCase>;

std::string getTestBuffer(std::string pattern, size_t size) {
  std::string s;

  auto pattern_length = pattern.length();
  s.reserve(size);
  while (s.length() + pattern_length < size) {
    s += pattern;
  }
  s += pattern.substr(0, size - s.length());
  return s;
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
           "That's impossible!"}},
         {
             "LargeBuffer",
             {
                 getTestBuffer(
                     "Train yourself to let go of everything you fear to lose.",
                     32 << 20),
                 "Hello there!",
             },
             {
                 "Do. Or do not. There is no try.",
                 getTestBuffer("The greatest teacher, failure is.", 32 << 20),
             },
         }}),
    [](const ::testing::TestParamInfo<ProcessVMTest::ParamType>& info) {
      return info.param.test_name;
    });

// TestReadvSameProcess calls process_vm_readv in the same process with various
// local/remote buffers.
TEST_P(ProcessVMTest, TestReadvSameProcess) {
  TestIovecs local(GetParam().local_data);
  TestIovecs remote(GetParam().remote_data);

  auto want_size = std::min(remote.bytes_, local.bytes_);
  EXPECT_THAT(
      process_vm_readv(getpid(), local.iovecs_.data(), local.iovecs_.size(),
                       remote.iovecs_.data(), remote.iovecs_.size(), 0),
      SyscallSucceedsWithValue(want_size));
  EXPECT_TRUE(bytes_match(local, remote, want_size));
}

// TestReadvSameProcessDifferentThread calls process_vm_readv in the same
// process, but with a different (non-leader) remote thread, with various
// local/remote buffers.
TEST_P(ProcessVMTest, TestReadvSameProcessDifferentThread) {
  TestIovecs local(GetParam().local_data);
  TestIovecs remote(GetParam().remote_data);

  std::atomic<std::int32_t> sibling_tid{0};
  std::atomic<std::uint32_t> sibling_exit{0};
  ScopedThread t([&] {
    sibling_tid.store(gettid());
    syscall(SYS_futex, &sibling_tid, FUTEX_WAKE, 1);
    while (sibling_exit.load() == 0) {
      syscall(SYS_futex, &sibling_exit, FUTEX_WAIT, 0, nullptr);
    }
  });
  Cleanup cleanup_t([&] {
    sibling_exit.store(1);
    syscall(SYS_futex, &sibling_exit, FUTEX_WAKE, 1);
  });
  while (sibling_tid.load() == 0) {
    syscall(SYS_futex, &sibling_tid, FUTEX_WAIT, 0, nullptr);
  }

  auto want_size = std::min(remote.bytes_, local.bytes_);
  EXPECT_THAT(process_vm_readv(sibling_tid.load(), local.iovecs_.data(),
                               local.iovecs_.size(), remote.iovecs_.data(),
                               remote.iovecs_.size(), 0),
              SyscallSucceedsWithValue(want_size));
  EXPECT_TRUE(bytes_match(local, remote, want_size));
}

// TestReadvSubProcess reads data from a forked child process.
TEST_P(ProcessVMTest, TestReadvSubProcess) {
  TestIovecs local = TestIovecs(GetParam().local_data);
  TestIovecs remote = TestIovecs(GetParam().remote_data);

  pid_t pid = fork();
  TEST_CHECK_SUCCESS(pid);
  if (pid == 0) {
    // Child. This is the "remote" process.
    // Wait for parent to read data.
    sleep(10);  // NOLINT - SleepFor is not async-signal-safe.
    _exit(0);
  }

  auto cleanup = absl::MakeCleanup([&] { kill(pid, SIGKILL); });

  // Erase the string data in parent's copy of remote, to make sure we are
  // reading data from the child.
  remote.erase();

  // Compare against actual remote (not what we sent to the child, since we
  // emptied it).
  TestIovecs want_remote = TestIovecs(GetParam().remote_data);
  auto want_size = std::min(local.bytes_, want_remote.bytes_);
  ASSERT_THAT(process_vm_readv(pid, local.iovecs_.data(), local.iovecs_.size(),
                               remote.iovecs_.data(), remote.iovecs_.size(), 0),
              SyscallSucceedsWithValue(want_size));
  EXPECT_TRUE(bytes_match(local, want_remote, want_size));
}

// TestWritevSameProcess calls process_vm_readv in the same process with various
// local/remote buffers.
TEST_P(ProcessVMTest, TestWritevSameProcess) {
  TestIovecs local(GetParam().local_data);
  TestIovecs remote(GetParam().remote_data);

  auto want_size = std::min(remote.bytes_, local.bytes_);
  EXPECT_THAT(
      process_vm_writev(getpid(), local.iovecs_.data(), local.iovecs_.size(),
                        remote.iovecs_.data(), remote.iovecs_.size(), 0),
      SyscallSucceedsWithValue(want_size));
  EXPECT_TRUE(bytes_match(local, remote, want_size));
}

// TestWritevSubProcess writes data to a forked child process.
TEST_P(ProcessVMTest, TestWritevSubProcess) {
  TestIovecs local(GetParam().local_data);
  TestIovecs remote(GetParam().remote_data);

  // A pipe is used to wait on the write call from the parent, so we can block
  // asserting until the write is complete.
  int pipefd[2];
  ASSERT_THAT(pipe(pipefd), SyscallSucceeds());

  pid_t pid = fork();
  TEST_CHECK_SUCCESS(pid);
  if (pid == 0) {
    // Child. This is the "remote" process.
    close(pipefd[1]);

    // Wait on pipefd. It will be closed after the parent has written.
    char buf;
    TEST_CHECK_SUCCESS(read(pipefd[0], &buf, sizeof(buf)));
    close(pipefd[0]);

    // Check the data. This will exit non-0 in the case of a mismatch.
    auto want_size = std::min(local.bytes_, remote.bytes_);
    TEST_CHECK(bytes_match(local, remote, want_size));

    _exit(0);
  }

  auto cleanup = absl::MakeCleanup([&] {
    int status = 0;
    EXPECT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  });

  // Write to the remote.
  auto want_size = std::min(local.bytes_, remote.bytes_);
  ASSERT_THAT(
      process_vm_writev(pid, local.iovecs_.data(), local.iovecs_.size(),
                        remote.iovecs_.data(), remote.iovecs_.size(), 0),
      SyscallSucceedsWithValue(want_size));

  // Now that we've written, close pipefd to signal the child can continue.
  close(pipefd[1]);
}

TEST(ProcessVMInvalidTest, NonZeroFlags) {
  struct iovec iov = {};
  // Flags should be 0.
  EXPECT_THAT(process_vm_readv(0, &iov, 1, &iov, 1, 10),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(process_vm_writev(0, &iov, 1, &iov, 1, 10),
              SyscallFailsWithErrno(EINVAL));
}

TEST(ProcessVMInvalidTest, NullLocalIovec) {
  struct iovec iov = {};
  pid_t child = fork();
  if (child == 0) {
    sleep(10);  // NOLINT - SleepFor is not async-signal-safe.
    _exit(0);
  }

  EXPECT_THAT(process_vm_readv(child, nullptr, 1, &iov, 1, 0),
              SyscallFailsWithErrno(EFAULT));

  EXPECT_THAT(process_vm_writev(child, nullptr, 1, &iov, 1, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(kill(child, SIGKILL), SyscallSucceeds());
  EXPECT_THAT(waitpid(child, 0, 0), SyscallSucceeds());
}

TEST(ProcessVMInvalidTest, NULLRemoteIovec) {
  std::string contents = "3263827";
  struct iovec iov;
  iov.iov_base = contents.data();
  iov.iov_len = contents.size();

  pid_t pid = fork();
  TEST_CHECK_SUCCESS(pid);
  if (pid == 0) {
    sleep(10);  // NOLINT - SleepFor is not async-signal-safe.
    _exit(0);
  }
  auto cleanup = absl::MakeCleanup([&] { kill(pid, SIGKILL); });

  EXPECT_THAT(process_vm_readv(pid, &iov, contents.length(), nullptr, 1, 0),
              SyscallFailsWithErrno(::testing::AnyOf(EFAULT, EINVAL)));
  EXPECT_THAT(process_vm_writev(pid, &iov, contents.length(), nullptr, 1, 0),
              SyscallFailsWithErrno(::testing::AnyOf(EFAULT, EINVAL)));
}

TEST(ProcessVMInvalidTest, ProcessNoExist) {
  std::string contents = "3263827";
  struct iovec iov;
  iov.iov_base = contents.data();
  iov.iov_len = contents.size();

  EXPECT_THAT(process_vm_readv(-1, &iov, 1, &iov, 1, 0),
              SyscallFailsWithErrno(ESRCH));
  EXPECT_THAT(process_vm_writev(-1, &iov, 1, &iov, 1, 0),
              SyscallFailsWithErrno(ESRCH));
}

TEST(ProcessVMInvalidTest, GreaterThanIOV_MAX) {
  std::string contents = "3263827";
  struct iovec iov;
  iov.iov_base = contents.data();
  iov.iov_len = contents.size();

  pid_t pid = fork();
  TEST_CHECK_SUCCESS(pid);
  if (pid == 0) {
    sleep(10);  // NOLINT - SleepFor is not async-signal-safe.
    _exit(0);
  }
  auto cleanup = absl::MakeCleanup([&] { kill(pid, SIGKILL); });

  EXPECT_THAT(process_vm_readv(pid, &iov, 1, &iov, IOV_MAX + 1, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(process_vm_writev(pid, &iov, 1, &iov, IOV_MAX + 1, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(ProcessVMInvalidTest, PartialReadWrite) {
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

TEST(ProcessVMInvalidTest, AccessInvalidMemoryFailsWithEINVAL) {
  auto const mapping =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  struct iovec iov_none, iov_valid;
  char buf[128];
  iov_valid.iov_base = buf;
  iov_valid.iov_len = sizeof(buf);
  iov_none.iov_base = mapping.ptr();
  iov_none.iov_len = mapping.len();

  EXPECT_THAT(
      RetryEINTR(process_vm_writev)(getpid(), &iov_none, 1, &iov_valid, 1, 0),
      SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(
      RetryEINTR(process_vm_writev)(getpid(), &iov_valid, 1, &iov_none, 1, 0),
      SyscallFailsWithErrno(EFAULT));
}

TEST(ProcessVMTest, WriteToZombie) {
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

// TestReadvNull calls process_vm_readv with null iovecs and checks that they
// succeed but return 0;
TEST(ProcessVMTest, TestReadvNull) {
  TestIovecs local(std::vector<std::string>{"foo"});
  TestIovecs remote(std::vector<std::string>{"bar"});

  // Pass 0 for local.
  EXPECT_THAT(process_vm_readv(getpid(), 0, 0, remote.iovecs_.data(),
                               remote.iovecs_.size(), 0),
              SyscallSucceedsWithValue(0));

  // Pass 0 for remote.
  EXPECT_THAT(process_vm_readv(getpid(), local.iovecs_.data(),
                               local.iovecs_.size(), 0, 0, 0),
              SyscallSucceedsWithValue(0));
}

// TestWritevNull calls process_vm_writev with null iovecs and checks that they
// succeed but return 0;
TEST(ProcessVMTest, TestWritevNull) {
  TestIovecs local(std::vector<std::string>{"foo"});
  TestIovecs remote(std::vector<std::string>{"bar"});

  // Pass 0 for local.
  EXPECT_THAT(process_vm_writev(getpid(), 0, 0, remote.iovecs_.data(),
                                remote.iovecs_.size(), 0),
              SyscallSucceedsWithValue(0));

  // Pass 0 for remote.
  EXPECT_THAT(process_vm_writev(getpid(), local.iovecs_.data(),
                                local.iovecs_.size(), 0, 0, 0),
              SyscallSucceedsWithValue(0));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
