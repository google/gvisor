// Copyright 2019 The gVisor Authors.
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

#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"
#include "test/util/time_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<int> InNewUserNamespace(const std::function<void()>& fn) {
  return InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWUSER) == 0);
    MaybeSave();
    fn();
  });
}

PosixErrorOr<std::tuple<pid_t, Cleanup>> CreateProcessInNewUserNamespace() {
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    return PosixError(errno, "pipe failed");
  }
  const auto cleanup_pipe_read =
      Cleanup([&] { EXPECT_THAT(close(pipefd[0]), SyscallSucceeds()); });
  auto cleanup_pipe_write =
      Cleanup([&] { EXPECT_THAT(close(pipefd[1]), SyscallSucceeds()); });
  pid_t child_pid = fork();
  if (child_pid < 0) {
    return PosixError(errno, "fork failed");
  }
  if (child_pid == 0) {
    // Close our copy of the pipe's read end, which doesn't really matter.
    TEST_PCHECK(close(pipefd[0]) >= 0);
    TEST_PCHECK(unshare(CLONE_NEWUSER) == 0);
    MaybeSave();
    // Indicate that we've switched namespaces by unblocking the parent's read.
    TEST_PCHECK(close(pipefd[1]) >= 0);
    while (true) {
      SleepSafe(absl::Minutes(1));
    }
  }
  auto cleanup_child = Cleanup([child_pid] {
    EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
    int status;
    ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        << "status = " << status;
  });
  // Close our copy of the pipe's write end, then wait for the child to close
  // its copy, indicating that it's switched namespaces.
  cleanup_pipe_write.Release()();
  char buf;
  if (RetryEINTR(read)(pipefd[0], &buf, 1) < 0) {
    return PosixError(errno, "reading from pipe failed");
  }
  MaybeSave();
  return std::make_tuple(child_pid, std::move(cleanup_child));
}

// TEST_CHECK-fails on error, since this function is used in contexts that
// require async-signal-safety.
void DenySetgroupsByPath(const char* path) {
  int fd = open(path, O_WRONLY);
  if (fd < 0 && errno == ENOENT) {
    // On kernels where this file doesn't exist, writing "deny" to it isn't
    // necessary to write to gid_map.
    return;
  }
  TEST_PCHECK(fd >= 0);
  MaybeSave();
  char deny[] = "deny";
  TEST_PCHECK(write(fd, deny, sizeof(deny)) == sizeof(deny));
  MaybeSave();
  TEST_PCHECK(close(fd) == 0);
}

void DenySelfSetgroups() { DenySetgroupsByPath("/proc/self/setgroups"); }

void DenyPidSetgroups(pid_t pid) {
  DenySetgroupsByPath(absl::StrCat("/proc/", pid, "/setgroups").c_str());
}

// Returns a valid UID/GID that isn't id.
uint32_t another_id(uint32_t id) { return (id + 1) % 65535; }

struct TestParam {
  std::string desc;
  int cap;
  std::function<std::string(absl::string_view)> get_map_filename;
  std::function<uint32_t()> get_current_id;
};

std::string DescribeTestParam(const ::testing::TestParamInfo<TestParam>& info) {
  return info.param.desc;
}

std::vector<TestParam> UidGidMapTestParams() {
  return {TestParam{"UID", CAP_SETUID,
                    [](absl::string_view pid) {
                      return absl::StrCat("/proc/", pid, "/uid_map");
                    },
                    []() -> uint32_t { return getuid(); }},
          TestParam{"GID", CAP_SETGID,
                    [](absl::string_view pid) {
                      return absl::StrCat("/proc/", pid, "/gid_map");
                    },
                    []() -> uint32_t { return getgid(); }}};
}

class ProcUidGidMapTest : public ::testing::TestWithParam<TestParam> {
 protected:
  uint32_t CurrentID() { return GetParam().get_current_id(); }
};

class ProcSelfUidGidMapTest : public ProcUidGidMapTest {
 protected:
  PosixErrorOr<int> InNewUserNamespaceWithMapFD(
      const std::function<void(int)>& fn) {
    std::string map_filename = GetParam().get_map_filename("self");
    return InNewUserNamespace([&] {
      int fd = open(map_filename.c_str(), O_RDWR);
      TEST_PCHECK(fd >= 0);
      MaybeSave();
      fn(fd);
      TEST_PCHECK(close(fd) == 0);
    });
  }
};

class ProcPidUidGidMapTest : public ProcUidGidMapTest {
 protected:
  PosixErrorOr<bool> HaveSetIDCapability() {
    return HaveCapability(GetParam().cap);
  }

  // Returns true if the caller is running in a user namespace with all IDs
  // mapped. This matters for tests that expect to successfully map arbitrary
  // IDs into a child user namespace, since even with CAP_SET*ID this is only
  // possible if those IDs are mapped into the current one.
  PosixErrorOr<bool> AllIDsMapped() {
    ASSIGN_OR_RETURN_ERRNO(std::string id_map,
                           GetContents(GetParam().get_map_filename("self")));
    absl::StripTrailingAsciiWhitespace(&id_map);
    std::vector<std::string> id_map_parts =
        absl::StrSplit(id_map, ' ', absl::SkipEmpty());
    return id_map_parts == std::vector<std::string>({"0", "0", "4294967295"});
  }

  PosixErrorOr<FileDescriptor> OpenMapFile(pid_t pid) {
    return Open(GetParam().get_map_filename(absl::StrCat(pid)), O_RDWR);
  }
};

TEST_P(ProcSelfUidGidMapTest, IsInitiallyEmpty) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  EXPECT_THAT(InNewUserNamespaceWithMapFD([](int fd) {
                char buf[64];
                TEST_PCHECK(read(fd, buf, sizeof(buf)) == 0);
              }),
              IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, IdentityMapOwnID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  uint32_t id = CurrentID();
  std::string line = absl::StrCat(id, " ", id, " 1");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        size_t n;
        TEST_PCHECK((n = write(fd, line.c_str(), line.size())) != -1);
        TEST_CHECK(n == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, TrailingNewlineAndNULIgnored) {
  // This is identical to IdentityMapOwnID, except that a trailing newline, NUL,
  // and an invalid (incomplete) map entry are appended to the valid entry. The
  // newline should be accepted, and everything after the NUL should be ignored.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  uint32_t id = CurrentID();
  std::string line = absl::StrCat(id, " ", id, " 1\n\0 4 3");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        // The write should return the full size of the write, even though
        // characters after the NUL were ignored.
        size_t n;
        TEST_PCHECK((n = write(fd, line.c_str(), line.size())) != -1);
        TEST_CHECK(n == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, NonIdentityMapOwnID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  uint32_t id = CurrentID();
  uint32_t id2 = another_id(id);
  std::string line = absl::StrCat(id2, " ", id, " 1");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        TEST_PCHECK(static_cast<long unsigned int>(
                        write(fd, line.c_str(), line.size())) == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, MapOtherID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  // Whether or not we have CAP_SET*ID is irrelevant: the process running in the
  // new (child) user namespace won't have any capabilities in the current
  // (parent) user namespace, which is needed.
  uint32_t id = CurrentID();
  uint32_t id2 = another_id(id);
  std::string line = absl::StrCat(id, " ", id2, " 1");
  EXPECT_THAT(InNewUserNamespaceWithMapFD([&](int fd) {
                DenySelfSetgroups();
                TEST_PCHECK(write(fd, line.c_str(), line.size()) < 0);
                TEST_CHECK(errno == EPERM);
              }),
              IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(All, ProcSelfUidGidMapTest,
                         ::testing::ValuesIn(UidGidMapTestParams()),
                         DescribeTestParam);

TEST_P(ProcPidUidGidMapTest, MapOtherIDPrivileged) {
  // Like ProcSelfUidGidMapTest_MapOtherID, but since we have CAP_SET*ID in the
  // parent user namespace (this one), we can map IDs that aren't ours.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(AllIDsMapped()));

  pid_t child_pid;
  Cleanup cleanup_child;
  std::tie(child_pid, cleanup_child) =
      ASSERT_NO_ERRNO_AND_VALUE(CreateProcessInNewUserNamespace());

  uint32_t id = CurrentID();
  uint32_t id2 = another_id(id);
  std::string line = absl::StrCat(id, " ", id2, " 1");
  DenyPidSetgroups(child_pid);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenMapFile(child_pid));
  EXPECT_THAT(write(fd.get(), line.c_str(), line.size()),
              SyscallSucceedsWithValue(line.size()));
}

TEST_P(ProcPidUidGidMapTest, MapAnyIDsPrivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(AllIDsMapped()));

  pid_t child_pid;
  Cleanup cleanup_child;
  std::tie(child_pid, cleanup_child) =
      ASSERT_NO_ERRNO_AND_VALUE(CreateProcessInNewUserNamespace());

  // Test all of:
  //
  // - Mapping ranges of length > 1
  //
  // - Mapping multiple ranges
  //
  // - Non-identity mappings
  char entries[] = "2 0 2\n4 6 2";
  DenyPidSetgroups(child_pid);
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(OpenMapFile(child_pid));
  EXPECT_THAT(write(fd.get(), entries, sizeof(entries)),
              SyscallSucceedsWithValue(sizeof(entries)));
}

INSTANTIATE_TEST_SUITE_P(All, ProcPidUidGidMapTest,
                         ::testing::ValuesIn(UidGidMapTestParams()),
                         DescribeTestParam);

}  // namespace testing
}  // namespace gvisor
