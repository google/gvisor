// Copyright 2019 Google LLC
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
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<int> InNewUserNamespace(const std::function<void()>& fn) {
  return InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWUSER) == 0);
    MaybeSave();
    fn();
  });
}

// TEST_CHECK-fails on error, since this function is used in contexts that
// require async-signal-safety.
void DenySelfSetgroups() {
  int fd = open("/proc/self/setgroups", O_WRONLY);
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

// Returns a valid UID/GID that isn't id.
uint32_t another_id(uint32_t id) { return (id + 1) % 65535; }

struct TestParam {
  std::string desc;
  std::string map_filename;
  int cap;
  std::function<uint32_t()> get_current_id;
};

std::string DescribeTestParam(const ::testing::TestParamInfo<TestParam>& info) {
  return info.param.desc;
}

class ProcSelfUidGidMapTest : public ::testing::TestWithParam<TestParam> {
 protected:
  PosixErrorOr<int> InNewUserNamespaceWithMapFD(
      const std::function<void(int)>& fn) {
    std::string map_filename = GetParam().map_filename;
    return InNewUserNamespace([&] {
      int fd = open(map_filename.c_str(), O_RDWR);
      TEST_PCHECK(fd >= 0);
      MaybeSave();
      fn(fd);
      TEST_PCHECK(close(fd) == 0);
    });
  }

  uint32_t CurrentID() { return GetParam().get_current_id(); }

  PosixErrorOr<bool> HaveSetIDCapability() {
    return HaveCapability(GetParam().cap);
  }

  // Returns true if the caller is running in a user namespace with all IDs
  // mapped. This matters for tests that expect to successfully map arbitrary
  // IDs into a child user namespace, since even with CAP_SET*ID this is only
  // possible if those IDs are mapped into the current one.
  PosixErrorOr<bool> AllIDsMapped() {
    ASSIGN_OR_RETURN_ERRNO(std::string id_map, GetContents(GetParam().map_filename));
    std::vector<std::string> id_map_parts =
        absl::StrSplit(id_map, ' ', absl::SkipEmpty());
    return id_map_parts == std::vector<std::string>({"0", "0", "4294967295"});
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
  // This is the only write permitted if the writer does not have CAP_SET*ID.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  uint32_t id = CurrentID();
  std::string line = absl::StrCat(id, " ", id, " 1");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        TEST_PCHECK(write(fd, line.c_str(), line.size()) == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, NonIdentityMapOwnID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
  uint32_t id = CurrentID();
  uint32_t id2 = another_id(id);
  std::string line = absl::StrCat(id2, " ", id, " 1");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        TEST_PCHECK(write(fd, line.c_str(), line.size()) == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, MapOtherIDUnprivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
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

TEST_P(ProcSelfUidGidMapTest, MapOtherIDPrivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(AllIDsMapped()));
  uint32_t id = CurrentID();
  uint32_t id2 = another_id(id);
  std::string line = absl::StrCat(id, " ", id2, " 1");
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        TEST_PCHECK(write(fd, line.c_str(), line.size()) == line.size());
      }),
      IsPosixErrorOkAndHolds(0));
}

TEST_P(ProcSelfUidGidMapTest, MapAnyIDsPrivileged) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(CanCreateUserNamespace()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveSetIDCapability()));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(AllIDsMapped()));
  // Test all of:
  //
  // - Mapping ranges of length > 1
  //
  // - Mapping multiple ranges
  //
  // - Non-identity mappings
  char entries[] = "2 0 2\n4 6 2";
  EXPECT_THAT(
      InNewUserNamespaceWithMapFD([&](int fd) {
        DenySelfSetgroups();
        TEST_PCHECK(write(fd, entries, sizeof(entries)) == sizeof(entries));
      }),
      IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_CASE_P(
    All, ProcSelfUidGidMapTest,
    ::testing::Values(TestParam{"UID", "/proc/self/uid_map", CAP_SETUID,
                                []() -> uint32_t { return getuid(); }},
                      TestParam{"GID", "/proc/self/gid_map", CAP_SETGID,
                                []() -> uint32_t { return getgid(); }}),
    DescribeTestParam);

}  // namespace testing
}  // namespace gvisor
