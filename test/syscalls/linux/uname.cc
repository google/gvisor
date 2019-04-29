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

#include <sched.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/util/capability_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(UnameTest, Sanity) {
  struct utsname buf;
  ASSERT_THAT(uname(&buf), SyscallSucceeds());
  EXPECT_NE(strlen(buf.release), 0);
  EXPECT_NE(strlen(buf.version), 0);
  EXPECT_NE(strlen(buf.machine), 0);
  EXPECT_NE(strlen(buf.sysname), 0);
  EXPECT_NE(strlen(buf.nodename), 0);
  EXPECT_NE(strlen(buf.domainname), 0);
}

TEST(UnameTest, SetNames) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  constexpr char kHostname[] = "wubbalubba";
  ASSERT_THAT(sethostname(kHostname, sizeof(kHostname)), SyscallSucceeds());

  constexpr char kDomainname[] = "dubdub.com";
  ASSERT_THAT(setdomainname(kDomainname, sizeof(kDomainname)),
              SyscallSucceeds());

  struct utsname buf;
  EXPECT_THAT(uname(&buf), SyscallSucceeds());
  EXPECT_EQ(absl::string_view(buf.nodename), kHostname);
  EXPECT_EQ(absl::string_view(buf.domainname), kDomainname);

  // These should just be glibc wrappers that also call uname(2).
  char hostname[65];
  EXPECT_THAT(gethostname(hostname, sizeof(hostname)), SyscallSucceeds());
  EXPECT_EQ(absl::string_view(hostname), kHostname);

  char domainname[65];
  EXPECT_THAT(getdomainname(domainname, sizeof(domainname)), SyscallSucceeds());
  EXPECT_EQ(absl::string_view(domainname), kDomainname);
}

TEST(UnameTest, UnprivilegedSetNames) {
  if (ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN))) {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
  }

  EXPECT_THAT(sethostname("", 0), SyscallFailsWithErrno(EPERM));
  EXPECT_THAT(setdomainname("", 0), SyscallFailsWithErrno(EPERM));
}

TEST(UnameTest, UnshareUTS) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  struct utsname init;
  ASSERT_THAT(uname(&init), SyscallSucceeds());

  ScopedThread([&]() {
    EXPECT_THAT(unshare(CLONE_NEWUTS), SyscallSucceeds());

    constexpr char kHostname[] = "wubbalubba";
    EXPECT_THAT(sethostname(kHostname, sizeof(kHostname)), SyscallSucceeds());

    char hostname[65];
    EXPECT_THAT(gethostname(hostname, sizeof(hostname)), SyscallSucceeds());
  });

  struct utsname after;
  EXPECT_THAT(uname(&after), SyscallSucceeds());
  EXPECT_EQ(absl::string_view(after.nodename), init.nodename);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
