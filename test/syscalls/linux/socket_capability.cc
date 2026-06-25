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

// Subset of socket tests that need Linux-specific headers (compared to POSIX
// headers).

#include <cerrno>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

TEST(SocketTest, UnixConnectNeedsWritePerm) {
  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));

  struct sockaddr_un addr =
      ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(/*abstract=*/false, AF_UNIX));
  ASSERT_THAT(bind(bound.get(), reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());
  ASSERT_THAT(listen(bound.get(), 1), SyscallSucceeds());

  // Drop capabilities that allow us to override permission checks. Otherwise if
  // the test is run as root, the connect below will bypass permission checks
  // and succeed unexpectedly.
  AutoCapability cap(CAP_DAC_OVERRIDE, false);

  // Connect should fail without write perms.
  ASSERT_THAT(chmod(addr.sun_path, 0500), SyscallSucceeds());
  FileDescriptor client =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_UNIX, SOCK_STREAM, PF_UNIX));
  ASSERT_THAT(connect(client.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallFailsWithErrno(EACCES));

  // Connect should succeed with write perms.
  ASSERT_THAT(chmod(addr.sun_path, 0200), SyscallSucceeds());
  EXPECT_THAT(connect(client.get(), reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)),
              SyscallSucceeds());
}

TEST(SocketTest, SetMarkNeedsNetAdminOrRaw) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)) &&
          !ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor bound =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET, SOCK_STREAM, 0));

  int mark = 1234;

  EXPECT_THAT(setsockopt(bound.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)),
              SyscallSucceeds());

  AutoCapability cap_admin(CAP_NET_ADMIN, false);
  AutoCapability cap_raw(CAP_NET_RAW, false);
  EXPECT_THAT(setsockopt(bound.get(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)),
              SyscallFailsWithErrno(EPERM));

  int get_mark = 0;
  socklen_t optlen = sizeof(get_mark);
  EXPECT_THAT(getsockopt(bound.get(), SOL_SOCKET, SO_MARK, &get_mark, &optlen),
              SyscallSucceeds());
  EXPECT_EQ(get_mark, mark);
}

}  // namespace testing
}  // namespace gvisor
