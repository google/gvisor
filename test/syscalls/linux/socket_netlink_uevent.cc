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

#include <linux/filter.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

// Tests for NETLINK_KOBJECT_UEVENT sockets.
//
// gVisor never sends any messages on these sockets, so we don't test the events
// themselves.

namespace gvisor {
namespace testing {

namespace {

// SO_PASSCRED can be enabled. Since no messages are sent in gVisor, we don't
// actually test receiving credentials.
TEST(NetlinkUeventTest, PassCred) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_KOBJECT_UEVENT));

  EXPECT_THAT(setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &kSockOptOn,
                         sizeof(kSockOptOn)),
              SyscallSucceeds());
}

// SO_DETACH_FILTER fails without a filter already installed.
TEST(NetlinkUeventTest, DetachNoFilter) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_KOBJECT_UEVENT));

  int opt;
  EXPECT_THAT(
      setsockopt(fd.get(), SOL_SOCKET, SO_DETACH_FILTER, &opt, sizeof(opt)),
      SyscallFailsWithErrno(ENOENT));
}

// We can attach a BPF filter.
TEST(NetlinkUeventTest, AttachFilter) {
  FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_KOBJECT_UEVENT));

  // Minimal BPF program: a single ret.
  struct sock_filter filter = {0x6, 0, 0, 0};
  struct sock_fprog prog = {};
  prog.len = 1;
  prog.filter = &filter;

  EXPECT_THAT(
      setsockopt(fd.get(), SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)),
      SyscallSucceeds());

  int opt;
  EXPECT_THAT(
      setsockopt(fd.get(), SOL_SOCKET, SO_DETACH_FILTER, &opt, sizeof(opt)),
      SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
