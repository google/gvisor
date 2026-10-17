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

#include "tools/ioctl_sniffer/sniffer_bridge.h"

#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <optional>
#include <string>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "tools/ioctl_sniffer/ioctl.pb.h"

namespace gvisor {
namespace testing {
namespace {

constexpr char kSocketEnv[] = "GVISOR_IOCTL_SNIFFER_SOCKET_PATH";

TEST(SnifferBridgeTest, FramesConsecutiveMessages) {
  const auto addr = ASSERT_NO_ERRNO_AND_VALUE(UniqueUnixAddr(false, AF_UNIX));
  const FileDescriptor listener(socket(AF_UNIX, SOCK_STREAM, 0));
  ASSERT_THAT(listener.get(), SyscallSucceeds());
  ASSERT_THAT(bind(listener.get(), reinterpret_cast<const sockaddr*>(&addr),
                   sizeof(addr)),
              SyscallSucceeds());
  const Cleanup unlink_socket([&addr] { unlink(addr.sun_path); });
  ASSERT_THAT(listen(listener.get(), 1), SyscallSucceeds());

  std::optional<std::string> previous;
  if (const char* value = std::getenv(kSocketEnv); value != nullptr) {
    previous = value;
  }
  const Cleanup restore_env([&previous] {
    if (previous.has_value()) {
      setenv(kSocketEnv, previous->c_str(), 1);
    } else {
      unsetenv(kSocketEnv);
    }
  });
  ASSERT_THAT(setenv(kSocketEnv, addr.sun_path, 1), SyscallSucceeds());

  // The empty second message checks that buffer reuse does not retain the
  // first message's payload.
  std::array<Ioctl, 2> messages;
  messages[0].set_fd_path("/dev/nvidia0");
  messages[0].set_request(123);
  messages[0].set_ret(-1);
  messages[0].set_arg_data("ioctl arguments");
  const ScopedThread sender([&messages] {
    for (const auto& message : messages) {
      WriteIoctlProto(message);
    }
  });

  const FileDescriptor connection(
      RetryEINTR(accept)(listener.get(), nullptr, nullptr));
  ASSERT_THAT(connection.get(), SyscallSucceeds());
  for (const auto& expected : messages) {
    std::array<unsigned char, sizeof(uint64_t)> header;
    ASSERT_THAT(ReadFd(connection.get(), header.data(), header.size()),
                SyscallSucceedsWithValue(header.size()));
    uint64_t size = 0;
    for (size_t i = 0; i < header.size(); ++i) {
      size |= static_cast<uint64_t>(header[i]) << (8 * i);
    }
    ASSERT_EQ(size, expected.ByteSizeLong());
    std::string encoded(size, '\0');
    ASSERT_THAT(ReadFd(connection.get(), encoded.data(), encoded.size()),
                SyscallSucceedsWithValue(encoded.size()));
    Ioctl actual;
    ASSERT_TRUE(actual.ParseFromString(encoded));
    EXPECT_EQ(actual.SerializeAsString(), expected.SerializeAsString());
  }
  // The sending thread owns the connection and closes it on exit.
  char trailing;
  EXPECT_THAT(ReadFd(connection.get(), &trailing, 1),
              SyscallSucceedsWithValue(0));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
