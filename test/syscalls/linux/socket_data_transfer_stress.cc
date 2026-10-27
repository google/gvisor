// Copyright 2020 The gVisor Authors.
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

#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

using DataTransferStressTest = SocketPairTest;

TEST_P(DataTransferStressTest, BigDataTransfer) {
  const std::unique_ptr<SocketPair> sockets =
      ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());
  int client_fd = sockets->first_fd();
  int server_fd = sockets->second_fd();

  ScopedThread echo([server_fd]() {
    std::array<uint8_t, 1024> buf;
    for (;;) {
      ssize_t r = read(server_fd, buf.data(), buf.size());
      ASSERT_THAT(r, SyscallSucceeds());
      if (r == 0) {
        break;
      }
      for (ssize_t i = 0; i < r;) {
        ssize_t w = write(server_fd, buf.data() + i, r - i);
        ASSERT_GE(w, 0);
        i += w;
      }
    }
    ASSERT_THAT(shutdown(server_fd, SHUT_WR), SyscallSucceeds());
  });

  // Tests can be prohibitively slow on the KVM platform with nested virt.
  const int kShift = GvisorPlatform() == Platform::kKVM ? 10 : 20;

  const std::string chunk = "Though this upload be but little, it is fierce.";
  std::string big_string;
  while (big_string.size() < size_t(31 << kShift)) {
    big_string += chunk;
  }
  absl::string_view data = big_string;

  ScopedThread writer([client_fd, data]() {
    absl::string_view view = data;
    while (!view.empty()) {
      ssize_t n = write(client_fd, view.data(), view.size());
      ASSERT_GE(n, 0);
      view = view.substr(n);
    }
    ASSERT_THAT(shutdown(client_fd, SHUT_WR), SyscallSucceeds());
  });

  std::string buf;
  buf.resize(1 << kShift);
  while (!data.empty()) {
    ssize_t n = read(client_fd, buf.data(), buf.size());
    ASSERT_GE(n, 0);
    for (ssize_t i = 0; i < n; i += chunk.size()) {
      ssize_t c = std::min(ssize_t(chunk.size()), n - i);
      ASSERT_EQ(buf.substr(i, c), data.substr(i, c)) << "offset " << i;
    }
    data = data.substr(n);
  }
  // Should read EOF now.
  ASSERT_THAT(read(client_fd, buf.data(), buf.size()),
              SyscallSucceedsWithValue(0));
}

INSTANTIATE_TEST_SUITE_P(
    AllConnectedSockets, DataTransferStressTest,
    ::testing::Values(IPv6TCPAcceptBindPersistentListenerSocketPair(0),
                      IPv4TCPAcceptBindPersistentListenerSocketPair(0),
                      DualStackTCPAcceptBindPersistentListenerSocketPair(0)));

}  // namespace testing
}  // namespace gvisor
