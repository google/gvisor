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

#include "test/syscalls/linux/socket_blocking.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <cstdio>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"
#include "test/util/timer_util.h"

namespace gvisor {
namespace testing {

TEST_P(BlockingSocketPairTest, RecvBlocks) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(NewSocketPair());

  char sent_data[100];
  RandomizeBuffer(sent_data, sizeof(sent_data));

  constexpr auto kDuration = absl::Milliseconds(200);
  auto before = Now(CLOCK_MONOTONIC);

  const ScopedThread t([&]() {
    absl::SleepFor(kDuration);
    ASSERT_THAT(write(sockets->first_fd(), sent_data, sizeof(sent_data)),
                SyscallSucceedsWithValue(sizeof(sent_data)));
  });

  char received_data[sizeof(sent_data)] = {};
  ASSERT_THAT(RetryEINTR(recv)(sockets->second_fd(), received_data,
                               sizeof(received_data), 0),
              SyscallSucceedsWithValue(sizeof(received_data)));

  auto after = Now(CLOCK_MONOTONIC);
  EXPECT_GE(after - before, kDuration);
}

}  // namespace testing
}  // namespace gvisor
