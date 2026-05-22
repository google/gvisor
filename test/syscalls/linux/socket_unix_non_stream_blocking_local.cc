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

#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

#include <vector>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_non_stream_blocking.h"
#include "test/syscalls/linux/unix_domain_socket_test_util.h"
#include "test/util/signal_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

void SigUrgHandler(int) {}

std::vector<SocketPairKind> GetSocketPairs() {
  return VecCat<SocketPairKind>(
      ApplyVec<SocketPairKind>(UnixDomainSocketPair,
                               std::vector<int>{SOCK_DGRAM, SOCK_SEQPACKET}),
      ApplyVec<SocketPairKind>(FilesystemBoundUnixDomainSocketPair,
                               std::vector<int>{SOCK_DGRAM, SOCK_SEQPACKET}),
      ApplyVec<SocketPairKind>(AbstractBoundUnixDomainSocketPair,
                               std::vector<int>{SOCK_DGRAM, SOCK_SEQPACKET}));
}

INSTANTIATE_TEST_SUITE_P(
    BlockingNonStreamUnixSockets, BlockingNonStreamSocketPairTest,
    ::testing::ValuesIn(IncludeReversals(GetSocketPairs())));

// Some SOCK_SEQPACKET users probe the next packet length by calling recvfrom
// with MSG_TRUNC | MSG_PEEK and a null, zero-length receive buffer. When a
// signal handler is installed with SA_RESTART, Linux restarts this blocking
// recvfrom instead of returning EINTR. Do not wrap recvfrom in RetryEINTR here:
// the test is checking kernel restart behavior, not userspace retry behavior.
TEST(UnixSeqpacketBlockingTest, RecvfromTruncPeekNullBufferRestarted) {
  auto sockets = ASSERT_NO_ERRNO_AND_VALUE(
      UnixDomainSocketPair(SOCK_SEQPACKET | SOCK_CLOEXEC).Create());

  struct sigaction sa = {};
  sa.sa_handler = SigUrgHandler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  auto const cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSigaction(SIGURG, sa));

  pthread_t target = pthread_self();
  constexpr char kPayload[] = "recvfrom-restart";

  ScopedThread t([&] {
    absl::SleepFor(absl::Milliseconds(50));
    ASSERT_EQ(pthread_kill(target, SIGURG), 0);
    absl::SleepFor(absl::Milliseconds(100));
    ASSERT_THAT(
        RetryEINTR(send)(sockets->first_fd(), kPayload, sizeof(kPayload), 0),
        SyscallSucceedsWithValue(sizeof(kPayload)));
  });

  ASSERT_THAT(recvfrom(sockets->second_fd(), nullptr, 0, MSG_TRUNC | MSG_PEEK,
                       nullptr, nullptr),
              SyscallSucceedsWithValue(sizeof(kPayload)));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
