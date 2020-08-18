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

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <memory>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "benchmark/benchmark.h"
#include "test/util/epoll_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// Returns a new eventfd.
PosixErrorOr<FileDescriptor> NewEventFD() {
  int fd = eventfd(0, /* flags = */ 0);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "eventfd");
  }
  return FileDescriptor(fd);
}

// Also stolen from epoll.cc unit tests.
void BM_EpollTimeout(benchmark::State& state) {
  constexpr int kFDsPerEpoll = 3;
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());

  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < kFDsPerEpoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(
        RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN, 0));
  }

  struct epoll_event result[kFDsPerEpoll];
  int timeout_ms = state.range(0);

  for (auto _ : state) {
    EXPECT_EQ(0, epoll_wait(epollfd.get(), result, kFDsPerEpoll, timeout_ms));
  }
}

BENCHMARK(BM_EpollTimeout)->Range(0, 8);

// Also stolen from epoll.cc unit tests.
void BM_EpollAllEvents(benchmark::State& state) {
  auto epollfd = ASSERT_NO_ERRNO_AND_VALUE(NewEpollFD());
  const int fds_per_epoll = state.range(0);
  constexpr uint64_t kEventVal = 5;

  std::vector<FileDescriptor> eventfds;
  for (int i = 0; i < fds_per_epoll; i++) {
    eventfds.push_back(ASSERT_NO_ERRNO_AND_VALUE(NewEventFD()));
    ASSERT_NO_ERRNO(
        RegisterEpollFD(epollfd.get(), eventfds[i].get(), EPOLLIN, 0));

    ASSERT_THAT(WriteFd(eventfds[i].get(), &kEventVal, sizeof(kEventVal)),
                SyscallSucceedsWithValue(sizeof(kEventVal)));
  }

  std::vector<struct epoll_event> result(fds_per_epoll);

  for (auto _ : state) {
    EXPECT_EQ(fds_per_epoll,
              epoll_wait(epollfd.get(), result.data(), fds_per_epoll, 0));
  }
}

BENCHMARK(BM_EpollAllEvents)->Range(2, 1024);

}  // namespace

}  // namespace testing
}  // namespace gvisor
