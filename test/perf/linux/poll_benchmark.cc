// Copyright 2023 The gVisor Authors.
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

#include <sys/poll.h>

#include <cstdint>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "benchmark/benchmark.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

void Setup(int count, std::vector<FileDescriptor>& event_fds,
           std::vector<pollfd>& poll_fds) {
  for (int i = 0; i < count; ++i) {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
    poll_fds.push_back(pollfd{.fd = fd.get(), .events = POLLIN});
    event_fds.push_back(std::move(fd));
  }
}

void BM_PollTimeout(benchmark::State& state) {
  constexpr int kFDsPerPoll = 3;
  std::vector<FileDescriptor> event_fds;
  std::vector<pollfd> poll_fds;
  ASSERT_NO_FATAL_FAILURE(Setup(kFDsPerPoll, event_fds, poll_fds));

  const int timeout_ms = state.range(0);
  for (auto _ : state) {
    EXPECT_EQ(poll(poll_fds.data(), poll_fds.size(), timeout_ms), 0);
  }
}

BENCHMARK(BM_PollTimeout)->Range(/*start=*/0, /*limit=*/8);

void BM_PollAllEvents(benchmark::State& state) {
  const int fds_per_poll = state.range(0);
  std::vector<FileDescriptor> event_fds;
  std::vector<pollfd> poll_fds;
  ASSERT_NO_FATAL_FAILURE(Setup(fds_per_poll, event_fds, poll_fds));

  constexpr uint64_t kEventVal = 5;
  for (const auto& eventfd : event_fds) {
    ASSERT_THAT(WriteFd(eventfd.get(), &kEventVal, sizeof(kEventVal)),
                SyscallSucceedsWithValue(sizeof(kEventVal)));
  }

  constexpr int kTimeoutMs = 0;
  for (auto _ : state) {
    EXPECT_EQ(poll(poll_fds.data(), poll_fds.size(), kTimeoutMs), fds_per_poll);
  }
}

BENCHMARK(BM_PollAllEvents)->Range(/*start=*/2, /*limit=*/1024);

}  // namespace

}  // namespace testing
}  // namespace gvisor
