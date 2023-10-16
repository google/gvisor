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

#include <sys/select.h>

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

// Populates |event_fds| with new event FDs and |read_fds| with each new event
// FD.
void Setup(int count, std::vector<FileDescriptor>& event_fds, fd_set& read_fds,
           int& max_fd) {
  max_fd = -1;
  FD_ZERO(&read_fds);

  for (int i = 0; i < count; ++i) {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(NewEventFD());
    if (fd.get() > max_fd) {
      max_fd = fd.get();
    }
    FD_SET(fd.get(), &read_fds);
    event_fds.push_back(std::move(fd));
  }

  ASSERT_LT(max_fd, FD_SETSIZE);
}

// Benchmarks a call to select(2) when no FD is "ready" with varying timeout
// values.
void BM_SelectTimeout(benchmark::State& state) {
  constexpr int kFDsPerSelect = 3;
  std::vector<FileDescriptor> event_fds;
  fd_set read_fds;
  int max_fd;
  ASSERT_NO_FATAL_FAILURE(Setup(kFDsPerSelect, event_fds, read_fds, max_fd));

  const int timeout_ms = state.range(0);
  timeval timeout = {
      .tv_sec = 0,
      .tv_usec = timeout_ms * 1000,
  };
  for (auto _ : state) {
    EXPECT_EQ(select(max_fd + 1, &read_fds, /*writefds=*/nullptr,
                     /*exceptfds=*/nullptr, &timeout),
              0);
  }
}

BENCHMARK(BM_SelectTimeout)->Range(/*start=*/0, /*limit=*/8);

// Benchmarks a call to select(2) with a zero timeout and varying number of
// "ready" FDs.
void BM_SelectAllEvents(benchmark::State& state) {
  const int fds_per_select = state.range(0);
  std::vector<FileDescriptor> event_fds;
  fd_set read_fds;
  int max_fd;
  ASSERT_NO_FATAL_FAILURE(Setup(fds_per_select, event_fds, read_fds, max_fd));

  constexpr uint64_t kEventVal = 5;
  for (const auto& eventfd : event_fds) {
    ASSERT_THAT(WriteFd(eventfd.get(), &kEventVal, sizeof(kEventVal)),
                SyscallSucceedsWithValue(sizeof(kEventVal)));
  }

  timeval timeout = {};
  for (auto _ : state) {
    EXPECT_EQ(select(max_fd + 1, &read_fds, /*writefds=*/nullptr,
                     /*exceptfds=*/nullptr, &timeout),
              fds_per_select);
  }
}

BENCHMARK(BM_SelectAllEvents)->Range(/*start=*/2, /*limit=*/512);

}  // namespace

}  // namespace testing
}  // namespace gvisor
