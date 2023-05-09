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

#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/synchronization/barrier.h"
#include "benchmark/benchmark.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/logging.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int kBusyMax = 250;

// Do some CPU-bound busy-work.
int busy(int max) {
  // Prevent the compiler from optimizing this work away,
  volatile int count = 0;

  for (int i = 1; i < max; i++) {
    for (int j = 2; j < i / 2; j++) {
      if (i % j == 0) {
        count++;
      }
    }
  }

  return count;
}

void BM_CPUBoundUniprocess(benchmark::State& state) {
  for (auto _ : state) {
    busy(kBusyMax);
  }
}

BENCHMARK(BM_CPUBoundUniprocess);

void BM_CPUBoundAsymmetric(benchmark::State& state) {
  const size_t max = state.max_iterations;
  pid_t child = fork();
  if (child == 0) {
    for (size_t i = 0; i < max; i++) {
      busy(kBusyMax);
    }
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  ASSERT_TRUE(state.KeepRunningBatch(max));

  int status;
  EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(0, WEXITSTATUS(status));
  ASSERT_FALSE(state.KeepRunning());
}

BENCHMARK(BM_CPUBoundAsymmetric)->UseRealTime();

void BM_CPUBoundSymmetric(benchmark::State& state) {
  std::vector<pid_t> children;
  auto child_cleanup = Cleanup([&] {
    for (const pid_t child : children) {
      int status;
      EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
      EXPECT_TRUE(WIFEXITED(status));
      EXPECT_EQ(0, WEXITSTATUS(status));
    }
    ASSERT_FALSE(state.KeepRunning());
  });

  const int processes = state.range(0);
  for (int i = 0; i < processes; i++) {
    size_t cur = (state.max_iterations + (processes - 1)) / processes;
    if ((state.iterations() + cur) >= state.max_iterations) {
      cur = state.max_iterations - state.iterations();
    }
    pid_t child = fork();
    if (child == 0) {
      for (size_t i = 0; i < cur; i++) {
        busy(kBusyMax);
      }
      _exit(0);
    }
    ASSERT_THAT(child, SyscallSucceeds());
    if (cur > 0) {
      // We can have a zero cur here, depending.
      ASSERT_TRUE(state.KeepRunningBatch(cur));
    }
    children.push_back(child);
  }
}

BENCHMARK(BM_CPUBoundSymmetric)->Range(2, 16)->UseRealTime();

// Child routine for ProcessSwitch/ThreadSwitch.
// Reads from readfd and writes the result to writefd.
void SwitchChild(int readfd, int writefd) {
  while (1) {
    char buf;
    int ret = ReadFd(readfd, &buf, 1);
    if (ret == 0) {
      break;
    }
    TEST_CHECK_MSG(ret == 1, "read failed");

    ret = WriteFd(writefd, &buf, 1);
    if (ret == -1) {
      TEST_CHECK_MSG(errno == EPIPE, "unexpected write failure");
      break;
    }
    TEST_CHECK_MSG(ret == 1, "write failed");
  }
}

// Send bytes in a loop through a series of pipes, each passing through a
// different process.
//
//  Proc 0        Proc 1
//    * ----------> *
//    ^   Pipe 1    |
//    |             |
//    | Pipe 0      | Pipe 2
//    |             |
//    |             |
//    |   Pipe 3    v
//    * <---------- *
//  Proc 3        Proc 2
//
// This exercises context switching through multiple processes.
void BM_ProcessSwitch(benchmark::State& state) {
  // Code below assumes there are at least two processes.
  const int num_processes = state.range(0);
  ASSERT_GE(num_processes, 2);

  std::vector<pid_t> children;
  auto child_cleanup = Cleanup([&] {
    for (const pid_t child : children) {
      int status;
      EXPECT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
      EXPECT_TRUE(WIFEXITED(status));
      EXPECT_EQ(0, WEXITSTATUS(status));
    }
  });

  // Must come after children, as the FDs must be closed before the children
  // will exit.
  std::vector<FileDescriptor> read_fds;
  std::vector<FileDescriptor> write_fds;

  for (int i = 0; i < num_processes; i++) {
    int fds[2];
    ASSERT_THAT(pipe(fds), SyscallSucceeds());
    read_fds.emplace_back(fds[0]);
    write_fds.emplace_back(fds[1]);
  }

  // This process is one of the processes in the loop. It will be considered
  // index 0.
  for (int i = 1; i < num_processes; i++) {
    // Read from current pipe index, write to next.
    const int read_index = i;
    const int read_fd = read_fds[read_index].get();

    const int write_index = (i + 1) % num_processes;
    const int write_fd = write_fds[write_index].get();

    // std::vector isn't safe to use from the fork child.
    FileDescriptor* read_array = read_fds.data();
    FileDescriptor* write_array = write_fds.data();

    pid_t child = fork();
    if (!child) {
      // Close all other FDs.
      for (int j = 0; j < num_processes; j++) {
        if (j != read_index) {
          read_array[j].reset();
        }
        if (j != write_index) {
          write_array[j].reset();
        }
      }

      SwitchChild(read_fd, write_fd);
      _exit(0);
    }
    ASSERT_THAT(child, SyscallSucceeds());
    children.push_back(child);
  }

  // Read from current pipe index (0), write to next (1).
  const int read_index = 0;
  const int read_fd = read_fds[read_index].get();

  const int write_index = 1;
  const int write_fd = write_fds[write_index].get();

  // Kick start the loop.
  char buf = 'a';
  ASSERT_THAT(WriteFd(write_fd, &buf, 1), SyscallSucceedsWithValue(1));

  for (auto _ : state) {
    ASSERT_THAT(ReadFd(read_fd, &buf, 1), SyscallSucceedsWithValue(1));
    ASSERT_THAT(WriteFd(write_fd, &buf, 1), SyscallSucceedsWithValue(1));
  }
}

BENCHMARK(BM_ProcessSwitch)->Range(2, 16)->UseRealTime();

// Equivalent to BM_ThreadSwitch using threads instead of processes.
void BM_ThreadSwitch(benchmark::State& state) {
  // Code below assumes there are at least two threads.
  const int num_threads = state.range(0);
  ASSERT_GE(num_threads, 2);

  // Must come after threads, as the FDs must be closed before the children
  // will exit.
  std::vector<std::unique_ptr<ScopedThread>> threads;
  std::vector<FileDescriptor> read_fds;
  std::vector<FileDescriptor> write_fds;

  for (int i = 0; i < num_threads; i++) {
    int fds[2];
    ASSERT_THAT(pipe(fds), SyscallSucceeds());
    read_fds.emplace_back(fds[0]);
    write_fds.emplace_back(fds[1]);
  }

  // This thread is one of the threads in the loop. It will be considered
  // index 0.
  for (int i = 1; i < num_threads; i++) {
    // Read from current pipe index, write to next.
    //
    // Transfer ownership of the FDs to the thread.
    const int read_index = i;
    const int read_fd = read_fds[read_index].release();

    const int write_index = (i + 1) % num_threads;
    const int write_fd = write_fds[write_index].release();

    threads.emplace_back(std::make_unique<ScopedThread>([read_fd, write_fd] {
      FileDescriptor read(read_fd);
      FileDescriptor write(write_fd);
      SwitchChild(read.get(), write.get());
    }));
  }

  // Read from current pipe index (0), write to next (1).
  const int read_index = 0;
  const int read_fd = read_fds[read_index].get();

  const int write_index = 1;
  const int write_fd = write_fds[write_index].get();

  // Kick start the loop.
  char buf = 'a';
  ASSERT_THAT(WriteFd(write_fd, &buf, 1), SyscallSucceedsWithValue(1));

  for (auto _ : state) {
    ASSERT_THAT(ReadFd(read_fd, &buf, 1), SyscallSucceedsWithValue(1));
    ASSERT_THAT(WriteFd(write_fd, &buf, 1), SyscallSucceedsWithValue(1));
  }

  // The two FDs still owned by this thread are closed, causing the next thread
  // to exit its loop and close its FDs, and so on until all threads exit.
}

BENCHMARK(BM_ThreadSwitch)->Range(2, 16)->UseRealTime();

void BM_ThreadStart(benchmark::State& state) {
  const int num_threads = state.range(0);

  for (auto _ : state) {
    state.PauseTiming();

    auto barrier = new absl::Barrier(num_threads + 1);
    std::vector<std::unique_ptr<ScopedThread>> threads;

    state.ResumeTiming();

    for (int i = 0; i < num_threads; ++i) {
      threads.emplace_back(std::make_unique<ScopedThread>([barrier] {
        if (barrier->Block()) {
          delete barrier;
        }
      }));
    }

    if (barrier->Block()) {
      delete barrier;
    }

    state.PauseTiming();

    for (const auto& thread : threads) {
      thread->Join();
    }

    state.ResumeTiming();
  }
}

BENCHMARK(BM_ThreadStart)->Range(1, 2048)->UseRealTime();

// Benchmark the complete fork + exit + wait.
void BM_ProcessLifecycle(benchmark::State& state) {
  const int num_procs = state.range(0);

  std::vector<pid_t> pids(num_procs);
  for (auto _ : state) {
    for (int i = 0; i < num_procs; ++i) {
      int pid = fork();
      if (pid == 0) {
        _exit(0);
      }
      ASSERT_THAT(pid, SyscallSucceeds());
      pids[i] = pid;
    }

    for (const int pid : pids) {
      ASSERT_THAT(RetryEINTR(waitpid)(pid, nullptr, 0),
                  SyscallSucceedsWithValue(pid));
    }
  }
}

BENCHMARK(BM_ProcessLifecycle)->Range(1, 512)->UseRealTime();

}  // namespace

}  // namespace testing
}  // namespace gvisor
