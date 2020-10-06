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

#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

// This is the classic test case for memory fences on architectures with total
// store ordering; see e.g. Intel SDM Vol. 3A Sec. 8.2.3.4 "Loads May Be
// Reordered with Earlier Stores to Different Locations". In each iteration of
// the test, given two variables X and Y initially set to 0
// (MembarrierTestSharedState::local_var and remote_var in the code), two
// threads execute as follows:
//
// T1                                   T2
// --                                   --
//
// X = 1                                Y = 1
// T1fence()                            T2fence()
// read Y                               read X
//
// On architectures where memory writes may be locally buffered by each CPU
// (essentially all architectures), if T1fence() and T2fence() are omitted or
// ineffective, it is possible for both T1 and T2 to read 0 because the memory
// write from the other CPU is not yet visible outside that CPU. T1fence() and
// T2fence() are expected to perform the necessary synchronization to restore
// sequential consistency: both threads agree on a order of memory accesses that
// is consistent with program order in each thread, such that at least one
// thread reads 1.
//
// In the NoMembarrier test, T1fence() and T2fence() are both ordinary memory
// fences establishing ordering between memory accesses before and after the
// fence (std::atomic_thread_fence). In all other test cases, T1fence() is not a
// memory fence at all, but only prevents compiler reordering of memory accesses
// (std::atomic_signal_fence); T2fence() is an invocation of the membarrier()
// syscall, which establishes ordering of memory accesses before and after the
// syscall on both threads.

template <typename F>
int DoMembarrierTestSide(std::atomic<int>* our_var,
                         std::atomic<int> const& their_var,
                         F const& test_fence) {
  our_var->store(1, std::memory_order_relaxed);
  test_fence();
  return their_var.load(std::memory_order_relaxed);
}

struct MembarrierTestSharedState {
  std::atomic<int64_t> remote_iter_cur;
  std::atomic<int64_t> remote_iter_done;
  std::atomic<int> local_var;
  std::atomic<int> remote_var;
  int remote_obs_of_local_var;

  void Init() {
    remote_iter_cur.store(-1, std::memory_order_relaxed);
    remote_iter_done.store(-1, std::memory_order_relaxed);
  }
};

// Special value for MembarrierTestSharedState::remote_iter_cur indicating that
// the remote thread should terminate.
constexpr int64_t kRemoteIterStop = -2;

// Must be async-signal-safe.
template <typename F>
void RunMembarrierTestRemoteSide(MembarrierTestSharedState* state,
                                 F const& test_fence) {
  int64_t i = 0;
  int64_t cur;
  while (true) {
    while ((cur = state->remote_iter_cur.load(std::memory_order_acquire)) < i) {
      if (cur == kRemoteIterStop) {
        return;
      }
      // spin
    }
    state->remote_obs_of_local_var =
        DoMembarrierTestSide(&state->remote_var, state->local_var, test_fence);
    state->remote_iter_done.store(i, std::memory_order_release);
    i++;
  }
}

template <typename F>
void RunMembarrierTestLocalSide(MembarrierTestSharedState* state,
                                F const& test_fence) {
  // On test completion, instruct the remote thread to terminate.
  Cleanup cleanup_remote([&] {
    state->remote_iter_cur.store(kRemoteIterStop, std::memory_order_relaxed);
  });

  int64_t i = 0;
  absl::Time end = absl::Now() + absl::Seconds(5);  // arbitrary test duration
  while (absl::Now() < end) {
    // Reset both vars to 0.
    state->local_var.store(0, std::memory_order_relaxed);
    state->remote_var.store(0, std::memory_order_relaxed);
    // Instruct the remote thread to begin this iteration.
    state->remote_iter_cur.store(i, std::memory_order_release);
    // Perform our side of the test.
    auto local_obs_of_remote_var =
        DoMembarrierTestSide(&state->local_var, state->remote_var, test_fence);
    // Wait for the remote thread to finish this iteration.
    while (state->remote_iter_done.load(std::memory_order_acquire) < i) {
      // spin
    }
    ASSERT_TRUE(local_obs_of_remote_var != 0 ||
                state->remote_obs_of_local_var != 0);
    i++;
  }
}

TEST(MembarrierTest, NoMembarrier) {
  MembarrierTestSharedState state;
  state.Init();

  ScopedThread remote_thread([&] {
    RunMembarrierTestRemoteSide(
        &state, [] { std::atomic_thread_fence(std::memory_order_seq_cst); });
  });
  RunMembarrierTestLocalSide(
      &state, [] { std::atomic_thread_fence(std::memory_order_seq_cst); });
}

enum membarrier_cmd {
  MEMBARRIER_CMD_QUERY = 0,
  MEMBARRIER_CMD_GLOBAL = (1 << 0),
  MEMBARRIER_CMD_GLOBAL_EXPEDITED = (1 << 1),
  MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED = (1 << 2),
  MEMBARRIER_CMD_PRIVATE_EXPEDITED = (1 << 3),
  MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED = (1 << 4),
};

int membarrier(membarrier_cmd cmd, int flags) {
  return syscall(SYS_membarrier, cmd, flags);
}

PosixErrorOr<int> SupportedMembarrierCommands() {
  int cmds = membarrier(MEMBARRIER_CMD_QUERY, 0);
  if (cmds < 0) {
    if (errno == ENOSYS) {
      // No commands are supported.
      return 0;
    }
    return PosixError(errno, "membarrier(MEMBARRIER_CMD_QUERY) failed");
  }
  return cmds;
}

TEST(MembarrierTest, Global) {
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           MEMBARRIER_CMD_GLOBAL) == 0);

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto state = static_cast<MembarrierTestSharedState*>(m.ptr());
  state->Init();

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    RunMembarrierTestRemoteSide(
        state, [] { TEST_PCHECK(membarrier(MEMBARRIER_CMD_GLOBAL, 0) == 0); });
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());
  Cleanup cleanup_child([&] {
    int status;
    ASSERT_THAT(waitpid(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
        << " status " << status;
  });
  RunMembarrierTestLocalSide(
      state, [] { std::atomic_signal_fence(std::memory_order_seq_cst); });
}

TEST(MembarrierTest, GlobalExpedited) {
  constexpr int kRequiredCommands = MEMBARRIER_CMD_GLOBAL_EXPEDITED |
                                    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED;
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           kRequiredCommands) != kRequiredCommands);

  ASSERT_THAT(membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0),
              SyscallSucceeds());

  Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_SHARED));
  auto state = static_cast<MembarrierTestSharedState*>(m.ptr());
  state->Init();

  pid_t const child_pid = fork();
  if (child_pid == 0) {
    // In child process.
    RunMembarrierTestRemoteSide(state, [] {
      TEST_PCHECK(membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0) == 0);
    });
    _exit(0);
  }
  // In parent process.
  ASSERT_THAT(child_pid, SyscallSucceeds());
  Cleanup cleanup_child([&] {
    int status;
    ASSERT_THAT(waitpid(child_pid, &status, 0),
                SyscallSucceedsWithValue(child_pid));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0)
        << " status " << status;
  });
  RunMembarrierTestLocalSide(
      state, [] { std::atomic_signal_fence(std::memory_order_seq_cst); });
}

TEST(MembarrierTest, PrivateExpedited) {
  constexpr int kRequiredCommands = MEMBARRIER_CMD_PRIVATE_EXPEDITED |
                                    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
  SKIP_IF((ASSERT_NO_ERRNO_AND_VALUE(SupportedMembarrierCommands()) &
           kRequiredCommands) != kRequiredCommands);

  ASSERT_THAT(membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0),
              SyscallSucceeds());

  MembarrierTestSharedState state;
  state.Init();

  ScopedThread remote_thread([&] {
    RunMembarrierTestRemoteSide(&state, [] {
      TEST_PCHECK(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0) == 0);
    });
  });
  RunMembarrierTestLocalSide(
      &state, [] { std::atomic_signal_fence(std::memory_order_seq_cst); });
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
