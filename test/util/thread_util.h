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

#ifndef GVISOR_TEST_UTIL_THREAD_UTIL_H_
#define GVISOR_TEST_UTIL_THREAD_UTIL_H_

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <functional>
#include <utility>

#include "test/util/logging.h"

namespace gvisor {
namespace testing {

// ScopedThread is a minimal wrapper around pthreads.
//
// This is used in lieu of more complex mechanisms because it provides very
// predictable behavior (no messing with timers, etc.) The thread will
// automatically joined when it is destructed (goes out of scope), but can be
// joined manually as well.
class ScopedThread {
 public:
  // Constructs a thread that executes f exactly once.
  explicit ScopedThread(std::function<void*()> f) : f_(std::move(f)) {
    CreateThread();
  }

  explicit ScopedThread(const std::function<void()>& f) {
    f_ = [=] {
      f();
      return nullptr;
    };
    CreateThread();
  }

  ScopedThread(const ScopedThread& other) = delete;
  ScopedThread& operator=(const ScopedThread& other) = delete;

  // Joins the thread.
  ~ScopedThread() { Join(); }

  // Waits until this thread has finished executing. Join is idempotent and may
  // be called multiple times, however Join itself is not thread-safe.
  void* Join() {
    if (!joined_) {
      TEST_PCHECK(pthread_join(pt_, &retval_) == 0);
      joined_ = true;
    }
    return retval_;
  }

 private:
  void CreateThread() {
    TEST_PCHECK_MSG(
        pthread_create(&pt_, /* attr = */ nullptr,
                       +[](void* arg) -> void* {
                         return static_cast<ScopedThread*>(arg)->f_();
                       },
                       this) == 0,
        "thread creation failed");
  }

  std::function<void*()> f_;
  pthread_t pt_;
  bool joined_ = false;
  void* retval_ = nullptr;
};

inline pid_t gettid() { return syscall(SYS_gettid); }

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_THREAD_UTIL_H_
