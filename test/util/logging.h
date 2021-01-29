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

#ifndef GVISOR_TEST_UTIL_LOGGING_H_
#define GVISOR_TEST_UTIL_LOGGING_H_

#include <stddef.h>

namespace gvisor {
namespace testing {

void CheckFailure(const char* cond, size_t cond_size, const char* msg,
                  size_t msg_size, int errno_value);

// If cond is false, aborts the current process.
//
// This macro is async-signal-safe.
#define TEST_CHECK(cond)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ::gvisor::testing::CheckFailure(#cond, sizeof(#cond) - 1, nullptr, \
                                            0, 0);                             \
    }                                                                          \
  } while (0)

// If cond is false, logs msg then aborts the current process.
//
// This macro is async-signal-safe.
#define TEST_CHECK_MSG(cond, msg)                                          \
  do {                                                                     \
    if (!(cond)) {                                                         \
      ::gvisor::testing::CheckFailure(#cond, sizeof(#cond) - 1, msg, \
                                            sizeof(msg) - 1, 0);           \
    }                                                                      \
  } while (0)

// If cond is false, logs errno, then aborts the current process.
//
// This macro is async-signal-safe.
#define TEST_PCHECK(cond)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      ::gvisor::testing::CheckFailure(#cond, sizeof(#cond) - 1, nullptr, \
                                            0, errno);                         \
    }                                                                          \
  } while (0)

// If cond is false, logs msg and errno, then aborts the current process.
//
// This macro is async-signal-safe.
#define TEST_PCHECK_MSG(cond, msg)                                         \
  do {                                                                     \
    if (!(cond)) {                                                         \
      ::gvisor::testing::CheckFailure(#cond, sizeof(#cond) - 1, msg, \
                                            sizeof(msg) - 1, errno);       \
    }                                                                      \
  } while (0)

// expr must return PosixErrorOr<T>. The current process is aborted if
// !PosixError<T>.ok().
//
// This macro is async-signal-safe.
#define TEST_CHECK_NO_ERRNO(expr)               \
  ({                                            \
    auto _expr_result = (expr);                 \
    if (!_expr_result.ok()) {                   \
      ::gvisor::testing::CheckFailure(    \
          #expr, sizeof(#expr) - 1, nullptr, 0, \
          _expr_result.error().errno_value());  \
    }                                           \
  })

// expr must return PosixErrorOr<T>. The current process is aborted if
// !PosixError<T>.ok(). Otherwise, PosixErrorOr<T> value is returned.
//
// This macro is async-signal-safe.
#define TEST_CHECK_NO_ERRNO_AND_VALUE(expr)     \
  ({                                            \
    auto _expr_result = (expr);                 \
    if (!_expr_result.ok()) {                   \
      ::gvisor::testing::CheckFailure(    \
          #expr, sizeof(#expr) - 1, nullptr, 0, \
          _expr_result.error().errno_value());  \
    }                                           \
    std::move(_expr_result).ValueOrDie();       \
  })

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_LOGGING_H_
