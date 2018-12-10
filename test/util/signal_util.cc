// Copyright 2018 Google LLC
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

#include "test/util/signal_util.h"

#include <signal.h>
#include <ostream>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace {

struct Range {
  int start;
  int end;
};

// Format a Range as "start-end" or "start" for single value Ranges.
static ::std::ostream& operator<<(::std::ostream& os, const Range& range) {
  if (range.end > range.start) {
    return os << range.start << '-' << range.end;
  }

  return os << range.start;
}

}  // namespace

// Format a sigset_t as a comma separated list of numeric ranges.
// Empty sigset: []
// Full  sigset: [1-31,34-64]
::std::ostream& operator<<(::std::ostream& os, const sigset_t& sigset) {
  const char* delim = "";
  Range range = {0, 0};

  os << '[';

  for (int sig = 1; sig <= gvisor::testing::kMaxSignal; ++sig) {
    if (sigismember(&sigset, sig)) {
      if (range.start) {
        range.end = sig;
      } else {
        range.start = sig;
        range.end = sig;
      }
    } else if (range.start) {
      os << delim << range;
      delim = ",";
      range.start = 0;
      range.end = 0;
    }
  }

  if (range.start) {
    os << delim << range;
  }

  return os << ']';
}

namespace gvisor {
namespace testing {

PosixErrorOr<Cleanup> ScopedSigaction(int sig, struct sigaction const& sa) {
  struct sigaction old_sa;
  int rc = sigaction(sig, &sa, &old_sa);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "sigaction failed");
  }
  return Cleanup([sig, old_sa] {
    EXPECT_THAT(sigaction(sig, &old_sa, nullptr), SyscallSucceeds());
  });
}

PosixErrorOr<Cleanup> ScopedSignalMask(int how, sigset_t const& set) {
  sigset_t old;
  int rc = sigprocmask(how, &set, &old);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "sigprocmask failed");
  }
  return Cleanup([old] {
    EXPECT_THAT(sigprocmask(SIG_SETMASK, &old, nullptr), SyscallSucceeds());
  });
}

}  // namespace testing
}  // namespace gvisor
