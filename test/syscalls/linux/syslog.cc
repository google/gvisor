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

#include <sys/klog.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr int SYSLOG_ACTION_READ_ALL = 3;
constexpr int SYSLOG_ACTION_SIZE_BUFFER = 10;

int Syslog(int type, char* buf, int len) {
  return syscall(__NR_syslog, type, buf, len);
}

// Only SYSLOG_ACTION_SIZE_BUFFER and SYSLOG_ACTION_READ_ALL are implemented in
// gVisor.

TEST(Syslog, Size) {
  EXPECT_THAT(Syslog(SYSLOG_ACTION_SIZE_BUFFER, nullptr, 0), SyscallSucceeds());
}

TEST(Syslog, ReadAll) {
  // There might not be anything to read, so we can't check the write count.
  char buf[100];
  EXPECT_THAT(Syslog(SYSLOG_ACTION_READ_ALL, buf, sizeof(buf)),
              SyscallSucceeds());
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
