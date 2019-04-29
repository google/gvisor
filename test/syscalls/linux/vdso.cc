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

#include <string.h>
#include <sys/mman.h>

#include <algorithm>

#include "gtest/gtest.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/proc_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Ensure that the vvar page cannot be made writable.
TEST(VvarTest, WriteVvar) {
  auto contents = ASSERT_NO_ERRNO_AND_VALUE(GetContents("/proc/self/maps"));
  auto maps = ASSERT_NO_ERRNO_AND_VALUE(ParseProcMaps(contents));
  auto it = std::find_if(maps.begin(), maps.end(), [](const ProcMapsEntry& e) {
    return e.filename == "[vvar]";
  });

  SKIP_IF(it == maps.end());
  EXPECT_THAT(mprotect(reinterpret_cast<void*>(it->start), kPageSize,
                       PROT_READ | PROT_WRITE),
              SyscallFailsWithErrno(EACCES));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
