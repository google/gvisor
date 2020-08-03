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

#ifndef GVISOR_TEST_UTIL_FUSE_UTIL_H_
#define GVISOR_TEST_UTIL_FUSE_UTIL_H_

#include <linux/fuse.h>
#include <sys/stat.h>

namespace gvisor {
namespace testing {

  // Return a fuse_entry_out FUSE server response body.
  fuse_entry_out DefaultEntryOut(mode_t mode, uint64_t nodeId);

}  // namespace testing
}  // namespace gvisor
#endif  // GVISOR_TEST_UTIL_FUSE_UTIL_H_
