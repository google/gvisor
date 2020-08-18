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

#ifndef GVISOR_TEST_UTIL_TEMP_UMASK_H_
#define GVISOR_TEST_UTIL_TEMP_UMASK_H_

#include <sys/stat.h>
#include <sys/types.h>

namespace gvisor {
namespace testing {

class TempUmask {
 public:
  // Sets the process umask to `mask`.
  explicit TempUmask(mode_t mask) : old_mask_(umask(mask)) {}

  // Sets the process umask to its previous value.
  ~TempUmask() { umask(old_mask_); }

 private:
  mode_t old_mask_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_TEMP_UMASK_H_
