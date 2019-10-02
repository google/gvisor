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

#ifndef GVISOR_TEST_UTIL_SAVE_UTIL_H_
#define GVISOR_TEST_UTIL_SAVE_UTIL_H_

namespace gvisor {
namespace testing {
// Disable save prevents saving while the given function executes.
//
// This lasts the duration of the object, unless reset is called.
class DisableSave {
 public:
  DisableSave();
  ~DisableSave();
  DisableSave(DisableSave const&) = delete;
  DisableSave(DisableSave&&) = delete;
  DisableSave& operator=(DisableSave const&) = delete;
  DisableSave& operator=(DisableSave&&) = delete;

  // reset allows saves to continue, and is called implicitly by the destructor.
  // It may be called multiple times safely, but is not thread-safe.
  void reset();

 private:
  bool reset_ = false;
};

// May perform a co-operative save cycle.
//
// errno is guaranteed to be preserved.
void MaybeSave();

namespace internal {
bool ShouldSave();
}  // namespace internal

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_SAVE_UTIL_H_
