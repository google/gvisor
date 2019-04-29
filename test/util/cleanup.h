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

#ifndef GVISOR_TEST_UTIL_CLEANUP_H_
#define GVISOR_TEST_UTIL_CLEANUP_H_

#include <functional>
#include <utility>

namespace gvisor {
namespace testing {

class Cleanup {
 public:
  Cleanup() : released_(true) {}
  explicit Cleanup(std::function<void()>&& callback) : cb_(callback) {}

  Cleanup(Cleanup&& other) {
    released_ = other.released_;
    cb_ = other.Release();
  }

  Cleanup& operator=(Cleanup&& other) {
    released_ = other.released_;
    cb_ = other.Release();
    return *this;
  }

  ~Cleanup() {
    if (!released_) {
      cb_();
    }
  }

  std::function<void()>&& Release() {
    released_ = true;
    return std::move(cb_);
  }

 private:
  Cleanup(Cleanup const& other) = delete;

  bool released_ = false;
  std::function<void(void)> cb_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_CLEANUP_H_
