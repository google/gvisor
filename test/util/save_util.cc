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

#include "test/util/save_util.h"

#include <stddef.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <atomic>
#include <cerrno>

#define GVISOR_COOPERATIVE_SAVE_TEST "GVISOR_COOPERATIVE_SAVE_TEST"

namespace gvisor {
namespace testing {
namespace {

enum class CooperativeSaveMode {
  kUnknown = 0,  // cooperative_save_mode is statically-initialized to 0
  kAvailable,
  kNotAvailable,
};

std::atomic<CooperativeSaveMode> cooperative_save_mode;

bool CooperativeSaveEnabled() {
  auto mode = cooperative_save_mode.load();
  if (mode == CooperativeSaveMode::kUnknown) {
    mode = (getenv(GVISOR_COOPERATIVE_SAVE_TEST) != nullptr)
               ? CooperativeSaveMode::kAvailable
               : CooperativeSaveMode::kNotAvailable;
    cooperative_save_mode.store(mode);
  }
  return mode == CooperativeSaveMode::kAvailable;
}

std::atomic<int> save_disable;

}  // namespace

DisableSave::DisableSave() { save_disable++; }

DisableSave::~DisableSave() { reset(); }

void DisableSave::reset() {
  if (!reset_) {
    reset_ = true;
    save_disable--;
  }
}

void MaybeSave() {
  if (CooperativeSaveEnabled() && !save_disable.load()) {
    int orig_errno = errno;
    syscall(SYS_create_module, nullptr, 0);
    errno = orig_errno;
  }
}

}  // namespace testing
}  // namespace gvisor
