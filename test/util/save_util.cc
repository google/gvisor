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

#include "test/util/save_util.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>

#include "absl/types/optional.h"

namespace gvisor {
namespace testing {
namespace {

std::atomic<absl::optional<bool>> save_present;

bool SavePresent() {
  auto present = save_present.load();
  if (!present.has_value()) {
    present = getenv("GVISOR_SAVE_TEST") != nullptr;
    save_present.store(present);
  }
  return present.value();
}

std::atomic<int> save_disable;

}  // namespace

bool IsRunningWithSaveRestore() { return SavePresent(); }

void MaybeSave() {
  if (SavePresent() && save_disable.load() == 0) {
    internal::DoCooperativeSave();
  }
}

DisableSave::DisableSave() { save_disable++; }

DisableSave::~DisableSave() { reset(); }

void DisableSave::reset() {
  if (!reset_) {
    reset_ = true;
    save_disable--;
  }
}

}  // namespace testing
}  // namespace gvisor
