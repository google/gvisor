// Copyright 2026 The gVisor Authors.
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

#include <stddef.h>

namespace {

constexpr size_t kFrameSize = 4096;

// Recursing to this depth uses more than 32 MiB of stack.
constexpr int kDepth = (32 << 20) / kFrameSize;

__attribute__((noinline)) int Recurse(int depth) {
  volatile char buf[kFrameSize];
  for (size_t i = 0; i < kFrameSize; i += 64) {
    buf[i] = static_cast<char>(depth);
  }
  if (depth == 0) {
    return 0;
  }
  return Recurse(depth - 1) + buf[0] - static_cast<char>(depth);
}

}  // namespace

int main() { return Recurse(kDepth); }
