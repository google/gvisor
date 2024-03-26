// Copyright 2024 The gVisor Authors.
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

// new and delete that preserves errno in case of success.

#include <errno.h>
#include <stdlib.h>

namespace {
void* errno_safe_malloc(size_t size) {
  int original_errno = errno;
  void* result = malloc(size);
  if (result != nullptr) {
    errno = original_errno;
  }
  return result;
}

void errno_safe_free(void* p) {
  int original_errno = errno;
  free(p);
  errno = original_errno;
}
}  // namespace

void* operator new(size_t size) { return errno_safe_malloc(size); }
void* operator new[](size_t size) { return errno_safe_malloc(size); }
void operator delete(void* p) { errno_safe_free(p); }
void operator delete[](void* p) { errno_safe_free(p); }
