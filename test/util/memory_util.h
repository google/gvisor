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

#ifndef GVISOR_TEST_UTIL_MEMORY_UTIL_H_
#define GVISOR_TEST_UTIL_MEMORY_UTIL_H_

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// RAII type for mmap'ed memory. Only usable in tests due to use of a test-only
// macro that can't be named without invoking the presubmit's wrath.
class Mapping {
 public:
  // Constructs a mapping that owns nothing.
  Mapping() = default;

  // Constructs a mapping that owns the mmapped memory [ptr, ptr+len). Most
  // users should use Mmap or MmapAnon instead.
  Mapping(void* ptr, size_t len) : ptr_(ptr), len_(len) {}

  Mapping(Mapping&& orig) : ptr_(orig.ptr_), len_(orig.len_) { orig.release(); }

  Mapping& operator=(Mapping&& orig) {
    ptr_ = orig.ptr_;
    len_ = orig.len_;
    orig.release();
    return *this;
  }

  Mapping(Mapping const&) = delete;
  Mapping& operator=(Mapping const&) = delete;

  ~Mapping() { reset(); }

  void* ptr() const { return ptr_; }
  size_t len() const { return len_; }

  // Returns a pointer to the end of the mapping. Useful for when the mapping
  // is used as a thread stack.
  void* endptr() const { return reinterpret_cast<void*>(addr() + len_); }

  // Returns the start of this mapping cast to uintptr_t for ease of pointer
  // arithmetic.
  uintptr_t addr() const { return reinterpret_cast<uintptr_t>(ptr_); }

  // Returns the end of this mapping cast to uintptr_t for ease of pointer
  // arithmetic.
  uintptr_t endaddr() const { return reinterpret_cast<uintptr_t>(endptr()); }

  // Returns this mapping as a StringPiece for ease of comparison.
  //
  // This function is named view in anticipation of the eventual replacement of
  // StringPiece with std::string_view.
  absl::string_view view() const {
    return absl::string_view(static_cast<char const*>(ptr_), len_);
  }

  // These are both named reset for consistency with standard smart pointers.

  void reset(void* ptr, size_t len) {
    if (len_) {
      TEST_PCHECK(munmap(ptr_, len_) == 0);
    }
    ptr_ = ptr;
    len_ = len;
  }

  void reset() { reset(nullptr, 0); }

  void release() {
    ptr_ = nullptr;
    len_ = 0;
  }

 private:
  void* ptr_ = nullptr;
  size_t len_ = 0;
};

// Wrapper around mmap(2) that returns a Mapping.
inline PosixErrorOr<Mapping> Mmap(void* addr, size_t length, int prot,
                                  int flags, int fd, off_t offset) {
  void* ptr = mmap(addr, length, prot, flags, fd, offset);
  if (ptr == MAP_FAILED) {
    return PosixError(
        errno, absl::StrFormat("mmap(%p, %d, %x, %x, %d, %d)", addr, length,
                               prot, flags, fd, offset));
  }
  MaybeSave();
  return Mapping(ptr, length);
}

// Convenience wrapper around Mmap for anonymous mappings.
inline PosixErrorOr<Mapping> MmapAnon(size_t length, int prot, int flags) {
  return Mmap(nullptr, length, prot, flags | MAP_ANONYMOUS, -1, 0);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_MEMORY_UTIL_H_
