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

#include <errno.h>

#include <cstddef>
#include <initializer_list>
#include <limits>
#include <new>

#include "gtest/gtest.h"
#include "test/util/cleanup.h"

namespace gvisor {
namespace testing {
namespace {

constexpr struct {
  const char* name;
  void* (*allocate)(size_t);
  void (*deallocate)(void*) noexcept;
} kAllocators[] = {
    {"scalar", ::operator new, ::operator delete},
    {"array", ::operator new[], ::operator delete[]},
};

TEST(ErrnoSafeAllocatorTest, PreservesErrno) {
  for (const auto& allocator : kAllocators) {
    SCOPED_TRACE(allocator.name);
    for (const size_t size : {0, 1}) {
      SCOPED_TRACE(size);
      errno = EBUSY;
      void* ptr = allocator.allocate(size);
      const int allocation_errno = errno;
      ASSERT_NE(ptr, nullptr);
      errno = ENOTTY;
      allocator.deallocate(ptr);
      const int deallocation_errno = errno;
      EXPECT_EQ(allocation_errno, EBUSY);
      EXPECT_EQ(deallocation_errno, ENOTTY);
    }
  }
}

TEST(ErrnoSafeAllocatorTest, ThrowsOnFailure) {
  const auto previous = std::set_new_handler(nullptr);
  const Cleanup restore_handler([previous] { std::set_new_handler(previous); });
  volatile size_t size = std::numeric_limits<size_t>::max();
  for (const auto& allocator : kAllocators) {
    SCOPED_TRACE(allocator.name);
    EXPECT_THROW(allocator.allocate(size), std::bad_alloc);
  }
}

TEST(ErrnoSafeAllocatorTest, RetriesAfterNewHandlerReturns) {
  const auto previous = std::set_new_handler(nullptr);
  const Cleanup restore_handler([previous] { std::set_new_handler(previous); });
  volatile size_t size = std::numeric_limits<size_t>::max();
  for (const auto& allocator : kAllocators) {
    SCOPED_TRACE(allocator.name);
    static int calls;
    calls = 0;
    std::set_new_handler([] {
      if (++calls == 2) {
        std::set_new_handler(nullptr);
      }
    });
    EXPECT_THROW(allocator.allocate(size), std::bad_alloc);
    EXPECT_EQ(calls, 2);
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
