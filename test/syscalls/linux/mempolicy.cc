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

#include <errno.h>
#include <sys/syscall.h>

#include <memory>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/util/cleanup.h"
#include "test/util/memory_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#define BITS_PER_BYTE 8

#define MPOL_F_STATIC_NODES (1 << 15)
#define MPOL_F_RELATIVE_NODES (1 << 14)
#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2
#define MPOL_INTERLEAVE 3
#define MPOL_LOCAL 4
#define MPOL_F_NODE (1 << 0)
#define MPOL_F_ADDR (1 << 1)
#define MPOL_F_MEMS_ALLOWED (1 << 2)
#define MPOL_MF_STRICT (1 << 0)
#define MPOL_MF_MOVE (1 << 1)
#define MPOL_MF_MOVE_ALL (1 << 2)

int get_mempolicy(int* policy, uint64_t* nmask, uint64_t maxnode, void* addr,
                  int flags) {
  return syscall(SYS_get_mempolicy, policy, nmask, maxnode, addr, flags);
}

int set_mempolicy(int mode, uint64_t* nmask, uint64_t maxnode) {
  return syscall(SYS_set_mempolicy, mode, nmask, maxnode);
}

int mbind(void* addr, unsigned long len, int mode,
          const unsigned long* nodemask, unsigned long maxnode,
          unsigned flags) {
  return syscall(SYS_mbind, addr, len, mode, nodemask, maxnode, flags);
}

// Creates a cleanup object that resets the calling thread's mempolicy to the
// system default when the calling scope ends.
Cleanup ScopedMempolicy() {
  return Cleanup([] {
    EXPECT_THAT(set_mempolicy(MPOL_DEFAULT, nullptr, 0), SyscallSucceeds());
  });
}

// Temporarily change the memory policy for the calling thread within the
// caller's scope.
PosixErrorOr<Cleanup> ScopedSetMempolicy(int mode, uint64_t* nmask,
                                         uint64_t maxnode) {
  if (set_mempolicy(mode, nmask, maxnode)) {
    return PosixError(errno, "set_mempolicy");
  }
  return ScopedMempolicy();
}

TEST(MempolicyTest, CheckDefaultPolicy) {
  int mode = 0;
  uint64_t nodemask = 0;
  ASSERT_THAT(get_mempolicy(&mode, &nodemask, sizeof(nodemask) * BITS_PER_BYTE,
                            nullptr, 0),
              SyscallSucceeds());

  EXPECT_EQ(MPOL_DEFAULT, mode);
  EXPECT_EQ(0x0, nodemask);
}

TEST(MempolicyTest, PolicyPreservedAfterSetMempolicy) {
  uint64_t nodemask = 0x1;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSetMempolicy(
      MPOL_BIND, &nodemask, sizeof(nodemask) * BITS_PER_BYTE));

  int mode = 0;
  uint64_t nodemask_after = 0x0;
  ASSERT_THAT(get_mempolicy(&mode, &nodemask_after,
                            sizeof(nodemask_after) * BITS_PER_BYTE, nullptr, 0),
              SyscallSucceeds());
  EXPECT_EQ(MPOL_BIND, mode);
  EXPECT_EQ(0x1, nodemask_after);

  // Try throw in some mode flags.
  for (auto mode_flag : {MPOL_F_STATIC_NODES, MPOL_F_RELATIVE_NODES}) {
    auto cleanup2 = ASSERT_NO_ERRNO_AND_VALUE(
        ScopedSetMempolicy(MPOL_INTERLEAVE | mode_flag, &nodemask,
                           sizeof(nodemask) * BITS_PER_BYTE));
    mode = 0;
    nodemask_after = 0x0;
    ASSERT_THAT(
        get_mempolicy(&mode, &nodemask_after,
                      sizeof(nodemask_after) * BITS_PER_BYTE, nullptr, 0),
        SyscallSucceeds());
    EXPECT_EQ(MPOL_INTERLEAVE | mode_flag, mode);
    EXPECT_EQ(0x1, nodemask_after);
  }
}

TEST(MempolicyTest, SetMempolicyRejectsInvalidInputs) {
  auto cleanup = ScopedMempolicy();
  uint64_t nodemask;

  if (IsRunningOnGvisor()) {
    // Invalid nodemask, we only support a single node on gvisor.
    nodemask = 0x4;
    ASSERT_THAT(set_mempolicy(MPOL_DEFAULT, &nodemask,
                              sizeof(nodemask) * BITS_PER_BYTE),
                SyscallFailsWithErrno(EINVAL));
  }

  nodemask = 0x1;

  // Invalid mode.
  ASSERT_THAT(set_mempolicy(7439, &nodemask, sizeof(nodemask) * BITS_PER_BYTE),
              SyscallFailsWithErrno(EINVAL));

  // Invalid nodemask size.
  ASSERT_THAT(set_mempolicy(MPOL_DEFAULT, &nodemask, 0),
              SyscallFailsWithErrno(EINVAL));

  // Invalid mode flag.
  ASSERT_THAT(
      set_mempolicy(MPOL_DEFAULT | MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES,
                    &nodemask, sizeof(nodemask) * BITS_PER_BYTE),
      SyscallFailsWithErrno(EINVAL));

  // MPOL_INTERLEAVE with empty nodemask.
  nodemask = 0x0;
  ASSERT_THAT(set_mempolicy(MPOL_INTERLEAVE, &nodemask,
                            sizeof(nodemask) * BITS_PER_BYTE),
              SyscallFailsWithErrno(EINVAL));
}

// The manpages specify that the nodemask provided to set_mempolicy are
// considered empty if the nodemask pointer is null, or if the nodemask size is
// 0. We use a policy which accepts both empty and non-empty nodemasks
// (MPOL_PREFERRED), a policy which requires a non-empty nodemask (MPOL_BIND),
// and a policy which completely ignores the nodemask (MPOL_DEFAULT) to verify
// argument checking around nodemasks.
TEST(MempolicyTest, EmptyNodemaskOnSet) {
  auto cleanup = ScopedMempolicy();

  EXPECT_THAT(set_mempolicy(MPOL_DEFAULT, nullptr, 1), SyscallSucceeds());
  EXPECT_THAT(set_mempolicy(MPOL_BIND, nullptr, 1),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(set_mempolicy(MPOL_PREFERRED, nullptr, 1), SyscallSucceeds());

  uint64_t nodemask = 0x1;
  EXPECT_THAT(set_mempolicy(MPOL_DEFAULT, &nodemask, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(set_mempolicy(MPOL_BIND, &nodemask, 0),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(set_mempolicy(MPOL_PREFERRED, &nodemask, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(MempolicyTest, QueryAvailableNodes) {
  uint64_t nodemask = 0;
  ASSERT_THAT(
      get_mempolicy(nullptr, &nodemask, sizeof(nodemask) * BITS_PER_BYTE,
                    nullptr, MPOL_F_MEMS_ALLOWED),
      SyscallSucceeds());
  // We can only be sure there is a single node if running on gvisor.
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(0x1, nodemask);
  }

  // MPOL_F_ADDR and MPOL_F_NODE flags may not be combined with
  // MPOL_F_MEMS_ALLLOWED.
  for (auto flags :
       {MPOL_F_MEMS_ALLOWED | MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED | MPOL_F_NODE,
        MPOL_F_MEMS_ALLOWED | MPOL_F_ADDR | MPOL_F_NODE}) {
    ASSERT_THAT(get_mempolicy(nullptr, &nodemask,
                              sizeof(nodemask) * BITS_PER_BYTE, nullptr, flags),
                SyscallFailsWithErrno(EINVAL));
  }
}

TEST(MempolicyTest, GetMempolicyQueryNodeForAddress) {
  uint64_t dummy_stack_address;
  auto dummy_heap_address = std::make_unique<uint64_t>();
  int mode;

  for (auto ptr : {&dummy_stack_address, dummy_heap_address.get()}) {
    mode = -1;
    ASSERT_THAT(
        get_mempolicy(&mode, nullptr, 0, ptr, MPOL_F_ADDR | MPOL_F_NODE),
        SyscallSucceeds());
    // If we're not running on gvisor, the address may be allocated on a
    // different numa node.
    if (IsRunningOnGvisor()) {
      EXPECT_EQ(0, mode);
    }
  }

  void* invalid_address = reinterpret_cast<void*>(-1);

  // Invalid address.
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, invalid_address,
                            MPOL_F_ADDR | MPOL_F_NODE),
              SyscallFailsWithErrno(EFAULT));

  // Invalid mode pointer.
  ASSERT_THAT(get_mempolicy(reinterpret_cast<int*>(invalid_address), nullptr, 0,
                            &dummy_stack_address, MPOL_F_ADDR | MPOL_F_NODE),
              SyscallFailsWithErrno(EFAULT));
}

TEST(MempolicyTest, GetMempolicyCanOmitPointers) {
  int mode;
  uint64_t nodemask;

  // Omit nodemask pointer.
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, nullptr, 0), SyscallSucceeds());
  // Omit mode pointer.
  ASSERT_THAT(get_mempolicy(nullptr, &nodemask,
                            sizeof(nodemask) * BITS_PER_BYTE, nullptr, 0),
              SyscallSucceeds());
  // Omit both pointers.
  ASSERT_THAT(get_mempolicy(nullptr, nullptr, 0, nullptr, 0),
              SyscallSucceeds());
}

TEST(MempolicyTest, GetMempolicyNextInterleaveNode) {
  int mode;
  // Policy for thread not yet set to MPOL_INTERLEAVE, can't query for
  // the next node which will be used for allocation.
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, nullptr, MPOL_F_NODE),
              SyscallFailsWithErrno(EINVAL));

  // Set default policy for thread to MPOL_INTERLEAVE.
  uint64_t nodemask = 0x1;
  auto cleanup = ASSERT_NO_ERRNO_AND_VALUE(ScopedSetMempolicy(
      MPOL_INTERLEAVE, &nodemask, sizeof(nodemask) * BITS_PER_BYTE));

  mode = -1;
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, nullptr, MPOL_F_NODE),
              SyscallSucceeds());
  EXPECT_EQ(0, mode);
}

TEST(MempolicyTest, Mbind) {
  uint64_t nodemask = 0x1;
  // Temporarily set the thread policy to MPOL_PREFERRED.
  const auto cleanup_thread_policy =
      ASSERT_NO_ERRNO_AND_VALUE(ScopedSetMempolicy(
          MPOL_PREFERRED, &nodemask, sizeof(nodemask) * BITS_PER_BYTE));

  const auto mapping = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS));

  // vmas default to MPOL_DEFAULT irrespective of the thread policy (currently
  // MPOL_PREFERRED).
  int mode;
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, mapping.ptr(), MPOL_F_ADDR),
              SyscallSucceeds());
  EXPECT_EQ(mode, MPOL_DEFAULT);

  // Set MPOL_PREFERRED for the vma and read it back. Note that setting
  // MPOL_PREFERRED with an empty node set will set mode to MPOL_LOCAL on newer
  // Linux releases.
  ASSERT_THAT(mbind(mapping.ptr(), mapping.len(), MPOL_PREFERRED, &nodemask,
                    sizeof(nodemask) * BITS_PER_BYTE, 0),
              SyscallSucceeds());
  ASSERT_THAT(get_mempolicy(&mode, nullptr, 0, mapping.ptr(), MPOL_F_ADDR),
              SyscallSucceeds());
  EXPECT_EQ(mode, MPOL_PREFERRED);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
