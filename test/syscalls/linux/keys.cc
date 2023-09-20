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

#include <asm-generic/errno.h>
#include <linux/keyctl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <cerrno>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "test/util/posix_error.h"
#include "test/util/thread_util.h"

#define KEY_POS_VIEW 0x01000000
#define KEY_POS_READ 0x02000000
#define KEY_POS_WRITE 0x04000000
#define KEY_POS_SEARCH 0x08000000
#define KEY_POS_LINK 0x10000000
#define KEY_POS_SETATTR 0x20000000

#define KEY_USR_VIEW 0x00010000
#define KEY_USR_READ 0x00020000
#define KEY_USR_WRITE 0x00040000
#define KEY_USR_SEARCH 0x00080000
#define KEY_USR_LINK 0x00100000
#define KEY_USR_SETATTR 0x00200000

#define KEY_GRP_VIEW 0x00000100
#define KEY_GRP_READ 0x00000200
#define KEY_GRP_WRITE 0x00000400
#define KEY_GRP_SEARCH 0x00000800
#define KEY_GRP_LINK 0x00001000
#define KEY_GRP_SETATTR 0x00002000

#define KEY_OTH_VIEW 0x00000001
#define KEY_OTH_READ 0x00000002
#define KEY_OTH_WRITE 0x00000004
#define KEY_OTH_SEARCH 0x00000008
#define KEY_OTH_LINK 0x00000010
#define KEY_OTH_SETATTR 0x00000020

namespace gvisor {
namespace testing {
namespace {

// keyctl is a cosmetic wrapper for the keyctl(2) system call.
static inline PosixErrorOr<int64_t> keyctl(int operation, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4,
                                           uint64_t arg5) {
  int64_t ret = syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
  if (ret == -1) {
    return PosixError(
        errno, absl::StrFormat("keyctl(%d, %d, %d, %d, %d) failed", operation,
                               arg2, arg3, arg4, arg5));
  }
  return ret;
}

static inline PosixErrorOr<int64_t> keyctl(int operation) {
  return keyctl(operation, 0, 0, 0, 0);
}

static inline PosixErrorOr<int64_t> keyctl(int operation, uint64_t arg2) {
  return keyctl(operation, arg2, 0, 0, 0);
}

static inline PosixErrorOr<int64_t> keyctl(int operation, uint64_t arg2,
                                           uint64_t arg3) {
  return keyctl(operation, arg2, arg3, 0, 0);
}

// DescribedKey is the description of a key.
struct DescribedKey {
  int64_t key_id;
  std::string full_desc;
  std::string type;
  uint64_t uid;
  uint64_t gid;
  uint64_t perm;
  std::string description;
};

std::string DescribedKeyString(const DescribedKey& described_key) {
  std::string process_perms = "??????";
  uint64_t perms = described_key.perm;
  process_perms[0] = (perms & KEY_POS_VIEW) == 0 ? '-' : 'v';     // view
  process_perms[1] = (perms & KEY_POS_READ) == 0 ? '-' : 'r';     // read
  process_perms[2] = (perms & KEY_POS_WRITE) == 0 ? '-' : 'w';    // write
  process_perms[3] = (perms & KEY_POS_SEARCH) == 0 ? '-' : 's';   // search
  process_perms[4] = (perms & KEY_POS_LINK) == 0 ? '-' : 'l';     // link
  process_perms[5] = (perms & KEY_POS_SETATTR) == 0 ? '-' : 'a';  // setattr
  std::string user_perms = "??????";
  user_perms[0] = (perms & KEY_USR_VIEW) == 0 ? '-' : 'v';     // view
  user_perms[1] = (perms & KEY_USR_READ) == 0 ? '-' : 'r';     // read
  user_perms[2] = (perms & KEY_USR_WRITE) == 0 ? '-' : 'w';    // write
  user_perms[3] = (perms & KEY_USR_SEARCH) == 0 ? '-' : 's';   // search
  user_perms[4] = (perms & KEY_USR_LINK) == 0 ? '-' : 'l';     // link
  user_perms[5] = (perms & KEY_USR_SETATTR) == 0 ? '-' : 'a';  // setattr
  std::string group_perms = "??????";
  group_perms[0] = (perms & KEY_GRP_VIEW) == 0 ? '-' : 'v';     // view
  group_perms[1] = (perms & KEY_GRP_READ) == 0 ? '-' : 'r';     // read
  group_perms[2] = (perms & KEY_GRP_WRITE) == 0 ? '-' : 'w';    // write
  group_perms[3] = (perms & KEY_GRP_SEARCH) == 0 ? '-' : 's';   // search
  group_perms[4] = (perms & KEY_GRP_LINK) == 0 ? '-' : 'l';     // link
  group_perms[5] = (perms & KEY_GRP_SETATTR) == 0 ? '-' : 'a';  // setattr
  std::string other_perms = "??????";
  other_perms[0] = (perms & KEY_OTH_VIEW) == 0 ? '-' : 'v';     // view
  other_perms[1] = (perms & KEY_OTH_READ) == 0 ? '-' : 'r';     // read
  other_perms[2] = (perms & KEY_OTH_WRITE) == 0 ? '-' : 'w';    // write
  other_perms[3] = (perms & KEY_OTH_SEARCH) == 0 ? '-' : 's';   // search
  other_perms[4] = (perms & KEY_OTH_LINK) == 0 ? '-' : 'l';     // link
  other_perms[5] = (perms & KEY_OTH_SETATTR) == 0 ? '-' : 'a';  // setattr

  return absl::StrFormat(
      "id=%d type=%s uid=%d gid=%d perms=0x%x "
      "[process=%s,user=%s,group=%s,other=%s] desc=%s",
      described_key.key_id, described_key.type, described_key.uid,
      described_key.gid, described_key.perm, process_perms, user_perms,
      group_perms, other_perms, described_key.description);
}

bool operator==(const DescribedKey& lhs, const DescribedKey& rhs) {
  if (lhs.key_id != rhs.key_id) {
    return false;
  }
  if (lhs.type != rhs.type) {
    return false;
  }
  if (lhs.uid != rhs.uid) {
    return false;
  }
  if (lhs.gid != rhs.gid) {
    return false;
  }
  if (lhs.perm != rhs.perm) {
    return false;
  }
  if (lhs.description != rhs.description) {
    return false;
  }
  return true;
}

bool operator!=(const DescribedKey& lhs, const DescribedKey& rhs) {
  return !(lhs == rhs);
}

PosixErrorOr<DescribedKey> DescribeKey(int64_t key_id) {
  ASSIGN_OR_RETURN_ERRNO(int64_t resolved_id,
                         keyctl(KEYCTL_GET_KEYRING_ID, key_id));
  if (resolved_id <= 0) {
    if (key_id == KEY_SPEC_SESSION_KEYRING) {
      return PosixError(
          -1, absl::StrFormat("Could not resolve session keyring (errno=%d)",
                              errno));
    }
    return PosixError(
        -1, absl::StrFormat("Could not resolve key id %d (errno=%d)", key_id,
                            errno));
  }
  DescribedKey described_key;
  described_key.key_id = resolved_id;
  char described_key_buf[1024];
  ASSIGN_OR_RETURN_ERRNO(
      int64_t buf_bytes,
      keyctl(KEYCTL_DESCRIBE, key_id, (uint64_t)(described_key_buf), 1024, 0));
  if (buf_bytes <= 0) {
    if (key_id == KEY_SPEC_SESSION_KEYRING) {
      return PosixError(-1, "Could not describe session keyring");
    }
    return PosixError(-1, absl::StrFormat("Could not describe key %d", key_id));
  }
  // Remove one byte from the key size because the returned length
  // includes the \0 at the end of the buffer.
  described_key.full_desc = std::string(described_key_buf, buf_bytes - 1);
  int i = 0;
  for (absl::string_view element :
       absl::StrSplit(described_key.full_desc, ';')) {
    switch (i) {
      case 0:
        described_key.type = element;
        break;
      case 1:
        if (!absl::SimpleAtoi(element, &described_key.uid)) {
          return PosixError(-1, absl::StrFormat("Could not parse uid from: %s",
                                                described_key.full_desc));
        }
        break;
      case 2:
        if (!absl::SimpleAtoi(element, &described_key.gid)) {
          return PosixError(-1, absl::StrFormat("Could not parse gid from: %s",
                                                described_key.full_desc));
        }
        break;
      case 3:
        described_key.perm = std::stoull(std::string(element), nullptr, 16);
        break;
      case 4:
        described_key.description = std::string(element);
        break;
      default:
        return PosixError(
            -1,
            absl::StrFormat(
                "Key string had more than the expected number of elements: %s",
                described_key.full_desc));
    }
    i++;
  }
  return described_key;
}

TEST(KeysTest, GetCurrentSessionKeyring) {
  DescribedKey key =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  std::cerr << "Session key: " << DescribedKeyString(key) << std::endl;
  EXPECT_TRUE(absl::StartsWith(key.description, "_ses"))
      << "Unexpected name for session keyring";
}

TEST(KeysTest, GetCurrentSessionKeyringViaID) {
  DescribedKey key_via_special_id =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  std::cerr << "Session key (retrieved via KEY_SPEC_SESSION_KEYRING): "
            << DescribedKeyString(key_via_special_id) << std::endl;
  DescribedKey key_via_actual_id =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(key_via_special_id.key_id));
  std::cerr << "Session key (retrieved via explicit ID "
            << key_via_special_id.key_id
            << "): " << DescribedKeyString(key_via_special_id) << std::endl;
  EXPECT_EQ(key_via_special_id, key_via_actual_id);
}

TEST(KeysTest, GetKeyringThatDoesNotExist) {
  // We don't know which keyring IDs do exist, so we just iterate until we find
  // one that doesn't exist. Surely we'll find one eventually.
  char described_key_buf[1024];
  uint32_t key_id;
  bool found_non_existent_key = false;
  for (int i = 0; i < 100; ++i) {
    key_id = absl::Uniform<uint32_t>(absl::InsecureBitGen(), 0,
                                     std::numeric_limits<uint32_t>::max());
    PosixErrorOr<int64_t> buf_bytes =
        keyctl(KEYCTL_DESCRIBE, key_id, (uint64_t)(described_key_buf), 1024, 0);
    if (!buf_bytes.ok() && errno == ENOKEY) {
      found_non_existent_key = true;
      break;
    }
  }
  EXPECT_TRUE(found_non_existent_key) << "Did not find any non-existent key ID";
}

TEST(KeysTest, DescribeKeyWithNullBuffer) {
  DescribedKey session_key =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  int64_t desc_length = ASSERT_NO_ERRNO_AND_VALUE(
      keyctl(KEYCTL_DESCRIBE, KEY_SPEC_SESSION_KEYRING, 0));
  EXPECT_EQ(desc_length, session_key.full_desc.length() + 1);
}

TEST(KeysTest, DescribeKeyWithTooSmallBuffer) {
  DescribedKey session_key =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  char described_key_buf[4];
  ASSERT_LT(4, session_key.full_desc.length());
  int64_t desc_length = ASSERT_NO_ERRNO_AND_VALUE(
      keyctl(KEYCTL_DESCRIBE, KEY_SPEC_SESSION_KEYRING,
             (uint64_t)(described_key_buf), 0, 0));
  EXPECT_EQ(desc_length, session_key.full_desc.length() + 1);
}

TEST(KeysTest, ChildThreadInheritsSessionKeyring) {
  DescribedKey parent_key =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  std::cerr << "Parent session keyring before spawning child thread: "
            << DescribedKeyString(parent_key) << std::endl;
  DescribedKey child_key;
  ScopedThread([&] {
    child_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Child session keyring: " << DescribedKeyString(child_key)
              << std::endl;
  }).Join();
  EXPECT_EQ(parent_key, child_key)
      << "Child session keyring did not match parent session keyring: child="
      << DescribedKeyString(child_key)
      << " vs parent=" << DescribedKeyString(parent_key);
}

TEST(KeysTest, ChildThreadInheritsSessionKeyringCreatedAfterChildIsBorn) {
  DescribedKey first_parent_key;
  DescribedKey second_parent_key;
  DescribedKey child_key;
  ScopedThread([&] {
    int64_t session_keyring_id =
        ASSERT_NO_ERRNO_AND_VALUE(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    ASSERT_GT(session_keyring_id, 0)
        << "Failed to join session keyring: " << errno;
    first_parent_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Parent session keyring before spawning child: "
              << DescribedKeyString(first_parent_key) << std::endl;
    ScopedThread([&] {
      absl::Mutex mu;
      bool child_ready = false;
      bool parent_keyring_created = false;
      ScopedThread child([&] {
        absl::MutexLock child_ml(&mu);
        child_ready = true;
        std::cerr << "Child is spawned and waiting for parent." << std::endl;
        mu.Await(absl::Condition(&parent_keyring_created));
        child_key =
            ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
        std::cerr << "Child session keyring: " << DescribedKeyString(child_key)
                  << std::endl;
      });
      [&] {
        absl::MutexLock parent_ml(&mu);
        mu.Await(absl::Condition(&child_ready));
        int64_t session_keyring_id =
            ASSERT_NO_ERRNO_AND_VALUE(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
        ASSERT_GT(session_keyring_id, 0)
            << "Failed to join session keyring: " << errno;
        second_parent_key =
            ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
        std::cerr << "Parent session keyring after spawning child: "
                  << DescribedKeyString(second_parent_key) << std::endl;
        parent_keyring_created = true;
      }();
      child.Join();
    }).Join();
  }).Join();
  ASSERT_NE(first_parent_key, second_parent_key);
  ASSERT_EQ(first_parent_key, child_key);
}

TEST(KeysTest, JoinNewNamedSessionKeyring) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  DescribedKey child_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    child_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Child session keyring after joining new session keyring: "
              << DescribedKeyString(child_key) << std::endl;
  }).Join();
  EXPECT_EQ(child_key.description, kKeyringName);
}

TEST(KeysTest, ChildJoinsNewSessionKeyring) {
  DescribedKey parent_key_before =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  std::cerr << "Parent session keyring before spawning child thread: "
            << DescribedKeyString(parent_key_before) << std::endl;
  DescribedKey child_key;
  ScopedThread([&] {
    int64_t session_keyring_id =
        ASSERT_NO_ERRNO_AND_VALUE(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    ASSERT_GT(session_keyring_id, 0)
        << "Failed to join session keyring: " << errno;
    child_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Child session keyring after joining new session keyring: "
              << DescribedKeyString(child_key) << std::endl;
    ASSERT_EQ(child_key.key_id, session_keyring_id);
  }).Join();
  DescribedKey parent_key_after =
      ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  std::cerr << "Parent session keyring after child finished: "
            << DescribedKeyString(parent_key_after) << std::endl;
  EXPECT_EQ(parent_key_before, parent_key_after)
      << "Parent session keyring changed after child did its thing: "
      << DescribedKeyString(parent_key_after) << " vs "
      << DescribedKeyString(parent_key_before);
  EXPECT_NE(parent_key_before, child_key)
      << "Child session keyring did not change after joining new session "
         "keyring: "
      << DescribedKeyString(child_key);
}

TEST(KeysTest, ExistingNamedSessionKeyringIsNew) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  DescribedKey parent_key;
  DescribedKey first_child_key;
  DescribedKey second_child_initial_key;
  DescribedKey second_child_existing_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    parent_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    absl::Mutex mu;
    bool first_child_created_keyring = false;
    ScopedThread first_child([&] {
      absl::MutexLock ml(&mu);
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      first_child_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "First child's session keyring: "
                << DescribedKeyString(first_child_key) << std::endl;
      first_child_created_keyring = true;
    });
    ScopedThread([&] {
      absl::MutexLock ml(&mu);
      second_child_initial_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Session child's initial session keyring: "
                << DescribedKeyString(second_child_initial_key) << std::endl;
      mu.Await(absl::Condition(&first_child_created_keyring));
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      second_child_existing_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Session child's second session keyring: "
                << DescribedKeyString(second_child_existing_key) << std::endl;
    }).Join();
    first_child.Join();
  }).Join();
  EXPECT_EQ(parent_key, second_child_initial_key);
  EXPECT_EQ(first_child_key.description, kKeyringName);
  EXPECT_NE(parent_key, first_child_key);
  EXPECT_NE(first_child_key, second_child_existing_key);
  EXPECT_EQ(first_child_key.description, second_child_existing_key.description);
  EXPECT_NE(first_child_key.key_id, second_child_existing_key.key_id);
}

TEST(KeysTest, SetAndRetrieveKeyPermissions) {
  DescribedKey before_key;
  DescribedKey after_key;
  DescribedKey deeper_key;
  uint64_t new_perms = 0;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    before_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Child session keyring after joining new session keyring: "
              << DescribedKeyString(before_key) << std::endl;
    new_perms = (before_key.perm | KEY_USR_SEARCH) & 0xffffffff;
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, new_perms));
    after_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr
        << "Child session keyring after changing session keyring permissions: "
        << DescribedKeyString(after_key) << std::endl;
    ScopedThread([&] {
      deeper_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second-level child session keyring: "
                << DescribedKeyString(deeper_key) << std::endl;
    }).Join();
  }).Join();
  EXPECT_NE(new_perms, 0) << "New permissions are empty";
  EXPECT_NE(before_key.perm, new_perms)
      << "Permissions were not actually requested to change, please update "
         "permissions mask";
  EXPECT_EQ(after_key.perm, new_perms)
      << "Permissions were not updated correctly";
  EXPECT_EQ(after_key, deeper_key) << "Permissions were not inherited";
}

TEST(KeysTest, JoinExistingNamedKeyringFromParent) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  constexpr absl::string_view kOtherKeyringName = "my_other_keyring";
  DescribedKey first_level_key;
  DescribedKey second_level_key;
  DescribedKey third_level_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    DescribedKey before_perms_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    uint64_t perms = (before_perms_key.perm | 0x80008) & 0xffffffff;
    ASSERT_NO_ERRNO(keyctl(KEYCTL_SETPERM, before_perms_key.key_id, perms));
    first_level_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "First-level child keyring: "
              << DescribedKeyString(first_level_key) << std::endl;
    ScopedThread([&] {
      ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING,
                             (uint64_t)(kOtherKeyringName.data())));
      second_level_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second-level child keyring: "
                << DescribedKeyString(second_level_key) << std::endl;
      ScopedThread([&] {
        ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING,
                               (uint64_t)(kKeyringName.data())));
        third_level_key =
            ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
        std::cerr << "Third-level child keyring: "
                  << DescribedKeyString(third_level_key) << std::endl;
      }).Join();
    }).Join();
  }).Join();
  // The key_id is different per process, so don't compare that.
  // We use the permissions field to verify that the keyring is the same
  // between the first and the third level, to show that the same keyring
  // is being looked up.
  // However, the second level didn't look up the same keyring, so its
  // permissions should be different.
  EXPECT_EQ(first_level_key.perm, third_level_key.perm);
  EXPECT_NE(first_level_key.perm, second_level_key.perm);
}

TEST(KeysTest, DefaultKeyPermissions) {
  constexpr absl::string_view kKeyringName = "named_session_keyring";
  DescribedKey default_named_session_key;
  DescribedKey default_unnamed_session_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    default_named_session_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  }).Join();
  ScopedThread([&] {
    ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    default_unnamed_session_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
  }).Join();
  std::cerr << "Default named session keyring: "
            << DescribedKeyString(default_named_session_key) << std::endl;
  std::cerr << "Default unnamed session keyring: "
            << DescribedKeyString(default_unnamed_session_key) << std::endl;
  // Possessor permissions:
  uint64_t key_pos_all = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE |
                         KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR;
  EXPECT_EQ(default_unnamed_session_key.perm & key_pos_all, key_pos_all);
  EXPECT_EQ(default_named_session_key.perm & key_pos_all, key_pos_all);

  // User permissions:
  // These differ depending on whether the keyring is named or not.
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_VIEW, KEY_USR_VIEW);
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_READ, KEY_USR_READ);
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_WRITE, 0);
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_SEARCH, 0);
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_LINK, 0);
  EXPECT_EQ(default_unnamed_session_key.perm & KEY_USR_SETATTR, 0);
  EXPECT_EQ(default_unnamed_session_key.perm | KEY_USR_LINK,
            default_named_session_key.perm);

  // Group permissions:
  uint64_t key_group_all = KEY_GRP_VIEW | KEY_GRP_READ | KEY_GRP_WRITE |
                           KEY_GRP_SEARCH | KEY_GRP_LINK | KEY_GRP_SETATTR;
  EXPECT_EQ(default_unnamed_session_key.perm & key_group_all, 0);
  EXPECT_EQ(default_named_session_key.perm & key_group_all, 0);

  // Other permissions:
  uint64_t key_other_all = KEY_OTH_VIEW | KEY_OTH_READ | KEY_OTH_WRITE |
                           KEY_OTH_SEARCH | KEY_OTH_LINK | KEY_OTH_SETATTR;
  EXPECT_EQ(default_unnamed_session_key.perm & key_other_all, 0);
  EXPECT_EQ(default_named_session_key.perm & key_other_all, 0);
}

TEST(KeysTest, EnforceKeyPermissions) {
  ScopedThread([&] {
    constexpr absl::string_view kKeyringName = "my_little_keyring";
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    DescribedKey key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    ASSERT_NO_ERRNO(keyctl(KEYCTL_SETPERM, key.key_id, 0 /* No permissions */));
    EXPECT_THAT(keyctl(KEYCTL_DESCRIBE, KEY_SPEC_SESSION_KEYRING),
                PosixErrorIs(EACCES))
        << "Session keyring can be described";
    EXPECT_THAT(keyctl(KEYCTL_DESCRIBE, key.key_id), PosixErrorIs(EACCES))
        << "Session keyring can be described by ID";
    ASSERT_THAT(keyctl(KEYCTL_SETPERM, key.key_id, 0), PosixErrorIs(EACCES))
        << "Session keyring perms can be changed after locking them down";
    ScopedThread([&] {
      EXPECT_THAT(keyctl(KEYCTL_DESCRIBE, KEY_SPEC_SESSION_KEYRING),
                  PosixErrorIs(EACCES))
          << "Session keyring can be described in child";
      EXPECT_THAT(keyctl(KEYCTL_DESCRIBE, key.key_id), PosixErrorIs(EACCES))
          << "Session keyring can be described by ID in child";
      ASSERT_THAT(keyctl(KEYCTL_SETPERM, key.key_id, 0), PosixErrorIs(EACCES))
          << "Session keyring perms can be changed after locking them down in "
             "parent";
    }).Join();
  }).Join();
}

// JoiningNonSearchableNamedKeyring verifies what happens when joining an
// existing named keyring without the search permission.
TEST(KeysTest, JoiningNonSearchableNamedKeyring) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  DescribedKey first_key;
  DescribedKey second_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    first_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "First child keyring: " << DescribedKeyString(first_key)
              << std::endl;
    uint64_t non_searchable_perms =
        first_key.perm &
        ~(KEY_POS_SEARCH | KEY_USR_SEARCH | KEY_GRP_SEARCH | KEY_OTH_SEARCH);
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, non_searchable_perms));
    ScopedThread([&] {
      // The man page says this should fail with EACCES, but Linux actually
      // creates a new keyring with the same name instead.
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      second_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second child keyring: " << DescribedKeyString(first_key)
                << std::endl;
    }).Join();
  }).Join();
  ASSERT_NE(first_key.key_id, second_key.key_id);
}

// JoiningSearchableNamedKeyring verifies what happens when joining an
// existing named keyring with the search permission.
TEST(KeysTest, JoiningSearchableNamedKeyring) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  DescribedKey searchable_key;
  DescribedKey second_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
    DescribedKey initial_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Initial session keyring: " << DescribedKeyString(initial_key)
              << std::endl;
    uint64_t searchable_perms = initial_key.perm | KEY_USR_SEARCH;
    ASSERT_NO_ERRNO(
        keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, searchable_perms));
    searchable_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Searchable session keyring: "
              << DescribedKeyString(searchable_key) << std::endl;
    ScopedThread([&] {
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      second_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second keyring: " << DescribedKeyString(second_key)
                << std::endl;
    }).Join();
  }).Join();
  EXPECT_EQ(searchable_key.key_id, second_key.key_id);
}

TEST(KeysTest, SearchableKeyringIsSharedAcrossThreads) {
  constexpr absl::string_view kKeyringName = "my_little_keyring";
  DescribedKey parent_key;
  DescribedKey first_child_final_key;
  DescribedKey second_child_final_key;
  ScopedThread([&] {
    ASSERT_NO_ERRNO(keyctl(KEYCTL_JOIN_SESSION_KEYRING));
    parent_key =
        ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
    std::cerr << "Parent session keyring: " << DescribedKeyString(parent_key)
              << std::endl;
    absl::Mutex mu;

    // We're going to do a complicated dance.
    // Each of the following booleans is used to gate on the steps described
    // above it.

    // - Spawn two threads, have them wait on each other until they are both
    //   actually running code.
    bool first_child_ready = false;
    bool second_child_ready = false;

    // - Have the first thread create a named keyring.
    // - Have the first thread change this keyring to be searchable by user.
    bool first_child_created_keyring = false;

    // - Have the second thread join it by name.
    // - Have the second thread flip a bit in its permission field:
    //   KEY_GRP_LINK
    bool second_child_modified_keyring = false;

    // - Have the first thread re-read the permissions of its keyring.
    // - Have the first thread flip another bit in the permission field:
    //   KEY_OTH_LINK
    bool first_child_modified_keyring = false;

    // - Have the second thread re-read the permissions of its keyring.
    // - Verify that the final keys from both threads match and have both bits
    //   flipped.

    ScopedThread first_child([&] {
      absl::MutexLock ml(&mu);
      first_child_ready = true;
      mu.Await(absl::Condition(&second_child_ready));
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      DescribedKey initial_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "First child: initial session keyring: "
                << DescribedKeyString(initial_key) << std::endl;
      uint64_t searchable_perms = initial_key.perm | KEY_USR_SEARCH;
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, searchable_perms));
      DescribedKey searchable_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "First child: searchable session keyring: "
                << DescribedKeyString(searchable_key) << std::endl;
      first_child_created_keyring = true;
      mu.Await(absl::Condition(&second_child_modified_keyring));
      DescribedKey modified_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr
          << "First child: session keyring after second thread modified it: "
          << DescribedKeyString(modified_key) << std::endl;
      uint64_t new_perms = modified_key.perm | KEY_OTH_LINK;
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, new_perms));
      first_child_final_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "First child: final session keyring: "
                << DescribedKeyString(first_child_final_key) << std::endl;
      first_child_modified_keyring = true;
    });
    ScopedThread second_child([&] {
      absl::MutexLock ml(&mu);
      second_child_ready = true;
      mu.Await(absl::Condition(&first_child_ready));
      mu.Await(absl::Condition(&first_child_created_keyring));
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_JOIN_SESSION_KEYRING, (uint64_t)(kKeyringName.data())));
      DescribedKey initial_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second child: initial session keyring: "
                << DescribedKeyString(initial_key) << std::endl;
      uint64_t new_perms = initial_key.perm | KEY_GRP_LINK;
      ASSERT_NO_ERRNO(
          keyctl(KEYCTL_SETPERM, KEY_SPEC_SESSION_KEYRING, new_perms));
      DescribedKey modified_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr
          << "Second child: session keyring after modifying its permissions: "
          << DescribedKeyString(modified_key) << std::endl;
      second_child_modified_keyring = true;
      mu.Await(absl::Condition(&first_child_modified_keyring));
      second_child_final_key =
          ASSERT_NO_ERRNO_AND_VALUE(DescribeKey(KEY_SPEC_SESSION_KEYRING));
      std::cerr << "Second child: final session keyring: "
                << DescribedKeyString(second_child_final_key) << std::endl;
    });
    first_child.Join();
    second_child.Join();
  }).Join();
  EXPECT_NE(parent_key, first_child_final_key);
  EXPECT_NE(parent_key, second_child_final_key);
  EXPECT_NE(parent_key.perm, first_child_final_key.perm);
  EXPECT_EQ(first_child_final_key.key_id, second_child_final_key.key_id);
  for (const uint64_t bit :
       {KEY_USR_LINK, KEY_USR_SEARCH, KEY_GRP_LINK, KEY_OTH_LINK}) {
    EXPECT_EQ(parent_key.perm & bit, 0) << "Bit " << bit << " in parent key";
    EXPECT_EQ(first_child_final_key.perm & bit, bit)
        << "Bit " << bit << " in first child key";
    EXPECT_EQ(second_child_final_key.perm & bit, bit)
        << "Bit " << bit << " in second child key";
  }
  EXPECT_EQ(first_child_final_key.perm, second_child_final_key.perm);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
