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

#include <fcntl.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_IS_SET 1
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_LOWER 3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 28
#endif
#ifndef PR_GET_SECUREBITS
#define PR_GET_SECUREBITS 27
#endif
#ifndef SECBIT_KEEP_CAPS
#define SECBIT_KEEP_CAPS (1 << 4)
#endif
#ifndef SECBIT_KEEP_CAPS_LOCKED
#define SECBIT_KEEP_CAPS_LOCKED (1 << 5)
#endif

// Helper to check if a capability is in the ambient set.
PosixErrorOr<bool> AmbientCapIsSet(int cap) {
  int val = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
  if (val < 0) {
    return PosixError(errno, "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET)");
  }
  return val == 1;
}

// Helper to raise a capability in the ambient set.
PosixError AmbientCapRaise(int cap) {
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0) {
    return PosixError(errno, "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE)");
  }
  return NoError();
}

// Helper to lower a capability in the ambient set.
PosixError AmbientCapLower(int cap) {
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0) < 0) {
    return PosixError(errno, "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER)");
  }
  return NoError();
}

// Helper to clear all ambient capabilities.
PosixError AmbientCapClearAll() {
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
    return PosixError(errno, "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)");
  }
  return NoError();
}

// Helper to read capability sets of another process.
PosixErrorOr<CapSet> GetProcessCapabilitySets(pid_t pid) {
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, pid};
  struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
  if (syscall(__NR_capget, &header, &caps) < 0) {
    return PosixError(errno, "capget");
  }
  CapSet cs;
  cs.effective =
      (static_cast<uint64_t>(caps[1].effective) << 32) | caps[0].effective;
  cs.permitted =
      (static_cast<uint64_t>(caps[1].permitted) << 32) | caps[0].permitted;
  cs.inheritable =
      (static_cast<uint64_t>(caps[1].inheritable) << 32) | caps[0].inheritable;
  return cs;
}

// Reads /proc/[pid]/status and parses the ambient capability set.
PosixErrorOr<uint64_t> GetProcessAmbientCapabilitySet(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/status", pid);

  std::string contents;
  PosixError perr = GetContents(path, &contents);
  RETURN_IF_ERRNO(perr);

  size_t pos = contents.find("CapAmb:\t");
  if (pos == std::string::npos) {
    return PosixError(ENOENT, "CapAmb not found in /proc/[pid]/status");
  }

  pos += 8;  // size of "CapAmb:\t"
  size_t end_pos = contents.find('\n', pos);
  if (end_pos == std::string::npos) {
    return PosixError(EINVAL, "Invalid CapAmb format in /proc/[pid]/status");
  }
  std::string val_str = contents.substr(pos, end_pos - pos);
  uint64_t val = 0;
  if (sscanf(val_str.c_str(), "%" SCNx64, &val) != 1) {
    return PosixError(EINVAL, "Failed to parse CapAmb hex value");
  }

  return val;
}

std::string GetBasename(const std::string& path) {
  size_t pos = path.find_last_of('/');
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

// Poll child's command name until it has completed execve and is running the
// expected command.
bool WaitForChildExec(pid_t child_pid, const std::string& expected_comm) {
  char comm_path[64];
  snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", child_pid);
  for (int i = 0; i < 1000; ++i) {
    int fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
      char buf[32] = {};
      int n = read(fd, buf, sizeof(buf) - 1);
      close(fd);
      if (n > 0 && strcmp(buf, expected_comm.c_str()) == 0) {
        return true;
      }
    }
    absl::SleepFor(absl::Milliseconds(1));
  }
  return false;
}

class AmbientCapabilitiesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (getuid() != 0) {
      GTEST_SKIP()
          << "Subprocess tests must be run as root to manipulate capabilities.";
    }
    // Start with a clean state for Inheritable and Ambient.
    ASSERT_NO_ERRNO(AmbientCapClearAll());
    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable = 0;
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));
  }
};

TEST_F(AmbientCapabilitiesTest, BasicRaiseAndLower) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    // Raising a capability not in permitted/inheritable should fail with EPERM.
    EXPECT_THAT(AmbientCapRaise(CAP_NET_BIND_SERVICE), PosixErrorIs(EPERM));

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());

    // Add CAP_NET_BIND_SERVICE to Inheritable.
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));

    ASSERT_NO_ERRNO(AmbientCapLower(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
  });
}

TEST_F(AmbientCapabilitiesTest, ClearedWhenPermittedDropped) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));

    ASSERT_NO_ERRNO(DropPermittedCapability(CAP_NET_BIND_SERVICE));

    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
  });
}

TEST_F(AmbientCapabilitiesTest, ClearedWhenInheritableDropped) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));

    cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable &= ~(1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
  });
}

TEST_F(AmbientCapabilitiesTest, ClearAll) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE) | (1ULL << CAP_NET_RAW);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_RAW));

    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_RAW), IsPosixErrorOkAndHolds(true));

    ASSERT_NO_ERRNO(AmbientCapClearAll());

    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_RAW), IsPosixErrorOkAndHolds(false));
  });
}

TEST_F(AmbientCapabilitiesTest, PreservedAcrossExecve) {
  // This test will set keepcaps, raise ambient caps, setuid to non-root,
  // and then execve a standard sleep command to verify that the child
  // inherits the ambient caps in its permitted and effective sets.
  pid_t child_pid = fork();
  ASSERT_THAT(child_pid, SyscallSucceeds());

  if (child_pid == 0) {
    // In child process.
    TEST_CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);

    CapSet cs = EXPECT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    TEST_CHECK(SetCapabilitySets(cs).ok());
    // Switch to nobody.
    TEST_CHECK(syscall(SYS_setuid, 65534) == 0);

    // Verify we still have the cap in permitted, but ambient was cleared.
    cs = EXPECT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    TEST_CHECK((cs.permitted & (1ULL << CAP_NET_BIND_SERVICE)) != 0);
    TEST_CHECK(
        !EXPECT_NO_ERRNO_AND_VALUE(AmbientCapIsSet(CAP_NET_BIND_SERVICE)));

    // Raise ambient capabilities after setuid.
    TEST_CHECK(AmbientCapRaise(CAP_NET_BIND_SERVICE).ok());

    // Verify it is now in permitted and ambient.
    cs = EXPECT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    TEST_CHECK((cs.permitted & (1ULL << CAP_NET_BIND_SERVICE)) != 0);
    TEST_CHECK(
        EXPECT_NO_ERRNO_AND_VALUE(AmbientCapIsSet(CAP_NET_BIND_SERVICE)));

    char* const argv[] = {const_cast<char*>("/bin/sleep"),
                          const_cast<char*>("10"), nullptr};
    char* const envp[] = {nullptr};
    execve("/bin/sleep", argv, envp);
    TEST_CHECK_MSG(false, "execve failed");
  }

  ASSERT_TRUE(WaitForChildExec(child_pid, "sleep\n"))
      << "Child process failed to exec sleep";
  CapSet child_cs =
      ASSERT_NO_ERRNO_AND_VALUE(GetProcessCapabilitySets(child_pid));

  EXPECT_NE(child_cs.permitted & (1ULL << CAP_NET_BIND_SERVICE), 0);
  EXPECT_NE(child_cs.effective & (1ULL << CAP_NET_BIND_SERVICE), 0);

  uint64_t child_amb =
      ASSERT_NO_ERRNO_AND_VALUE(GetProcessAmbientCapabilitySet(child_pid));
  EXPECT_NE(child_amb & (1ULL << CAP_NET_BIND_SERVICE), 0);

  EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
  int status = 0;
  EXPECT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
}

TEST_F(AmbientCapabilitiesTest, ClearedOnTransitionToNonRoot) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    // Disable keepcaps.
    ASSERT_THAT(prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0), SyscallSucceeds());

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));

    // Set the user to nobody.
    ASSERT_THAT(syscall(SYS_setuid, 65534), SyscallSucceeds());

    // All sets should be cleared (since keep_caps was false).
    cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    EXPECT_EQ(cs.permitted & (1ULL << CAP_NET_BIND_SERVICE), 0);
    EXPECT_EQ(cs.effective & (1ULL << CAP_NET_BIND_SERVICE), 0);
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
  });
}

TEST_F(AmbientCapabilitiesTest, AmbientClearedOnTransitionEvenWithKeepCaps) {
  ScopedThread([] {
    ASSERT_NO_ERRNO(AmbientCapClearAll());

    // Enable keepcaps.
    ASSERT_THAT(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), SyscallSucceeds());

    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    ASSERT_NO_ERRNO(AmbientCapRaise(CAP_NET_BIND_SERVICE));
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(true));

    // Set the user to nobody.
    ASSERT_THAT(syscall(SYS_setuid, 65534), SyscallSucceeds());

    // Permitted capability should retain the capability because keep_caps was
    // true.
    cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    EXPECT_NE(cs.permitted & (1ULL << CAP_NET_BIND_SERVICE), 0);

    // Effective capability is cleared because we transitioned root to nobody.
    EXPECT_EQ(cs.effective & (1ULL << CAP_NET_BIND_SERVICE), 0);

    // Ambient capability is unconditionally cleared.
    EXPECT_THAT(AmbientCapIsSet(CAP_NET_BIND_SERVICE),
                IsPosixErrorOkAndHolds(false));
  });
}

PosixErrorOr<TempPath> CreateSuidToUserSleepExecutable(uid_t uid) {
  std::string exec_blob;
  PosixError perr = GetContents("/bin/sleep", &exec_blob);
  RETURN_IF_ERRNO(perr);

  auto temp_file_or =
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), exec_blob, 0755);
  RETURN_IF_ERRNO(temp_file_or);
  auto temp_file = std::move(temp_file_or).ValueOrDie();

  if (chown(temp_file.path().c_str(), uid, -1) < 0) {
    return PosixError(errno, "chown");
  }

  if (chmod(temp_file.path().c_str(), 0755 | S_ISUID) < 0) {
    return PosixError(errno, "chmod");
  }

  return temp_file;
}

TEST_F(AmbientCapabilitiesTest, ClearedOnFilePriv) {
  std::string tmpdir = GetAbsoluteTestTmpdir();
  bool is_nosuid = ASSERT_NO_ERRNO_AND_VALUE(IsNosuid(tmpdir));
  if (is_nosuid) {
    GTEST_SKIP() << "TEST_TMPDIR (" << tmpdir
                 << ") is mounted nosuid; cannot test SUID transition.";
  }

  // Create a SUID-to-5000 copy of sleep.
  TempPath suid_exe =
      ASSERT_NO_ERRNO_AND_VALUE(CreateSuidToUserSleepExecutable(5000));

  pid_t child_pid = fork();
  ASSERT_THAT(child_pid, SyscallSucceeds());

  if (child_pid == 0) {
    // In child process.
    TEST_CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);

    CapSet cs = EXPECT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.inheritable |= (1ULL << CAP_NET_BIND_SERVICE);
    TEST_CHECK(SetCapabilitySets(cs).ok());

    // Switch to UID 1000.
    TEST_CHECK(syscall(SYS_setuid, 1000) == 0);

    // Raise ambient capability CAP_NET_BIND_SERVICE.
    TEST_CHECK(AmbientCapRaise(CAP_NET_BIND_SERVICE).ok());

    // Verify it is now in permitted and ambient.
    cs = EXPECT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    TEST_CHECK((cs.permitted & (1ULL << CAP_NET_BIND_SERVICE)) != 0);
    TEST_CHECK(
        EXPECT_NO_ERRNO_AND_VALUE(AmbientCapIsSet(CAP_NET_BIND_SERVICE)));

    // Exec the SUID-to-5000 binary.
    char* const argv[] = {const_cast<char*>(suid_exe.path().c_str()),
                          const_cast<char*>("10"), nullptr};
    char* const envp[] = {nullptr};
    execve(suid_exe.path().c_str(), argv, envp);
    TEST_CHECK_MSG(false, "execve failed");
  }

  std::string expected_comm = GetBasename(suid_exe.path());
  if (expected_comm.length() > 15) {
    expected_comm = expected_comm.substr(0, 15);
  }
  expected_comm += '\n';

  ASSERT_TRUE(WaitForChildExec(child_pid, expected_comm))
      << "Child process failed to exec sleep";
  CapSet child_cs =
      ASSERT_NO_ERRNO_AND_VALUE(GetProcessCapabilitySets(child_pid));

  // Since it was a SUID exec (from 1000 to 5000), ambient caps should be
  // cleared. The child runs as UID 5000, so its permitted and effective sets
  // are empty.
  EXPECT_EQ(child_cs.permitted & (1ULL << CAP_NET_BIND_SERVICE), 0);
  EXPECT_EQ(child_cs.effective & (1ULL << CAP_NET_BIND_SERVICE), 0);

  uint64_t child_amb =
      ASSERT_NO_ERRNO_AND_VALUE(GetProcessAmbientCapabilitySet(child_pid));
  EXPECT_EQ(child_amb & (1ULL << CAP_NET_BIND_SERVICE), 0);

  EXPECT_THAT(kill(child_pid, SIGKILL), SyscallSucceeds());
  int status = 0;
  EXPECT_THAT(waitpid(child_pid, &status, 0),
              SyscallSucceedsWithValue(child_pid));
}

TEST_F(AmbientCapabilitiesTest, SecurebitsKeepCapsEPERM) {
  ScopedThread([] {
    // Unsupported bits return EPERM.
    EXPECT_THAT(prctl(PR_SET_SECUREBITS, 1ULL << 30, 0, 0, 0),
                SyscallFailsWithErrno(EPERM));

    int current_sec = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    ASSERT_THAT(current_sec, SyscallSucceeds());

    // Drop CAP_SETPCAP from permitted and effective sets.
    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    cs.effective &= ~(1ULL << CAP_SETPCAP);
    cs.permitted &= ~(1ULL << CAP_SETPCAP);
    ASSERT_NO_ERRNO(SetCapabilitySets(cs));

    // Without CAP_SETPCAP:
    // 1. Try to set to unchanged value and witness EPERM.
    EXPECT_THAT(prctl(PR_SET_SECUREBITS, current_sec, 0, 0, 0),
                SyscallFailsWithErrno(EPERM));
    // 2. Toggle the unprivileged SECBIT_KEEP_CAPS to witness EPERM.
    EXPECT_THAT(
        prctl(PR_SET_SECUREBITS, current_sec ^ SECBIT_KEEP_CAPS, 0, 0, 0),
        SyscallFailsWithErrno(EPERM));
  });
}

TEST_F(AmbientCapabilitiesTest, SecurebitsKeepCapsTransition) {
  ScopedThread([] {
    ASSERT_THAT(prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS, 0, 0, 0),
                SyscallSucceeds());
    CapSet cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    ASSERT_NE(cs.permitted, 0);
    ASSERT_THAT(syscall(SYS_setuid, 65534), SyscallSucceeds());

    CapSet post_cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    EXPECT_EQ(post_cs.permitted, cs.permitted);
  });
}

TEST_F(AmbientCapabilitiesTest, SecurebitsNoKeepCapsTransition) {
  ScopedThread([] {
    int val = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    ASSERT_THAT(val, SyscallSucceeds());
    if (val & SECBIT_KEEP_CAPS) {
      ASSERT_THAT(prctl(PR_SET_SECUREBITS, 0, 0, 0, 0), SyscallSucceeds());
    }
    ASSERT_THAT(syscall(SYS_setuid, 65534), SyscallSucceeds());

    CapSet post_cs = ASSERT_NO_ERRNO_AND_VALUE(GetCapabilitySets());
    EXPECT_EQ(post_cs.permitted, 0);
  });
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
