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

// All tests in this file rely on being about to mount and unmount cgroupfs,
// which isn't expected to work, or be safe on a general linux system.

#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cgroup_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#ifndef SYS_clone3
#define SYS_clone3 435
#endif  // SYS_clone3

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

namespace gvisor {

struct clone_args {
  uint64_t flags;
  uint64_t pidfd;
  uint64_t child_tid;
  uint64_t parent_tid;
  uint64_t exit_signal;
  uint64_t stack;
  uint64_t stack_size;
  uint64_t tls;
  uint64_t set_tid;
  uint64_t set_tid_size;
  uint64_t cgroup;
};

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

int clone3(struct clone_args* ca, size_t size) {
  return syscall(SYS_clone3, ca, size);
}
namespace testing {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;

bool Cgroup2Available() {
  return TEST_CHECK_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN));
}

class Cgroup2Test : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!Cgroup2Available()) {
      GTEST_SKIP() << "Cgroup v2 not available or ignored on gVisor";
    }
  }

  void CleanCgroupDirs(absl::string_view dir) {
    auto children = ListDir(dir, /*skipdots=*/true);
    if (children.ok()) {
      for (const auto& child : children.ValueOrDie()) {
        std::string full_path = JoinPath(dir, child);
        auto is_dir = IsDirectory(full_path);
        if (is_dir.ok() && is_dir.ValueOrDie()) {
          CleanCgroupDirs(full_path);
        }
      }
    }
    absl::Time deadline = absl::Now() + absl::Seconds(5);
    PosixError err;
    while (true) {
      err = Rmdir(dir);
      if (err.ok()) {
        break;
      }
      if (absl::Now() >= deadline) {
        ASSERT_NO_ERRNO(err);
        break;
      }
      absl::SleepFor(absl::Milliseconds(10));
    }
  }

  void TearDown() override {
    if (root_) {
      root_->Enter(getpid()).IgnoreError();
    }
    if (c_) {
      CleanCgroupDirs(c_->Path());
    }
  }

  void Init() {
    if (m_) return;
    m_.emplace(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    root_.emplace(ASSERT_NO_ERRNO_AND_VALUE(m_->MountCgroup2fs()));

    auto controllers = root_->ReadControlFile("cgroup.controllers");
    if (controllers.ok()) {
      std::vector<std::string> list = absl::StrSplit(
          controllers.ValueOrDie(), absl::ByAnyChar(" \n"), absl::SkipEmpty());
      for (const std::string& ctrl : list) {
        ASSERT_NO_ERRNO(root_->WriteControlFile("cgroup.subtree_control",
                                                absl::StrCat("+", ctrl)));
      }
    }

    c_.emplace(ASSERT_NO_ERRNO_AND_VALUE(root_->CreateChild("test")));
  }

  const Cgroup& c() {
    Init();
    return *c_;
  }

  const Cgroup& root() {
    Init();
    return *root_;
  }

  // WaitForFrozen polls cg's cgroup.events until it reports "frozen
  // <want>" (want is 0 or 1), instead of assuming a fixed delay after
  // writing cgroup.freeze is enough. How long the requested state takes to
  // actually settle for every task in the cgroup depends on scheduling, and
  // a fixed sleep occasionally isn't enough, racing the caller's next
  // action (e.g. sending a signal that should be deferred by an
  // in-progress freeze) against a settle that hasn't finished yet.
  //
  // Once cgroup.events first reports the requested state, an additional
  // fixed settle margin is applied before returning. Empirically (measured
  // under nested virtualization on a native nested-VM nested test
  // environment), the first "frozen 1" observation in cgroup.events does
  // not itself guarantee every task has finished settling into the fully
  // quiesced kernel state that defers non-fatal signal delivery: polling
  // tightly and returning on the first observation raced into that
  // unsettled window *more* often than a generous fixed sleep did. This
  // margin is a native-environment scheduling-jitter accommodation for
  // *this test's* timing, not a statement about gVisor's own frozen-state
  // transition, which is a single lock-protected flag flip in the sentry
  // and doesn't have an analogous settle window (see the ptrace-platform
  // runs of these tests, which are deterministic).
  void WaitForFrozen(const Cgroup& cg, int want) {
    std::string want_str = absl::StrCat("frozen ", want);
    absl::Time deadline = absl::Now() + absl::Seconds(2);
    while (true) {
      auto events = cg.ReadControlFile("cgroup.events");
      if (events.ok() && absl::StrContains(events.ValueOrDie(), want_str)) {
        absl::SleepFor(absl::Milliseconds(300));
        return;
      }
      if (absl::Now() >= deadline) {
        EXPECT_THAT(events, IsPosixErrorOkAndHolds(HasSubstr(want_str)));
        return;
      }
      absl::SleepFor(absl::Milliseconds(10));
    }
  }

  void ExpectInotifyEvent(const FileDescriptor& fd) {
    struct pollfd pfd = {fd.get(), POLLIN, 0};
    ASSERT_GT(poll(&pfd, 1, 5000), 0);
    char buf[4096];
    EXPECT_GT(read(fd.get(), buf, sizeof(buf)), 0);
  }

  void ExpectNoInotifyEvent(const FileDescriptor& fd) {
    struct pollfd pfd = {fd.get(), POLLIN, 0};
    ASSERT_EQ(poll(&pfd, 1, 250), 0);
  }

  PosixErrorOr<FileDescriptor> GetInotifyFd(const Cgroup& cg,
                                            absl::string_view path) {
    FileDescriptor fd(inotify_init1(IN_NONBLOCK));
    if (inotify_add_watch(fd.get(), cg.Relpath(path).c_str(), IN_MODIFY) < 0) {
      return PosixError(errno);
    }
    return std::move(fd);
  }

  void ExpectPollEvent(const FileDescriptor& fd) {
    struct pollfd pfd = {fd.get(), POLLPRI, 0};
    EXPECT_THAT(poll(&pfd, 1, 0), SyscallSucceedsWithValue(1));
    EXPECT_TRUE(pfd.revents & POLLPRI);
    EXPECT_TRUE(pfd.revents & POLLERR);

    char buf[256];
    EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceeds());
    EXPECT_GT(read(fd.get(), buf, sizeof(buf)), 0);
    EXPECT_THAT(poll(&pfd, 1, 0), SyscallSucceedsWithValue(0));
  }

  void ExpectNoPollEvent(const FileDescriptor& fd) {
    struct pollfd pfd = {fd.get(), POLLPRI, 0};
    EXPECT_THAT(poll(&pfd, 1, 0), SyscallSucceedsWithValue(0));
  }

  // ReadMarker returns true if a progress marker becomes readable on fd within
  // timeout_ms. Poll-based, so it never blocks on an empty pipe.
  bool ReadMarker(int fd, int timeout_ms) {
    struct pollfd pfd = {fd, POLLIN, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) {
      return false;
    }
    char buf[64];
    return read(fd, buf, sizeof(buf)) > 0;
  }

  // DrainMarkers consumes any currently-available progress markers on fd
  // without blocking.
  void DrainMarkers(int fd) {
    while (true) {
      struct pollfd pfd = {fd, POLLIN, 0};
      if (poll(&pfd, 1, 0) <= 0) {
        break;
      }
      char buf[4096];
      if (read(fd, buf, sizeof(buf)) <= 0) {
        break;
      }
    }
  }

  void ExpectDefaultControlFiles(const Cgroup& cg, bool is_root = false) {
    EXPECT_THAT(Exists(cg.Relpath("cgroup.procs")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.controllers")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.subtree_control")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.max.descendants")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.max.depth")),
                IsPosixErrorOkAndHolds(true));
    EXPECT_THAT(Exists(cg.Relpath("cgroup.stat")),
                IsPosixErrorOkAndHolds(true));
    if (!is_root) {
      EXPECT_THAT(Exists(cg.Relpath("cgroup.events")),
                  IsPosixErrorOkAndHolds(true));
      EXPECT_THAT(Exists(cg.Relpath("cgroup.type")),
                  IsPosixErrorOkAndHolds(true));
      EXPECT_THAT(Exists(cg.Relpath("cgroup.kill")),
                  IsPosixErrorOkAndHolds(true));
    }
  }

 protected:
  std::optional<Mounter> m_;
  std::optional<Cgroup> root_;
  std::optional<Cgroup> c_;
};

TEST(Cgroup2, SysFsCgroupAlreadyMounted) {
  SKIP_IF(!IsRunningOnGvisor());
  // On gVisor, this test runs with a flag that pre-mounts cgroup2fs at
  // /sys/fs/cgroup. We verify that it is indeed already mounted.
  struct statfs fs;
  ASSERT_EQ(statfs("/sys/fs/cgroup", &fs), 0);
  EXPECT_EQ(fs.f_type, CGROUP2_SUPER_MAGIC);
}

TEST_F(Cgroup2Test, RootControlFilesPopulated) {
  ExpectDefaultControlFiles(root(), /*is_root=*/true);
}

TEST_F(Cgroup2Test, Create) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child1"));
  EXPECT_THAT(Exists(child.Path()), IsPosixErrorOkAndHolds(true));
  ExpectDefaultControlFiles(child, /*is_root=*/false);

  // Defaults.
  EXPECT_THAT(child.ReadControlFile("cgroup.type"),
              IsPosixErrorOkAndHolds(HasSubstr("domain")));
  EXPECT_THAT(child.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Eq("")));
  EXPECT_THAT(child.ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 0")));

  // No tasks.
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.empty());
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
}

TEST_F(Cgroup2Test, MkdirWithPermissions) {
  std::string child_path = JoinPath(c().Path(), "child");
  ASSERT_NO_ERRNO(Mkdir(child_path, 0444));

  const struct stat s1 = ASSERT_NO_ERRNO_AND_VALUE(Stat(child_path));
  EXPECT_THAT(s1.st_mode, PermissionIs(0444));
  EXPECT_TRUE(S_ISDIR(s1.st_mode));
}

TEST_F(Cgroup2Test, CannotRenameControlFile) {
  EXPECT_THAT(
      rename(c().Relpath("cgroup.procs").c_str(), c().Relpath("foo").c_str()),
      SyscallFailsWithErrno(EPERM));
}

TEST_F(Cgroup2Test, CannotUmountWithOpenFD) {
  FileDescriptor opened_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(root().Relpath("cgroup.procs"), O_RDONLY));
  EXPECT_THAT(umount2(root().Path().c_str(), 0), SyscallFailsWithErrno(EBUSY));
}

TEST_F(Cgroup2Test, CannotMountOverBusy) {
  EXPECT_THAT(Mount("none", root().Path(), "cgroup2", 0, "", 0),
              PosixErrorIs(EBUSY));
}

TEST_F(Cgroup2Test, DestroyConstraints) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));

  // Cannot destroy a cgroup node that has a live sub-directory.
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  EXPECT_THAT(parent.Delete(), PosixErrorIs(EBUSY));

  // Cannot destroy a cgroup node with a live attached process.
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_THAT(child.Delete(), PosixErrorIs(EBUSY));

  // Destroy successfully once leaf node is empty.
  ASSERT_NO_ERRNO(root().Enter(getpid()));
  clean.Release();
  EXPECT_NO_ERRNO(child.Delete());
  EXPECT_NO_ERRNO(parent.Delete());
}

TEST_F(Cgroup2Test, CloneIntoCgroupPermFail) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  FileDescriptor cgroup_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), O_RDONLY | O_DIRECTORY));

  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP;
  args.cgroup = cgroup_fd.get();
  args.exit_signal = SIGCHLD;

  ScopedThread([&] {
    const uid_t nobody = 65534;
    ASSERT_THAT(syscall(SYS_setresuid, nobody, nobody, nobody),
                SyscallSucceeds());

    pid_t pid = clone3(&args, sizeof(args));
    if (pid == 0) {
      _exit(0);
    } else if (pid > 0) {
      int status;
      waitpid(pid, &status, 0);
    }
    EXPECT_THAT(pid, SyscallFailsWithErrno(EACCES));
  }).Join();
}

TEST_F(Cgroup2Test, DelegatedCgroupOwnership) {
  // Goferfs does not support traversing path lookups to the nested cgroup2fs
  // mountpoint for unprivileged users because parent temporary directories
  // under /tmp are created with mode 0700 owned by root.
  SKIP_IF(IsRunningOnGvisor() && ASSERT_NO_ERRNO_AND_VALUE(IsGoferfs(
                                     std::string(Dirname(root().Path())))));

  const uid_t nobody = 65534;
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  // Delegate the cgroup directory and its writeable files to nobody.
  ASSERT_THAT(chown(child.Path().c_str(), nobody, nobody), SyscallSucceeds());
  ASSERT_THAT(chown(child.Relpath("cgroup.procs").c_str(), nobody, nobody),
              SyscallSucceeds());
  ASSERT_THAT(
      chown(child.Relpath("cgroup.subtree_control").c_str(), nobody, nobody),
      SyscallSucceeds());

  ScopedThread([&] {
    ASSERT_THAT(syscall(SYS_setresgid, nobody, nobody, nobody),
                SyscallSucceeds());
    ASSERT_THAT(syscall(SYS_setresuid, nobody, nobody, nobody),
                SyscallSucceeds());

    // nobody should be able to create a nested sub-cgroup.
    std::string nested_path = JoinPath(child.Path(), "nobody_cchild");
    ASSERT_THAT(mkdir(nested_path.c_str(), 0755), SyscallSucceeds());

    // The sub-directory must be owned by nobody.
    struct stat st = {};
    ASSERT_THAT(stat(nested_path.c_str(), &st), SyscallSucceeds());
    EXPECT_EQ(st.st_uid, nobody);
    EXPECT_EQ(st.st_gid, nobody);

    // The control files inside the new sub-cgroup must also be owned by nobody.
    std::string nested_procs = JoinPath(nested_path, "cgroup.procs");
    struct stat file_st = {};
    ASSERT_THAT(stat(nested_procs.c_str(), &file_st), SyscallSucceeds());
    EXPECT_EQ(file_st.st_uid, nobody);
    EXPECT_EQ(file_st.st_gid, nobody);

    // Enable a controller if one is available.
    std::string controllers =
        ASSERT_NO_ERRNO_AND_VALUE(child.ReadControlFile("cgroup.controllers"));
    std::vector<std::string> enabled_ctrls =
        absl::StrSplit(controllers, absl::ByAnyChar(" \n"), absl::SkipEmpty());
    if (enabled_ctrls.empty()) return;

    std::string control_path = child.Relpath("cgroup.subtree_control");
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(control_path, O_WRONLY));
    std::string cmd = absl::StrCat("+", enabled_ctrls[0]);
    ASSERT_THAT(write(fd.get(), cmd.data(), cmd.size()),
                SyscallSucceedsWithValue(cmd.size()));

    // The newly generated controller file inside the nested cgroup
    // directory must also be owned by nobody.
    std::string nested_ctrl_file =
        JoinPath(nested_path, absl::StrCat(enabled_ctrls[0], ".max"));
    if (Exists(nested_ctrl_file).ValueOrDie()) {
      struct stat ctrl_st = {};
      ASSERT_THAT(stat(nested_ctrl_file.c_str(), &ctrl_st), SyscallSucceeds());
      EXPECT_EQ(ctrl_st.st_uid, nobody);
      EXPECT_EQ(ctrl_st.st_gid, nobody);
    }
  });
}

TEST_F(Cgroup2Test, CloneIntoCgroup) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  FileDescriptor cgroup_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), O_RDONLY | O_DIRECTORY));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP;

  args.cgroup = -1;
  EXPECT_THAT(clone3(&args, sizeof(args)), SyscallFailsWithErrno(EINVAL));
  args.cgroup = fds[0];
  EXPECT_THAT(clone3(&args, sizeof(args)), SyscallFailsWithErrno(EBADF));

  args.cgroup = cgroup_fd.get();
  args.exit_signal = SIGCHLD;
  pid_t pid = clone3(&args, sizeof(args));
  ASSERT_THAT(pid, SyscallSucceeds());
  if (pid == 0) {
    close(wfd.get());
    char buf;
    read(rfd.get(), &buf, 1);
    _exit(0);
  }
  rfd.reset();

  // Verify that the cgroup's procs file has our child too.
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.contains(pid));

  // Signal child to exit.
  wfd.reset();
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(Cgroup2Test, CloneIntoDeletedCgroup) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  FileDescriptor cgroup_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), O_RDONLY | O_DIRECTORY));

  ASSERT_NO_ERRNO(child.Delete());

  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP;
  args.cgroup = cgroup_fd.get();
  args.exit_signal = SIGCHLD;

  EXPECT_THAT(clone3(&args, sizeof(args)), SyscallFailsWithErrno(ENOENT));
}

// TODO(b/524293138): Add a variant for threaded controllers when threaded
// cgroups are supported. Currently gVisor behaves as if all controllers
// are domain controllers.
TEST_F(Cgroup2Test, CloneIntoCgroupWithControllersIsDisallowed) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "memory"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));

  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+memory"));

  FileDescriptor parent_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent.Path(), O_RDONLY | O_DIRECTORY));

  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP;
  args.cgroup = parent_fd.get();
  args.exit_signal = SIGCHLD;

  EXPECT_THAT(clone3(&args, sizeof(args)), SyscallFailsWithErrno(EBUSY));
}

TEST_F(Cgroup2Test, CloneIntoCgroupBypassesParentLimit) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup target = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("target"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("pids.max", "1"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  FileDescriptor target_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(target.Path(), O_RDONLY | O_DIRECTORY));

  pid_t pid = fork();
  if (pid == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }

    // Fork must fail because we were placed in the `parent` cgroup which has a
    // limit of 1 process.
    pid_t normal_pid = fork();
    if (normal_pid > 0) {
      _exit(2);
    }

    // But clone3(CLONE_INTO_CGROUP) into `target` should succeed.
    clone_args args = {};
    args.flags = CLONE_INTO_CGROUP;
    args.cgroup = target_fd.get();
    args.exit_signal = SIGCHLD;
    pid_t clone_pid = clone3(&args, sizeof(args));
    if (clone_pid < 0) {
      _exit(3);
    } else if (clone_pid == 0) {
      _exit(0);
    }

    // Reap grandchild and relay errors.
    int status;
    if (waitpid(clone_pid, &status, 0) != clone_pid) {
      _exit(4);
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      _exit(5);
    }
    _exit(0);
  }

  rfd.reset();
  ASSERT_GT(pid, 0);

  // Make `pid` the sole resident of `parent`.
  ASSERT_NO_ERRNO(parent.Enter(pid));
  // And allow the child process to proceed.
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(Cgroup2Test, PermChecksUseOpenTimeUserNs) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  FileDescriptor cgroup_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), O_RDONLY | O_DIRECTORY));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Clone into a new user namespace.
  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP | CLONE_NEWUSER;
  args.cgroup = cgroup_fd.get();
  args.exit_signal = SIGCHLD;

  pid_t pid = clone3(&args, sizeof(args));
  if (pid == 0) {
    close(wfd.get());
    char buf;
    read(rfd.get(), &buf, 1);
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  // Signal child to exit.
  wfd.reset();
  rfd.reset();

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(Cgroup2Test, CannotEnableControllerDisabledInParent) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  EXPECT_THAT(parent.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Not(HasSubstr("pids"))));

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  EXPECT_THAT(child.WriteControlFile("cgroup.subtree_control", "+pids"),
              PosixErrorIs(ENOENT));
}

TEST_F(Cgroup2Test, CannotDisableControllerEnabledInChild) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "+pids"));
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "-pids"),
              PosixErrorIs(EBUSY));

  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "-pids"));
  EXPECT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "-pids"));
}

TEST_F(Cgroup2Test, SubtreeControlPids) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // Once we enabled "pids" in the parent...
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  auto clean = Cleanup([&] {
    c().WriteControlFile("cgroup.subtree_control", "-pids").IgnoreError();
  });
  // ...it becomes available in the child.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));
  ExpectDefaultControlFiles(child);
  EXPECT_THAT(Exists(child.Relpath("pids.max")), IsPosixErrorOkAndHolds(true));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(::testing::HasSubstr("pids")));

  // Invalid writes to the subtree_control file must fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "+garbage"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "pids"),
              PosixErrorIs(EINVAL));
  // Attempting to write to the read-only cgroup.controllers list must fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.controllers", "+pids"),
              PosixErrorIs(EINVAL));

  // Disabling a controller in the parent makes it unavailable in the child.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "-pids"));
  EXPECT_THAT(Exists(child.Relpath("pids.max")), IsPosixErrorOkAndHolds(false));
  EXPECT_THAT(child.ReadControlFile("cgroup.controllers"),
              IsPosixErrorOkAndHolds(Not(HasSubstr("pids"))));
}

TEST_F(Cgroup2Test, PidsEnforcement) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);
  ASSERT_NO_ERRNO(child.WriteControlFile("pids.max", "1"));

  FileDescriptor event_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("pids.events"), O_RDONLY));
  FileDescriptor event_local_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(child.Relpath("pids.events.local"), O_RDONLY));
  // The fds are born ready. ExpectPollEvent will sync to make it unready.
  ExpectPollEvent(event_fd);
  ExpectPollEvent(event_local_fd);

  FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(child, "pids.events"));
  FileDescriptor inotify_local_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(child, "pids.events.local"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);
  constexpr int kCantFork = 102;
  pid_t pid = fork();
  if (pid == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    pid_t grand_pid = fork();
    int exit_code = kCantFork;
    if (grand_pid >= 0) {
      exit_code = 3;
      if (grand_pid == 0) {
        _exit(0);
      }
      waitpid(grand_pid, nullptr, 0);
    }
    _exit(exit_code);
  }
  rfd.reset();
  ASSERT_GT(pid, 0);

  ASSERT_NO_ERRNO(child.Enter(pid));
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), kCantFork);

  ExpectInotifyEvent(inotify_fd);
  ExpectInotifyEvent(inotify_local_fd);
  ExpectPollEvent(event_fd);
  ExpectPollEvent(event_local_fd);

  EXPECT_THAT(child.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("0\n"));
  EXPECT_THAT(child.ReadControlFile("pids.peak"),
              IsPosixErrorOkAndHolds("1\n"));
  EXPECT_THAT(child.ReadControlFile("pids.events"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(child.ReadControlFile("pids.events.local"),
              IsPosixErrorOkAndHolds("max 1\n"));
}

TEST_F(Cgroup2Test, PidsEnforcementLayered) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup grand_child =
      ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("grand_child"));

  constexpr int kCantForkFirstHalf = 104;
  constexpr int kCantForkSecondHalf = 106;
  constexpr int kInternalError = 105;

  // Part 1: `c()` has the more restrictive controller.
  ASSERT_NO_ERRNO(c().WriteControlFile("pids.max", "3"));
  ASSERT_NO_ERRNO(grand_child.WriteControlFile("pids.max", "max"));

  FileDescriptor c_event_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(c().Relpath("pids.events"), O_RDONLY));
  FileDescriptor c_event_local_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(c().Relpath("pids.events.local"), O_RDONLY));
  FileDescriptor gc_event_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(grand_child.Relpath("pids.events"), O_RDONLY));
  FileDescriptor gc_event_local_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(grand_child.Relpath("pids.events.local"), O_RDONLY));
  ExpectPollEvent(c_event_fd);
  ExpectPollEvent(c_event_local_fd);
  ExpectPollEvent(gc_event_fd);
  ExpectPollEvent(gc_event_local_fd);

  FileDescriptor c_inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(c(), "pids.events"));
  FileDescriptor c_inotify_local_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(c(), "pids.events.local"));
  FileDescriptor gc_inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(grand_child, "pids.events"));
  FileDescriptor gc_inotify_local_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(grand_child, "pids.events.local"));

  // "p2c" is parent-to-child, "c2p" is child-to-parent.
  // The "1" refers to the first half of the test.
  int p2c1[2], c2p1[2];
  ASSERT_THAT(pipe(p2c1), SyscallSucceeds());
  ASSERT_THAT(pipe(c2p1), SyscallSucceeds());
  FileDescriptor p2c_r1(p2c1[0]), p2c_w1(p2c1[1]);
  FileDescriptor c2p_r1(c2p1[0]), c2p_w1(c2p1[1]);

  pid_t pid1 = fork();
  if (pid1 == 0) {
    p2c_w1.CloseSignalSafe();
    c2p_r1.CloseSignalSafe();
    char token;
    if (read(p2c_r1.get(), &token, 1) <= 0) _exit(1);

    pid_t p1 = fork();
    if (p1 == 0) {
      read(p2c_r1.get(), &token, 1);
      _exit(0);
    }
    pid_t p2 = fork();
    if (p2 == 0) {
      read(p2c_r1.get(), &token, 1);
      _exit(0);
    }

    int exit_code = kCantForkFirstHalf;
    pid_t p3 = fork();
    if (p3 >= 0) {
      exit_code = kInternalError;
      if (p3 == 0) _exit(0);
      kill(p3, SIGKILL);
      waitpid(p3, nullptr, 0);
    } else if (errno != EAGAIN) {
      exit_code = kInternalError;
    }

    write(c2p_w1.get(), "x", 1);
    read(p2c_r1.get(), &token, 1);
    if (p1 > 0) waitpid(p1, nullptr, 0);
    if (p2 > 0) waitpid(p2, nullptr, 0);
    _exit(exit_code);
  }
  p2c_r1.reset();
  c2p_w1.reset();
  ASSERT_GT(pid1, 0);

  ASSERT_NO_ERRNO(grand_child.Enter(pid1));
  ASSERT_THAT(write(p2c_w1.get(), "x", 1), SyscallSucceeds());
  char token;
  EXPECT_GT(read(c2p_r1.get(), &token, 1), 0);

  ExpectInotifyEvent(c_inotify_fd);
  ExpectPollEvent(c_event_fd);
  ExpectInotifyEvent(c_inotify_local_fd);
  ExpectPollEvent(c_event_local_fd);

  ExpectNoInotifyEvent(gc_inotify_fd);
  ExpectNoPollEvent(gc_event_fd);
  ExpectNoInotifyEvent(gc_inotify_local_fd);
  ExpectNoPollEvent(gc_event_local_fd);

  EXPECT_THAT(c().ReadControlFile("pids.events"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(c().ReadControlFile("pids.events.local"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(c().ReadControlFile("pids.peak"), IsPosixErrorOkAndHolds("3\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.events"),
              IsPosixErrorOkAndHolds("max 0\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.events.local"),
              IsPosixErrorOkAndHolds("max 0\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.peak"),
              IsPosixErrorOkAndHolds("4\n"));

  // Write three bytes to unblock the three processes.
  ASSERT_THAT(write(p2c_w1.get(), "xxx", 3), SyscallSucceeds());

  int status;
  ASSERT_EQ(waitpid(pid1, &status, 0), pid1);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), kCantForkFirstHalf);
  EXPECT_THAT(c().ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("0\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("0\n"));

  // Part 2: `grand_child` has the more restrictive controller.
  ASSERT_NO_ERRNO(c().WriteControlFile("pids.max", "max"));
  ASSERT_NO_ERRNO(grand_child.WriteControlFile("pids.max", "3"));

  int p2c2[2], c2p2[2];
  ASSERT_THAT(pipe(p2c2), SyscallSucceeds());
  ASSERT_THAT(pipe(c2p2), SyscallSucceeds());
  FileDescriptor p2c_r2(p2c2[0]), p2c_w2(p2c2[1]);
  FileDescriptor c2p_r2(c2p2[0]), c2p_w2(c2p2[1]);

  pid_t pid2 = fork();
  if (pid2 == 0) {
    p2c_w2.CloseSignalSafe();
    c2p_r2.CloseSignalSafe();
    char token2;
    if (read(p2c_r2.get(), &token2, 1) <= 0) _exit(1);

    pid_t p1 = fork();
    if (p1 == 0) {
      read(p2c_r2.get(), &token2, 1);
      _exit(0);
    }
    pid_t p2 = fork();
    if (p2 == 0) {
      read(p2c_r2.get(), &token2, 1);
      _exit(0);
    }

    int exit_code = kCantForkSecondHalf;
    pid_t p3 = fork();
    if (p3 >= 0) {
      exit_code = kInternalError;
      if (p3 == 0) _exit(0);
      kill(p3, SIGKILL);
      waitpid(p3, nullptr, 0);
    } else if (errno != EAGAIN) {
      exit_code = kInternalError;
    }

    write(c2p_w2.get(), "x", 1);
    read(p2c_r2.get(), &token2, 1);
    if (p1 > 0) waitpid(p1, nullptr, 0);
    if (p2 > 0) waitpid(p2, nullptr, 0);
    _exit(exit_code);
  }
  p2c_r2.reset();
  c2p_w2.reset();
  ASSERT_GT(pid2, 0);

  ASSERT_NO_ERRNO(grand_child.Enter(pid2));
  ASSERT_THAT(write(p2c_w2.get(), "x", 1), SyscallSucceeds());
  EXPECT_GT(read(c2p_r2.get(), &token, 1), 0);

  ExpectInotifyEvent(c_inotify_fd);
  ExpectPollEvent(c_event_fd);
  ExpectNoInotifyEvent(c_inotify_local_fd);
  ExpectNoPollEvent(c_event_local_fd);

  ExpectInotifyEvent(gc_inotify_fd);
  ExpectPollEvent(gc_event_fd);
  ExpectInotifyEvent(gc_inotify_local_fd);
  ExpectPollEvent(gc_event_local_fd);

  EXPECT_THAT(grand_child.ReadControlFile("pids.events"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.events.local"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(grand_child.ReadControlFile("pids.peak"),
              IsPosixErrorOkAndHolds("4\n"));

  EXPECT_THAT(c().ReadControlFile("pids.events"),
              IsPosixErrorOkAndHolds("max 2\n"));
  EXPECT_THAT(c().ReadControlFile("pids.events.local"),
              IsPosixErrorOkAndHolds("max 1\n"));
  EXPECT_THAT(c().ReadControlFile("pids.peak"), IsPosixErrorOkAndHolds("3\n"));

  ASSERT_THAT(write(p2c_w2.get(), "xxx", 3), SyscallSucceeds());
  ASSERT_EQ(waitpid(pid2, &status, 0), pid2);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), kCantForkSecondHalf);
}

// A task already in a cgroup when the pids controller is enabled over it must
// be charged to the new controller, and migrating it away afterward must
// drain pids.current to 0, not -1.
TEST_F(Cgroup2Test, PidsChargesPreexistingTasksOnEnable) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));

  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("pids_pre"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));
  Cgroup sibling = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("sibling"));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);
  pid_t pid = fork();
  if (pid == 0) {
    close(wfd.get());
    char token;
    (void)read(rfd.get(), &token, 1);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  rfd.reset();

  // The task enters child before child has a pids controller.
  ASSERT_NO_ERRNO(child.Enter(pid));

  // Enabling +pids must charge the pre-existing task to child's new
  // controller.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.subtree_control", "+pids"));
  EXPECT_THAT(child.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("1\n"));
  EXPECT_THAT(sibling.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("0\n"));

  // Migrating the task away must drain child to 0.
  ASSERT_NO_ERRNO(sibling.Enter(pid));
  EXPECT_THAT(child.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("0\n"));
  EXPECT_THAT(sibling.ReadControlFile("pids.current"),
              IsPosixErrorOkAndHolds("1\n"));

  wfd.reset();
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, PidsMigrationAllowsBreaches) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);
  ASSERT_NO_ERRNO(child.WriteControlFile("pids.max", "0"));

  pid_t pid = fork();
  if (pid == 0) {
    pause();
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  auto clean = Cleanup([&pid] {
    kill(pid, SIGKILL);
    int status;
    waitpid(pid, &status, 0);
  });

  // Attempt to migrate the child to the constrained cgroup should succeed
  // even though we are breaching pids.max.
  //
  // "Organisational operations are not blocked by cgroup policies, so it is
  // possible to have pids.current > pids.max."
  ASSERT_NO_ERRNO(child.Enter(pid));
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.contains(pid));
}

// TODO(b/524293138): Add a variant for threaded controllers when threaded
// cgroups are supported. Currently gVisor behaves as if all controllers
// are domain controllers.
TEST_F(Cgroup2Test, NoInternalProcesses) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "memory"));
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));
  auto clean_mem = Cleanup([&] {
    c().WriteControlFile("cgroup.subtree_control", "-memory").IgnoreError();
  });
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // A cgroup may contain both member child cgroups and member processes
  // as long as no controllers are enabled in its subtree_control.
  ASSERT_THAT(parent.ReadControlFile("cgroup.subtree_control"),
              IsPosixErrorOkAndHolds(Eq("")));
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(parent.Enter(getpid()));

  // Attempting to subsequently enable any resource controllers while
  // member processes exist should fail.
  EXPECT_THAT(parent.WriteControlFile("cgroup.subtree_control", "+memory"),
              PosixErrorIs(EBUSY));

  // Moving the process down into the sub-cgroup renders the parent empty,
  // allowing us to enable controllers in the parent.
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_TRUE(
      parent.WriteControlFile("cgroup.subtree_control", "+memory").ok());

  // Finally, moving the process back up into the parent is now
  // strictly denied by the rule since subtree_control is active/non-empty.
  EXPECT_THAT(parent.Enter(getpid()), PosixErrorIs(EBUSY));
}

TEST_F(Cgroup2Test, AttachNonExistentProc) {
  constexpr pid_t kNonExistentPid = 99999999;
  EXPECT_THAT(c().WriteIntegerControlFile("cgroup.procs", kNonExistentPid),
              PosixErrorIs(ESRCH));
}

TEST_F(Cgroup2Test, PIDZeroMovesSelf) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.WriteIntegerControlFile("cgroup.procs", 0));

  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_TRUE(procs.contains(getpid()));

  std::string content;
  ASSERT_NO_ERRNO(GetContents("/proc/self/cgroup", &content));
  EXPECT_THAT(content, HasSubstr("0::/test/child\n"));
}

TEST_F(Cgroup2Test, TaskMigration) {
  Cgroup src = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("src"));
  ExpectDefaultControlFiles(src);
  Cgroup dst = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("dst"));
  ExpectDefaultControlFiles(dst);

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(src.Enter(getpid()));
  EXPECT_THAT(src.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  EXPECT_THAT(dst.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  EXPECT_NO_ERRNO(dst.Enter(getpid()));
  EXPECT_THAT(src.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
  EXPECT_THAT(dst.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
}

TEST_F(Cgroup2Test, CgroupDotEvents) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  FileDescriptor event_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("cgroup.events"), O_RDONLY));
  ExpectPollEvent(event_fd);

  FileDescriptor inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(child, "cgroup.events"));

  int fds1[2], fds2[2];
  ASSERT_THAT(pipe(fds1), SyscallSucceeds());
  ASSERT_THAT(pipe(fds2), SyscallSucceeds());
  FileDescriptor rfd1(fds1[0]);
  FileDescriptor wfd1(fds1[1]);
  FileDescriptor rfd2(fds2[0]);
  FileDescriptor wfd2(fds2[1]);

  pid_t pid1 = fork();
  if (pid1 == 0) {
    close(wfd1.get());
    char token;
    if (read(rfd1.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid1, 0);
  rfd1.reset();

  pid_t pid2 = fork();
  if (pid2 == 0) {
    close(wfd2.get());
    char token;
    if (read(rfd2.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  rfd2.reset();
  ASSERT_GT(pid2, 0);

  // Enter the cgroup: should trigger a populate event.
  ASSERT_NO_ERRNO(child.Enter(pid1));
  ExpectInotifyEvent(inotify_fd);
  ExpectPollEvent(event_fd);
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));

  // Enter a second process, should not trigger another populate event.
  ASSERT_NO_ERRNO(child.Enter(pid2));
  ExpectNoInotifyEvent(inotify_fd);
  ExpectNoPollEvent(event_fd);

  // Instruct task 1 to exit. Because task 2 is still alive, no depopulate event
  // should fire.
  ASSERT_THAT(write(wfd1.get(), "x", 1), SyscallSucceeds());
  wfd1.reset();
  ExpectNoInotifyEvent(inotify_fd);
  ExpectNoPollEvent(event_fd);

  // Instruct task 2 to also exit.
  ASSERT_THAT(write(wfd2.get(), "x", 1), SyscallSucceeds());
  wfd2.reset();
  // Now the depopulate event should fire.
  ExpectInotifyEvent(inotify_fd);
  ExpectPollEvent(event_fd);
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  // Reap the zombies.
  int status;
  ASSERT_EQ(waitpid(pid1, &status, 0), pid1);
  EXPECT_TRUE(WIFEXITED(status));
  ASSERT_EQ(waitpid(pid2, &status, 0), pid2);
  EXPECT_TRUE(WIFEXITED(status));
}

// CgroupDotEventsFrozenPollWakesOnBothTransitions verifies that poll(POLLPRI)
// on cgroup.events actually wakes a blocked waiter -- not merely reflects the
// correct value once polled -- on both the frozen 0->1 (settle) and 1->0
// (thaw) transitions. This is the runtime proof of freeze()'s
// snapshot-compare-notify pass: c.frozen flipping does not by itself cross
// any pendingFreezeCount edge (e.g. thawing an already-fully-parked cgroup
// retracts no credit, since none is outstanding), so without that pass
// nothing would call eventsFile.Notify() for that transition at all, even
// though the frozen line genuinely changed.
TEST_F(Cgroup2Test, CgroupDotEventsFrozenPollWakesOnBothTransitions) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t target_pid = fork();
  if (target_pid == 0) {
    go_w.reset();
    // Block indefinitely; the parent never writes and holds the write end
    // open.
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(0);
    }
    _exit(0);
  }
  ASSERT_GT(target_pid, 0);
  go_r.reset();

  ASSERT_NO_ERRNO(child.Enter(target_pid));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  // ready_fds signals from the poller to the parent that it is about to
  // call poll() (once per expected transition, two total); result_fds
  // reports back whether that poll() call actually observed POLLPRI.
  int ready_fds[2], result_fds[2];
  ASSERT_THAT(pipe(ready_fds), SyscallSucceeds());
  ASSERT_THAT(pipe(result_fds), SyscallSucceeds());
  FileDescriptor ready_r(ready_fds[0]);
  FileDescriptor ready_w(ready_fds[1]);
  FileDescriptor result_r(result_fds[0]);
  FileDescriptor result_w(result_fds[1]);

  std::string events_path = child.Relpath("cgroup.events");

  pid_t poller_pid = fork();
  if (poller_pid == 0) {
    ready_r.reset();
    result_r.reset();

    // Deliberately avoid gtest ASSERT_*/EXPECT_* macros in this forked
    // child: they operate on this process's own copy of gtest's internal
    // state, not the one the actual test result is collected from.
    int event_fd = open(events_path.c_str(), O_RDONLY);
    if (event_fd < 0) {
      _exit(1);
    }

    for (int i = 0; i < 2; i++) {
      char one = 1;
      if (write(ready_w.get(), &one, 1) != 1) {
        _exit(1);
      }
      struct pollfd pfd = {event_fd, POLLPRI, 0};
      int ret = poll(&pfd, 1, /*timeout=*/5000);
      char result = (ret == 1 && (pfd.revents & POLLPRI)) ? 1 : 0;
      // Consume the readiness so the next poll() call detects the next
      // transition rather than immediately re-observing this one.
      char buf[256];
      lseek(event_fd, 0, SEEK_SET);
      read(event_fd, buf, sizeof(buf));
      if (write(result_w.get(), &result, 1) != 1) {
        _exit(1);
      }
    }
    _exit(0);
  }
  ASSERT_GT(poller_pid, 0);
  ready_w.reset();
  result_w.reset();

  // Wait for the poller to be about to block in poll(), then freeze: the
  // 0->1 transition.
  char buf;
  ASSERT_THAT(read(ready_r.get(), &buf, 1), SyscallSucceedsWithValue(1));
  absl::SleepFor(absl::Milliseconds(50));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));

  char result;
  ASSERT_THAT(read(result_r.get(), &result, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(result, 1)
      << "poll(POLLPRI) on cgroup.events did not wake on frozen 0->1";
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));

  // Wait for the poller's second poll() call, then thaw: the 1->0
  // transition.
  ASSERT_THAT(read(ready_r.get(), &buf, 1), SyscallSucceedsWithValue(1));
  absl::SleepFor(absl::Milliseconds(50));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));

  ASSERT_THAT(read(result_r.get(), &result, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(result, 1)
      << "poll(POLLPRI) on cgroup.events did not wake on frozen 1->0";
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  int status;
  ASSERT_EQ(waitpid(poller_pid, &status, 0), poller_pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);

  // Let the target exit normally.
  go_w.reset();
  ASSERT_EQ(waitpid(target_pid, &status, 0), target_pid);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, CgroupDotEventsPropagatesToAncestors) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  FileDescriptor parent_event_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(parent.Relpath("cgroup.events"), O_RDONLY));
  ExpectPollEvent(parent_event_fd);
  FileDescriptor parent_inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(parent, "cgroup.events"));
  FileDescriptor child_event_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("cgroup.events"), O_RDONLY));
  ExpectPollEvent(child_event_fd);
  FileDescriptor child_inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(child, "cgroup.events"));

  // Create the first child process `pid1`.
  int fds1[2];
  ASSERT_THAT(pipe(fds1), SyscallSucceeds());
  FileDescriptor rfd1(fds1[0]);
  FileDescriptor wfd1(fds1[1]);
  pid_t pid1 = fork();
  if (pid1 == 0) {
    close(wfd1.get());
    char token;
    if (read(rfd1.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid1, 0);
  rfd1.reset();

  // Put `pid1` into `child`: should trigger a populate event for both child and
  // parent cgroups.
  ASSERT_NO_ERRNO(child.Enter(pid1));
  ExpectInotifyEvent(child_inotify_fd);
  ExpectPollEvent(child_event_fd);
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  ExpectInotifyEvent(parent_inotify_fd);
  ExpectPollEvent(parent_event_fd);
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));

  // Create a second child process `pid2`.
  int fds2[2];
  ASSERT_THAT(pipe(fds2), SyscallSucceeds());
  FileDescriptor rfd2(fds2[0]);
  FileDescriptor wfd2(fds2[1]);
  pid_t pid2 = fork();
  if (pid2 == 0) {
    close(wfd2.get());
    char token;
    if (read(rfd2.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid2, 0);
  rfd2.reset();

  // Create a sibling cgroup `sibling`.
  Cgroup sibling = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("sibling"));
  FileDescriptor sibling_event_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(sibling.Relpath("cgroup.events"), O_RDONLY));
  ExpectPollEvent(sibling_event_fd);
  FileDescriptor sibling_inotify_fd =
      ASSERT_NO_ERRNO_AND_VALUE(GetInotifyFd(sibling, "cgroup.events"));

  // Put pid2 into sibling.
  ASSERT_NO_ERRNO(sibling.Enter(pid2));
  ExpectInotifyEvent(sibling_inotify_fd);
  ExpectPollEvent(sibling_event_fd);
  EXPECT_THAT(sibling.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  // Parent's count changed, but its overall state did not (was already > 0),
  // so it sees no event.
  ExpectNoInotifyEvent(parent_inotify_fd);
  ExpectNoPollEvent(parent_event_fd);

  // Instruct pid1 to exit.
  ASSERT_THAT(write(wfd1.get(), "x", 1), SyscallSucceeds());
  wfd1.reset();
  // Depopulate should fire on the first child.
  ExpectInotifyEvent(child_inotify_fd);
  ExpectPollEvent(child_event_fd);
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
  // But parent is still populated by sibling, so no event for parent.
  ExpectNoInotifyEvent(parent_inotify_fd);
  ExpectNoPollEvent(parent_event_fd);

  // Instruct pid2 to exit.
  ASSERT_THAT(write(wfd2.get(), "x", 1), SyscallSucceeds());
  wfd2.reset();
  // Depopulate should fire on sibling.
  ExpectInotifyEvent(sibling_inotify_fd);
  ExpectPollEvent(sibling_event_fd);
  EXPECT_THAT(sibling.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
  // parent is finally empty, so it now it sees an event.
  ExpectInotifyEvent(parent_inotify_fd);
  ExpectPollEvent(parent_event_fd);
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  // Cleanup.
  int status;
  ASSERT_EQ(waitpid(pid1, &status, 0), pid1);
  EXPECT_TRUE(WIFEXITED(status));
  ASSERT_EQ(waitpid(pid2, &status, 0), pid2);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, CgroupDotEventsPerFDPollReadiness) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  FileDescriptor event_fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("cgroup.events"), O_RDONLY));
  FileDescriptor event_fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("cgroup.events"), O_RDONLY));

  // A read clears the initial unsynced poll events for event_fd1.
  ExpectPollEvent(event_fd1);
  // event_fd2 remains triggered since poll state is per-fd.
  ExpectPollEvent(event_fd2);

  // Enter the cgroup.
  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));

  // Entry is observed by both fds. A seek and read on event_fd1 clears it.
  ExpectPollEvent(event_fd1);
  // event_fd2 remains triggered since poll state is per-fd.
  ExpectPollEvent(event_fd2);
}

TEST_F(Cgroup2Test, ZombieCgroupMembership) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  ExpectDefaultControlFiles(child);

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  rfd.reset();
  ASSERT_GT(pid, 0);
  ASSERT_NO_ERRNO(child.Enter(pid));

  // Zombify the child.
  ASSERT_THAT(write(wfd.get(), "x", 1), SyscallSucceeds());
  wfd.reset();
  siginfo_t info = {};
  ASSERT_THAT(waitid(P_PID, pid, &info, WEXITED | WNOWAIT), SyscallSucceeds());

  // A zombie process does not appear in cgroup.procs...
  auto procs = ASSERT_NO_ERRNO_AND_VALUE(child.Procs());
  EXPECT_FALSE(procs.contains(pid));
  // ...and thus cannot be moved to another cgroup: the write succeeds,
  // but the process is not moved, as shown by the subsequent read.
  EXPECT_NO_ERRNO(c().WriteIntegerControlFile("cgroup.procs", pid));
  auto root_procs = ASSERT_NO_ERRNO_AND_VALUE(c().Procs());
  EXPECT_FALSE(root_procs.contains(pid));

  // Delete the child cgroup.
  ASSERT_NO_ERRNO(child.Delete());
  // To see "deleted".
  std::string content;
  ASSERT_NO_ERRNO(
      GetContents(absl::StrFormat("/proc/%d/cgroup", pid), &content));
  EXPECT_THAT(content, HasSubstr(" (deleted)\n"));

  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
}

TEST_F(Cgroup2Test, DefaultFilePerms) {
  // cgroup.procs has a default permission of 0644.
  struct stat st;
  ASSERT_THAT(stat(c().Relpath("cgroup.procs").c_str(), &st),
              SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0644);
  // Userspace can change it.
  EXPECT_THAT(chmod(c().Relpath("cgroup.procs").c_str(), 0777),
              SyscallSucceeds());
  ASSERT_THAT(stat(c().Relpath("cgroup.procs").c_str(), &st),
              SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0777);

  // Dirs have 0755 by default.
  ASSERT_THAT(stat(c().Path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0755);
  // Userspace can change it.
  EXPECT_THAT(chmod(c().Path().c_str(), 0700), SyscallSucceeds());
  ASSERT_THAT(stat(c().Path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_mode & 0777, 0700);
}

TEST_F(Cgroup2Test, PermChecksUseOpenTimeCreds) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  auto clean = Cleanup([&] { ASSERT_NO_ERRNO(root().Enter(getpid())); });
  ASSERT_NO_ERRNO(parent.Enter(getpid()));

  // Grant unprivileged user read/write permissions to cgroup.procs.
  constexpr uid_t kFeebleEUID = 65534;
  ASSERT_THAT(chown(child.Relpath("cgroup.procs").c_str(), kFeebleEUID, -1),
              SyscallSucceeds());

  FileDescriptor child_procs_fd;
  absl::Notification ready;
  ScopedThread t([&]() {
    ASSERT_THAT(syscall(SYS_setresuid, kFeebleEUID, kFeebleEUID, kFeebleEUID),
                SyscallSucceeds());
    child_procs_fd.reset(open(child.Relpath("cgroup.procs").c_str(), O_RDWR));
    ready.Notify();
  });
  ready.WaitForNotification();
  SKIP_IF(child_procs_fd.get() < 0);

  // Open-time creds of the feeble subthread are not sufficient for access.
  EXPECT_THAT(write(child_procs_fd.get(), "0", 1),
              SyscallFailsWithErrno(EACCES));

  // But if the feeble uid owns the common ancestor, then the write succeeds.
  ASSERT_THAT(chown(parent.Relpath("cgroup.procs").c_str(), kFeebleEUID, -1),
              SyscallSucceeds());
  EXPECT_THAT(write(child_procs_fd.get(), "0", 1), SyscallSucceedsWithValue(1));
}

TEST_F(Cgroup2Test, KillTree) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // cgroup.kill only accepts "1".
  EXPECT_THAT(parent.WriteControlFile("cgroup.kill", "0"),
              PosixErrorIs(ERANGE));
  EXPECT_THAT(parent.WriteControlFile("cgroup.kill", "2"),
              PosixErrorIs(ERANGE));
  EXPECT_THAT(parent.WriteControlFile("cgroup.kill", "abc"),
              PosixErrorIs(EINVAL));

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  pid_t pid1 = fork();
  if (pid1 == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid1, 0);

  pid_t pid2 = fork();
  if (pid2 == 0) {
    close(wfd.get());
    char token;
    if (read(rfd.get(), &token, 1) <= 0) {
      _exit(1);
    }
    _exit(0);
  }
  ASSERT_GT(pid2, 0);
  rfd.reset();

  ASSERT_NO_ERRNO(parent.Enter(pid1));
  ASSERT_NO_ERRNO(child.Enter(pid2));

  // Writing 1 to cgroup.kill kills all descendant tasks across the entire tree.
  EXPECT_TRUE(parent.WriteControlFile("cgroup.kill", "1").ok());
  wfd.reset();

  int status;
  ASSERT_EQ(waitpid(pid1, &status, 0), pid1);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);

  ASSERT_EQ(waitpid(pid2, &status, 0), pid2);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);
}

// FreezeStopsAndResumesProgress verifies that writing 1 to cgroup.freeze stops
// a running process from making progress, and writing 0 resumes it.
TEST_F(Cgroup2Test, FreezeStopsAndResumesProgress) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  // cgroup.freeze starts at 0.
  EXPECT_THAT(child.ReadControlFile("cgroup.freeze"),
              IsPosixErrorOkAndHolds(HasSubstr("0")));

  // prog: child emits a marker per loop iteration; parent observes progress.
  int prog_fds[2];
  ASSERT_THAT(pipe(prog_fds), SyscallSucceeds());
  FileDescriptor prog_r(prog_fds[0]);
  FileDescriptor prog_w(prog_fds[1]);
  // go: parent tells the child to begin looping (after it's in the cgroup).
  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    prog_r.reset();
    go_w.reset();
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(1);
    }
    while (true) {
      if (write(prog_w.get(), "x", 1) != 1) {
        _exit(2);
      }
      usleep(10000);  // 10ms
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  prog_w.reset();
  go_r.reset();

  ASSERT_NO_ERRNO(child.Enter(pid));
  ASSERT_THAT(write(go_w.get(), "x", 1), SyscallSucceeds());

  // poll-based helpers avoid blocking on an empty pipe.
  auto read_marker = [&](int timeout_ms) -> bool {
    struct pollfd pfd = {prog_r.get(), POLLIN, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0) {
      return false;
    }
    char buf[64];
    return read(prog_r.get(), buf, sizeof(buf)) > 0;
  };
  auto drain = [&]() {
    while (true) {
      struct pollfd pfd = {prog_r.get(), POLLIN, 0};
      if (poll(&pfd, 1, 0) <= 0) {
        break;
      }
      char buf[4096];
      if (read(prog_r.get(), buf, sizeof(buf)) <= 0) {
        break;
      }
    }
  };

  // The child is running and making progress.
  ASSERT_TRUE(read_marker(5000));

  // Freeze: the child must stop making progress.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  EXPECT_THAT(child.ReadControlFile("cgroup.freeze"),
              IsPosixErrorOkAndHolds(HasSubstr("1")));

  // Let the freeze take effect, then drain any markers buffered before the
  // child parked.
  absl::SleepFor(absl::Milliseconds(100));
  drain();

  // No new markers arrive while frozen (~50 missed 10ms iterations).
  EXPECT_FALSE(read_marker(500));

  // Thaw: progress resumes.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));
  EXPECT_THAT(child.ReadControlFile("cgroup.freeze"),
              IsPosixErrorOkAndHolds(HasSubstr("0")));
  EXPECT_TRUE(read_marker(5000));

  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

// FrozenProcessKillableBySIGKILL verifies that a frozen process (parked in a
// killable internal stop) is still terminated by SIGKILL. This is the runtime
// proof of frozenStop.Killable().
TEST_F(Cgroup2Test, FrozenProcessKillableBySIGKILL) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    go_w.reset();
    // Block indefinitely; the parent never writes and holds the write end open.
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(0);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  go_r.reset();

  ASSERT_NO_ERRNO(child.Enter(pid));

  // Freeze and wait for the effective state to actually take hold.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  WaitForFrozen(child, 1);

  // A frozen task must still die on SIGKILL.
  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGKILL);
}

// FrozenProcessWakesAndDiesOnDefaultFatalSignal verifies that a frozen
// process (parked in a killable internal stop) is woken by a non-SIGKILL
// signal whose default disposition terminates the process, and that the
// resulting exit status reflects that specific signal (SIGTERM) rather than
// SIGKILL. This is the runtime proof that ThreadGroup.applySignalSideEffects's
// generalized wake-on-fatal-signal path only unblocks the stop, and does not
// reuse killLocked's SIGKILL-specific delivery/exit-status semantics.
TEST_F(Cgroup2Test, FrozenProcessWakesAndDiesOnDefaultFatalSignal) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    go_w.reset();
    // Block indefinitely with SIGTERM at its default disposition (no
    // handler installed); the parent never writes and holds the write end
    // open.
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(0);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  go_r.reset();

  ASSERT_NO_ERRNO(child.Enter(pid));

  // Freeze and wait for the effective state to actually take hold.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  WaitForFrozen(child, 1);

  // A frozen task must wake and die on a default-disposition SIGTERM, with
  // an exit status that reflects SIGTERM specifically, not SIGKILL.
  ASSERT_THAT(kill(pid, SIGTERM), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM);
}

// g_sigusr1FrozenHandledFd is the write end of a pipe that
// HandleSigusr1ForFrozenTest writes a token to when SIGUSR1 is actually
// delivered to (and handled by) the forked child in
// FrozenProcessDefersNonFatalSignalUntilThaw below. It is set by that child
// itself, immediately after fork() and before installing the handler, so it
// is only ever touched within that single forked, single-threaded child
// process.
int g_sigusr1FrozenHandledFd = -1;

void HandleSigusr1ForFrozenTest(int sig) {
  char token = 1;
  (void)write(g_sigusr1FrozenHandledFd, &token, 1);
}

// FrozenProcessDefersNonFatalSignalUntilThaw verifies that a frozen process
// (parked in a killable internal stop) does NOT dequeue and deliver a
// pending signal whose default disposition is not fatal -- specifically, a
// SIGUSR1 with a handler installed -- while frozen: the handler must not
// run, and the process must not exit. Once thawed, the same still-pending
// signal must then be delivered normally (the handler runs). This is the
// runtime proof of the peekPendingBit-gated ordering in
// runInterrupt.execute(): freeze must take effect before an already-pending,
// non-fatal signal is dequeued, and must never delay a signal whose default
// disposition is fatal (covered separately by
// FrozenProcessWakesAndDiesOnDefaultFatalSignal above).
TEST_F(Cgroup2Test, FrozenProcessDefersNonFatalSignalUntilThaw) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  int handled_fds[2];
  ASSERT_THAT(pipe(handled_fds), SyscallSucceeds());
  FileDescriptor handled_r(handled_fds[0]);
  FileDescriptor handled_w(handled_fds[1]);

  // ready_fds signals from the child to the parent that its sigaction(2)
  // call has actually completed, so the parent does not freeze the child
  // while SIGUSR1 is still SIG_DFL: a freeze that lands in that window would
  // make the wake-on-fatal-signal path correctly kill the child instead of
  // deferring the (not-yet-installed) handler, which is not what this test
  // means to exercise.
  int ready_fds[2];
  ASSERT_THAT(pipe(ready_fds), SyscallSucceeds());
  FileDescriptor ready_r(ready_fds[0]);
  FileDescriptor ready_w(ready_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    go_w.reset();
    handled_r.reset();
    ready_r.reset();
    g_sigusr1FrozenHandledFd = handled_w.release();

    struct sigaction sa = {};
    sa.sa_handler = HandleSigusr1ForFrozenTest;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // No SA_RESTART: the read() below must return EINTR on
                       // signal delivery so the child observes it and loops,
                       // rather than either exiting or silently swallowing
                       // delivery via a transparent restart.
    if (sigaction(SIGUSR1, &sa, nullptr) != 0) {
      _exit(1);
    }

    char ready_token = 1;
    if (write(ready_w.get(), &ready_token, 1) != 1) {
      _exit(1);
    }
    ready_w.reset();

    // Block indefinitely, waking on either signal delivery (EINTR, in which
    // case keep blocking) or the parent closing go_w (EOF), whichever comes
    // first. The parent never writes to go_w; it only closes it once the
    // test is done observing the handler's effect, to let this child exit.
    char token;
    ssize_t n;
    while ((n = read(go_r.get(), &token, 1)) < 0 && errno == EINTR) {
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  go_r.reset();
  handled_w.reset();
  ready_w.reset();

  // Wait for the child's sigaction(SIGUSR1, ...) to actually complete before
  // entering it into the cgroup and freezing it.
  char ready_token;
  ASSERT_THAT(read(ready_r.get(), &ready_token, 1),
              SyscallSucceedsWithValue(1));

  ASSERT_NO_ERRNO(child.Enter(pid));

  // Freeze and wait for the effective state to actually take hold.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  WaitForFrozen(child, 1);

  ASSERT_THAT(kill(pid, SIGUSR1), SyscallSucceeds());

  // While frozen, the handler must not run: poll the handled-pipe with a
  // bounded timeout and expect no data, and confirm the process is still
  // alive (not reaped) throughout.
  struct pollfd pfd = {.fd = handled_r.get(), .events = POLLIN};
  EXPECT_THAT(poll(&pfd, 1, /*timeout=*/500), SyscallSucceedsWithValue(0))
      << "SIGUSR1 handler ran (or the process exited) while frozen";
  EXPECT_EQ(waitpid(pid, nullptr, WNOHANG), 0)
      << "process exited while frozen";

  // Thaw. The still-pending SIGUSR1 must now be dequeued and delivered.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));
  absl::SleepFor(absl::Milliseconds(100));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  pfd = {.fd = handled_r.get(), .events = POLLIN};
  ASSERT_THAT(poll(&pfd, 1, /*timeout=*/5000), SyscallSucceedsWithValue(1))
      << "SIGUSR1 handler did not run after thaw";
  char token;
  EXPECT_THAT(read(handled_r.get(), &token, 1), SyscallSucceedsWithValue(1));

  // Let the child exit normally.
  go_w.reset();
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

// IgnoreSigusr1ForFatalRaceTest is installed as SIGUSR1's handler in
// FrozenProcessDiesOnFatalSignalWithLowerNumberedSignalPending below, purely
// so SIGUSR1's disposition isn't SIG_DFL (which would make it fatal too).
void IgnoreSigusr1ForFatalRaceTest(int sig) {}

// FrozenProcessDiesOnFatalSignalWithLowerNumberedSignalPending verifies that
// a frozen process wakes and dies on a fatal-by-default signal even when a
// lower-numbered, non-fatal signal was queued first. On Linux this races
// with the target's own scheduling and isn't guaranteed either way; gVisor
// deliberately guarantees the process dies, so this test is gVisor-only.
TEST_F(Cgroup2Test,
       FrozenProcessDiesOnFatalSignalWithLowerNumberedSignalPending) {
  SKIP_IF(!IsRunningOnGvisor());

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int ready_fds[2];
  ASSERT_THAT(pipe(ready_fds), SyscallSucceeds());
  FileDescriptor ready_r(ready_fds[0]);
  FileDescriptor ready_w(ready_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    ready_r.reset();

    struct sigaction sa = {};
    sa.sa_handler = IgnoreSigusr1ForFatalRaceTest;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, nullptr) != 0) {
      _exit(1);
    }

    char ready_token = 1;
    if (write(ready_w.get(), &ready_token, 1) != 1) {
      _exit(1);
    }
    ready_w.reset();

    // Block indefinitely; SIGTERM at its default disposition should
    // eventually kill this process.
    while (true) {
      pause();
    }
  }
  ASSERT_GT(pid, 0);
  ready_w.reset();
  // If the bug under test is present, the child never dies on its own; make
  // sure it doesn't outlive (or get left as a zombie by) this test.
  auto clean_pid = Cleanup([&] {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
  });

  // Wait for the child's sigaction(SIGUSR1, ...) to actually complete before
  // entering it into the cgroup and freezing it.
  char ready_token;
  ASSERT_THAT(read(ready_r.get(), &ready_token, 1),
              SyscallSucceedsWithValue(1));

  ASSERT_NO_ERRNO(child.Enter(pid));

  // Freeze and wait for the effective state to actually take hold.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  WaitForFrozen(child, 1);

  // Queue the lower-numbered, non-fatal signal first, then the
  // higher-numbered, fatal-by-default one.
  ASSERT_THAT(kill(pid, SIGUSR1), SyscallSucceeds());
  ASSERT_THAT(kill(pid, SIGTERM), SyscallSucceeds());

  // The frozen process must still die on SIGTERM. Poll with WNOHANG on a
  // bounded deadline instead of a blocking waitpid: if the fatal-signal gate
  // regresses to only inspecting the lowest-numbered pending signal, this
  // process never dies while frozen, and a blocking wait would hang forever.
  int status = 0;
  bool exited = false;
  const absl::Time deadline = absl::Now() + absl::Seconds(10);
  while (absl::Now() < deadline) {
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid) {
      exited = true;
      break;
    }
    ASSERT_EQ(ret, 0) << "waitpid failed: " << strerror(errno);
    absl::SleepFor(absl::Milliseconds(50));
  }
  ASSERT_TRUE(exited) << "frozen process did not die on SIGTERM within the "
                          "deadline -- a lower-numbered pending SIGUSR1 is "
                          "likely blocking the fatal-signal gate";
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM);
}

// FrozenProcessDefersCoreDumpSignalUntilThaw verifies that a core-dump-default
// signal (SIGQUIT) does not kill a frozen process -- it stays queued until
// thaw -- unlike a term-default signal (SIGTERM), which kills it immediately
// while still frozen. Linux's complete_signal() gates its fatal-wake fast
// path on !sig_kernel_coredump(sig): core-dump signals only ever reach
// get_signal()'s normal dequeue path, which a frozen task never runs until
// thaw.
TEST_F(Cgroup2Test, FrozenProcessDefersCoreDumpSignalUntilThaw) {
  // SIGQUIT: frozen, must not die until thaw.
  {
    Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("quit"));
    pid_t pid = fork();
    if (pid == 0) {
      while (true) {
        pause();
      }
    }
    ASSERT_GT(pid, 0);
    auto cleanup = Cleanup([&] {
      kill(pid, SIGKILL);
      waitpid(pid, nullptr, 0);
    });

    ASSERT_NO_ERRNO(child.Enter(pid));
    ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
    WaitForFrozen(child, 1);

    ASSERT_THAT(kill(pid, SIGQUIT), SyscallSucceeds());

    // Must not die while frozen; give it a full second to prove that.
    int status = 0;
    const absl::Time not_dead_deadline = absl::Now() + absl::Seconds(1);
    while (absl::Now() < not_dead_deadline) {
      ASSERT_THAT(waitpid(pid, &status, WNOHANG), SyscallSucceedsWithValue(0))
          << "SIGQUIT killed the frozen process before thaw, status = "
          << status;
      absl::SleepFor(absl::Milliseconds(50));
    }

    // Thaw: the queued SIGQUIT should now kill it. Poll with WNOHANG on a
    // bounded deadline rather than a blocking waitpid, so a regression here
    // fails loudly instead of hanging the test.
    ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));
    bool exited = false;
    const absl::Time dead_deadline = absl::Now() + absl::Seconds(10);
    while (absl::Now() < dead_deadline) {
      pid_t ret = waitpid(pid, &status, WNOHANG);
      if (ret == pid) {
        exited = true;
        break;
      }
      ASSERT_EQ(ret, 0) << "waitpid failed: " << strerror(errno);
      absl::SleepFor(absl::Milliseconds(50));
    }
    ASSERT_TRUE(exited) << "process did not die on the queued SIGQUIT after "
                            "thaw within the deadline";
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGQUIT);
  }

  // SIGTERM: frozen, must die immediately (comparison).
  {
    Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("term"));
    pid_t pid = fork();
    if (pid == 0) {
      while (true) {
        pause();
      }
    }
    ASSERT_GT(pid, 0);
    auto cleanup = Cleanup([&] {
      kill(pid, SIGKILL);
      waitpid(pid, nullptr, 0);
    });

    ASSERT_NO_ERRNO(child.Enter(pid));
    ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
    WaitForFrozen(child, 1);

    ASSERT_THAT(kill(pid, SIGTERM), SyscallSucceeds());

    int status = 0;
    bool exited = false;
    const absl::Time deadline = absl::Now() + absl::Seconds(10);
    while (absl::Now() < deadline) {
      pid_t ret = waitpid(pid, &status, WNOHANG);
      if (ret == pid) {
        exited = true;
        break;
      }
      ASSERT_EQ(ret, 0) << "waitpid failed: " << strerror(errno);
      absl::SleepFor(absl::Milliseconds(50));
    }
    ASSERT_TRUE(exited) << "SIGTERM did not kill the frozen process within "
                            "the deadline";
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGTERM);
  }
}

// FrozenCgroupNotThawedBySIGCONT verifies that sending SIGCONT to a member
// task of a frozen cgroup does not thaw it. SIGCONT's side effect of ending a
// job-control group-stop (ThreadGroup.applySignalSideEffectsLocked's sig ==
// linux.SIGCONT case, endGroupStopLocked) is specific to *groupStop; cgroup
// v2 freeze is a separate stop mechanism (frozenStop) with its own explicit
// thaw path (writing "0" to cgroup.freeze), and must not be conflated with
// job control -- matching Linux, where the cgroup v2 freezer likewise
// ignores SIGCONT.
TEST_F(Cgroup2Test, FrozenCgroupNotThawedBySIGCONT) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    go_w.reset();
    // Block indefinitely; the parent never writes and holds the write end
    // open.
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(0);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  go_r.reset();

  ASSERT_NO_ERRNO(child.Enter(pid));

  // Freeze and wait for the effective state to actually take hold.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  WaitForFrozen(child, 1);

  ASSERT_THAT(kill(pid, SIGCONT), SyscallSucceeds());

  // SIGCONT must not thaw the cgroup: give it a moment to (not) take
  // effect, then confirm it is still frozen and the process is still alive.
  absl::SleepFor(absl::Milliseconds(200));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")))
      << "SIGCONT thawed a frozen cgroup";
  EXPECT_EQ(waitpid(pid, nullptr, WNOHANG), 0)
      << "process exited despite SIGCONT not being fatal";

  // The explicit thaw path must still work afterward.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));
  WaitForFrozen(child, 0);

  // Let the child exit normally.
  go_w.reset();
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
}

// CgroupFreezeEffectiveStateAndPropagation verifies that the cgroup.events
// "frozen" line reflects the effective state (self or any ancestor), that
// freeze propagates to descendants, and that cgroup.freeze itself reports only
// the cgroup's own requested flag.
TEST_F(Cgroup2Test, CgroupFreezeEffectiveStateAndPropagation) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  // Initially nothing is frozen.
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  // Freeze the parent: effective state propagates to the child, but the child's
  // own cgroup.freeze flag stays 0.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.freeze", "1"));
  EXPECT_THAT(parent.ReadControlFile("cgroup.freeze"),
              IsPosixErrorOkAndHolds(HasSubstr("1")));
  EXPECT_THAT(child.ReadControlFile("cgroup.freeze"),
              IsPosixErrorOkAndHolds(HasSubstr("0")));
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));

  // Thaw the parent: effective state clears everywhere.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.freeze", "0"));
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  // Freeze only the child: the parent is unaffected.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "1"));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));
  EXPECT_THAT(parent.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.freeze", "0"));
}

// CgroupFreezeInvalidInput verifies input validation on cgroup.freeze.
TEST_F(Cgroup2Test, CgroupFreezeInvalidInput) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  // Matches Linux: an out-of-range integer is ERANGE, a non-integer is EINVAL.
  EXPECT_THAT(child.WriteControlFile("cgroup.freeze", "2"), PosixErrorIs(ERANGE));
  EXPECT_THAT(child.WriteControlFile("cgroup.freeze", "abc"),
              PosixErrorIs(EINVAL));
  EXPECT_TRUE(child.WriteControlFile("cgroup.freeze", "1").ok());
  EXPECT_TRUE(child.WriteControlFile("cgroup.freeze", "0").ok());
}

// FreezeAncestorStopsDescendantTasks proves task-level freeze propagation: a
// process in a descendant cgroup actually stops when an ancestor is frozen (not
// merely that cgroup.events reports "frozen 1").
TEST_F(Cgroup2Test, FreezeAncestorStopsDescendantTasks) {
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(parent.CreateChild("child"));

  int prog_fds[2];
  ASSERT_THAT(pipe(prog_fds), SyscallSucceeds());
  FileDescriptor prog_r(prog_fds[0]);
  FileDescriptor prog_w(prog_fds[1]);
  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    prog_r.reset();
    go_w.reset();
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(1);
    }
    while (true) {
      if (write(prog_w.get(), "x", 1) != 1) {
        _exit(2);
      }
      usleep(10000);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  prog_w.reset();
  go_r.reset();

  // The process lives in the descendant cgroup.
  ASSERT_NO_ERRNO(child.Enter(pid));
  ASSERT_THAT(write(go_w.get(), "x", 1), SyscallSucceeds());
  ASSERT_TRUE(ReadMarker(prog_r.get(), 5000));

  // Freeze the ANCESTOR: the descendant's process must stop.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.freeze", "1"));
  EXPECT_THAT(child.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));
  absl::SleepFor(absl::Milliseconds(100));
  DrainMarkers(prog_r.get());
  EXPECT_FALSE(ReadMarker(prog_r.get(), 500));

  // Thaw the ancestor: the descendant's process resumes.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cgroup.freeze", "0"));
  EXPECT_TRUE(ReadMarker(prog_r.get(), 5000));

  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

// FreezeSettledStateAccountsForGrandchildren regresses a counting bug in
// updatePendingFreeze: a cgroup can be unsettled for either of two reasons
// -- its own pendingFreezeCount, or a child's own unsettled subtree via
// nrUnsettledChildren -- but the ancestor walk only checked the first
// reason's transition, ignoring whether the second still held. In a
// W -> A -> B hierarchy with a task in A and a group-stopped task in B, A's
// own task parking (while B's hasn't) wrongly propagates "settled" past A
// up to W; once B's task eventually settles too, W's unsettled-child
// counter goes permanently negative, and W reports "frozen 1" immediately
// on every later freeze, before anything has actually parked.
TEST_F(Cgroup2Test, FreezeSettledStateAccountsForGrandchildren) {
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("a"));
  Cgroup b = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("b"));

  // a_pid: a plain progress-marking loop, entered directly into A.
  int a_prog_fds[2];
  ASSERT_THAT(pipe(a_prog_fds), SyscallSucceeds());
  FileDescriptor a_prog_r(a_prog_fds[0]);
  FileDescriptor a_prog_w(a_prog_fds[1]);
  int a_go_fds[2];
  ASSERT_THAT(pipe(a_go_fds), SyscallSucceeds());
  FileDescriptor a_go_r(a_go_fds[0]);
  FileDescriptor a_go_w(a_go_fds[1]);

  pid_t a_pid = fork();
  if (a_pid == 0) {
    a_prog_r.reset();
    a_go_w.reset();
    char token;
    if (read(a_go_r.get(), &token, 1) <= 0) {
      _exit(1);
    }
    while (true) {
      if (write(a_prog_w.get(), "x", 1) != 1) {
        _exit(2);
      }
      usleep(10000);
    }
  }
  ASSERT_GT(a_pid, 0);
  a_prog_w.reset();
  a_go_r.reset();

  // b_pid: a group-stopped task, entered directly into B.
  pid_t b_pid = fork();
  if (b_pid == 0) {
    raise(SIGSTOP);
    while (true) {
      pause();
    }
  }
  ASSERT_GT(b_pid, 0);

  auto cleanup = Cleanup([&] {
    kill(a_pid, SIGKILL);
    waitpid(a_pid, nullptr, 0);
    kill(b_pid, SIGKILL);
    waitpid(b_pid, nullptr, 0);
  });

  ASSERT_NO_ERRNO(a.Enter(a_pid));
  ASSERT_THAT(write(a_go_w.get(), "x", 1), SyscallSucceeds());
  ASSERT_TRUE(ReadMarker(a_prog_r.get(), 5000));

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(b_pid, &status, WUNTRACED),
              SyscallSucceedsWithValue(b_pid));
  ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << "status = " << status;
  ASSERT_NO_ERRNO(b.Enter(b_pid));

  // Freeze at the root. a_pid can and will actually park; b_pid,
  // group-stopped, cannot enter frozenStop until it's continued, so B --
  // and therefore A and the root -- must all stay unsettled the whole time
  // b_pid is stopped.
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.freeze", "1"));

  // Wait for a_pid to actually stop making progress (parked), not just for
  // freeze to have been requested.
  absl::SleepFor(absl::Milliseconds(200));
  DrainMarkers(a_prog_r.get());
  EXPECT_FALSE(ReadMarker(a_prog_r.get(), 500));

  // a_pid has parked; b_pid has not and cannot on its own. If A's
  // transition wrongly propagated past A without checking A's own
  // unsettled child (B), the root would already claim "frozen 1" here.
  EXPECT_THAT(a.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));
  EXPECT_THAT(c().ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")));

  // Let b_pid settle too, while still frozen: continuing it lets it
  // actually enter frozenStop. This must still propagate normally -- the
  // new guard only short-circuits while a child is unsettled, not once it
  // settles -- so both A (nrUnsettledChildren 1->0) and the root
  // (1->0, from A's own transition) must actually reach "frozen 1" here.
  ASSERT_THAT(kill(b_pid, SIGCONT), SyscallSucceeds());
  WaitForFrozen(a, 1);
  WaitForFrozen(c(), 1);

  // Thaw everything, then stop b_pid again and re-freeze. If the first
  // settle (a_pid parking behind an unsettled B) already corrupted the
  // root's unsettled-child counter, and b_pid's own settle then drove it
  // negative, the counter can no longer register any child's unsettled
  // state at all -- the root would immediately claim "frozen 1" here even
  // though b_pid, freshly stopped, has not parked again.
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.freeze", "0"));
  WaitForFrozen(c(), 0);

  ASSERT_THAT(kill(b_pid, SIGSTOP), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(waitpid)(b_pid, &status, WUNTRACED),
              SyscallSucceedsWithValue(b_pid));
  ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
      << "status = " << status;

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.freeze", "1"));
  EXPECT_THAT(c().ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 0")))
      << "root reported frozen before b_pid (freshly stopped) could have "
         "parked -- nrUnsettledChildren is stuck negative from an earlier "
         "settle";
}

// CloneIntoFrozenCgroupStartsFrozen verifies that a task born (via
// CLONE_INTO_CGROUP) directly into a frozen cgroup starts frozen and runs no
// application code until thawed. (A plain fork/CLONE_THREAD into a frozen group
// isn't reachable from within it — the creating task would already be frozen —
// so CLONE_INTO_CGROUP from an unfrozen parent is the testable birth case.)
TEST_F(Cgroup2Test, CloneIntoFrozenCgroupStartsFrozen) {
  Cgroup frozen_cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("frozen"));
  ASSERT_NO_ERRNO(frozen_cg.WriteControlFile("cgroup.freeze", "1"));
  FileDescriptor cgroup_fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(frozen_cg.Path(), O_RDONLY | O_DIRECTORY));

  int prog_fds[2];
  ASSERT_THAT(pipe(prog_fds), SyscallSucceeds());
  FileDescriptor prog_r(prog_fds[0]);
  FileDescriptor prog_w(prog_fds[1]);

  clone_args args = {};
  args.flags = CLONE_INTO_CGROUP;
  args.cgroup = cgroup_fd.get();
  args.exit_signal = SIGCHLD;
  pid_t pid = clone3(&args, sizeof(args));
  ASSERT_THAT(pid, SyscallSucceeds());
  if (pid == 0) {
    prog_r.reset();
    // Born into a frozen cgroup: this loop must not run until thawed.
    while (true) {
      if (write(prog_w.get(), "x", 1) != 1) {
        _exit(2);
      }
      usleep(10000);
    }
    _exit(0);
  }
  prog_w.reset();

  // The child was born frozen: no progress markers appear.
  EXPECT_FALSE(ReadMarker(prog_r.get(), 500));
  EXPECT_THAT(frozen_cg.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("frozen 1")));

  // Thaw: the child now runs for the first time.
  ASSERT_NO_ERRNO(frozen_cg.WriteControlFile("cgroup.freeze", "0"));
  EXPECT_TRUE(ReadMarker(prog_r.get(), 5000));

  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

// MigrateIntoFrozenFreezesAndOutResumes proves the attach() reconciliation: a
// running task migrated (via cgroup.procs) into a frozen cgroup stops, and
// migrated back out resumes. Without the attach() fix, freeze would be
// escapable by moving a task out of a frozen subtree.
TEST_F(Cgroup2Test, MigrateIntoFrozenFreezesAndOutResumes) {
  Cgroup frozen_cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("frozen"));
  Cgroup normal_cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("normal"));
  ASSERT_NO_ERRNO(frozen_cg.WriteControlFile("cgroup.freeze", "1"));

  int prog_fds[2];
  ASSERT_THAT(pipe(prog_fds), SyscallSucceeds());
  FileDescriptor prog_r(prog_fds[0]);
  FileDescriptor prog_w(prog_fds[1]);
  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t pid = fork();
  if (pid == 0) {
    prog_r.reset();
    go_w.reset();
    char token;
    if (read(go_r.get(), &token, 1) <= 0) {
      _exit(1);
    }
    while (true) {
      if (write(prog_w.get(), "x", 1) != 1) {
        _exit(2);
      }
      usleep(10000);
    }
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  prog_w.reset();
  go_r.reset();

  // Start out running in the unfrozen cgroup.
  ASSERT_NO_ERRNO(normal_cg.Enter(pid));
  ASSERT_THAT(write(go_w.get(), "x", 1), SyscallSucceeds());
  ASSERT_TRUE(ReadMarker(prog_r.get(), 5000));

  // Migrate into the frozen cgroup: the task must stop.
  ASSERT_NO_ERRNO(frozen_cg.Enter(pid));
  absl::SleepFor(absl::Milliseconds(100));
  DrainMarkers(prog_r.get());
  EXPECT_FALSE(ReadMarker(prog_r.get(), 500));

  // Migrate back out to the unfrozen cgroup: the task must resume.
  ASSERT_NO_ERRNO(normal_cg.Enter(pid));
  EXPECT_TRUE(ReadMarker(prog_r.get(), 5000));

  ASSERT_THAT(kill(pid, SIGKILL), SyscallSucceeds());
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

TEST_F(Cgroup2Test, DescendantsStatAndLimit) {
  // Verify defaults.
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 0")));
  EXPECT_THAT(c().ReadControlFile("cgroup.max.descendants"),
              IsPosixErrorOkAndHolds("max\n"));
  EXPECT_THAT(c().ReadControlFile("cgroup.max.depth"),
              IsPosixErrorOkAndHolds("max\n"));

  // A single descendant.
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 1")));

  // Set max descendants to 1 on the child...
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.descendants", "1"));
  // ...thereby allowing the birth of the first grandchild.
  Cgroup grandchild =
      ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("grandchild"));
  EXPECT_THAT(c().ReadControlFile("cgroup.stat"),
              IsPosixErrorOkAndHolds(HasSubstr("nr_descendants 2")));
  // ...but not the second.
  auto second_grandchild = child.CreateChild("second_grandchild");
  EXPECT_FALSE(second_grandchild.ok());

  // Allow unlimited descendants on the child, but deny depth.
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.descendants", "max"));
  ASSERT_NO_ERRNO(child.WriteControlFile("cgroup.max.depth", "1"));
  auto great_grandchild = grandchild.CreateChild("great_grandchild");
  EXPECT_FALSE(great_grandchild.ok());
}

TEST_F(Cgroup2Test, V1MountRejectedWhenControllerEnabledInV2) {
  auto available =
      ASSERT_NO_ERRNO_AND_VALUE(root().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(available, "pids"));
  // Since it is enabled in v2, attempting to mount v1 pointing to pids should
  // fail with EBUSY.
  EXPECT_THAT(m_->MountCgroupfs("pids"), PosixErrorIs(EBUSY));
}

TEST_F(Cgroup2Test, V1MountSucceedsAndV2OwnershipReturnsOnUnmount) {
  auto v2_mount = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v2_mounter(std::move(v2_mount));
  auto v2_cg = ASSERT_NO_ERRNO_AND_VALUE(v2_mounter.MountCgroup2fs());

  // Skip if v2 doesn't have pids to begin with.
  auto available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(available, "pids"));
  // Skip if we can't drain pids from below v2 root.
  PosixError unused = v2_cg.WriteControlFile("cgroup.subtree_control", "-pids");
  SKIP_IF(unused.errno_value() == EBUSY);

  // Steal the pids controller away from v2 by mounting it in v1.
  auto v1_mount1 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v1_mounter1(std::move(v1_mount1));
  auto v1_cg1 = ASSERT_NO_ERRNO_AND_VALUE(v1_mounter1.MountCgroupfs("pids"));
  // Mount it again in another v1 hierarchy for good measure.
  auto v1_mount2 = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Mounter v1_mounter2(std::move(v1_mount2));
  auto v1_cg2 = ASSERT_NO_ERRNO_AND_VALUE(v1_mounter2.MountCgroupfs("pids"));

  // Now pids should be gone from v2 root's cgroup.controllers
  available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  EXPECT_THAT(available, ::testing::Not(::testing::HasSubstr("pids")));

  // Unmount the first v1 mount. Pids should still be absent from v2.
  ASSERT_NO_ERRNO(v1_mounter1.Unmount(v1_cg1));
  available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  EXPECT_THAT(available, ::testing::Not(::testing::HasSubstr("pids")));

  // Unmount the second v1 mount, restoring pids ownership to v2.
  ASSERT_NO_ERRNO(v1_mounter2.Unmount(v1_cg2));
  available =
      ASSERT_NO_ERRNO_AND_VALUE(v2_cg.ReadControlFile("cgroup.controllers"));
  EXPECT_THAT(available, ::testing::HasSubstr("pids"));
}

TEST_F(Cgroup2Test, MemoryCurrent) {
  DisableSave ds;  // Avoid S/R memory overhead.
  ASSERT_NO_ERRNO(c().Enter(getpid()));
  const uint64_t usage =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadIntegerControlFile("memory.current"));
  EXPECT_GE(usage, 0);

  // Consume some memory by mmapping and faulting it.
  constexpr size_t kMemSize = 10 * 1024 * 1024;         // 10 MB
  constexpr size_t kMemFloorSlack = 2 * 1024 * 1024;    // 2 MB
  constexpr size_t kMemCeilingSlack = 5 * 1024 * 1024;  // 5 MB
  void* mem = mmap(nullptr, kMemSize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED);
  auto clean_mem = Cleanup([&] { munmap(mem, kMemSize); });

  // Touch the memory to ensure it's actually allocated (faulted in).
  memset(mem, 1, kMemSize);
  // Loop to wait past the sentry's internal 10ms memory usage stats update
  // throttle window (f.nextCommitScan in pgalloc.go).
  uint64_t usage_after = 0;
  const absl::Time deadline = absl::Now() + absl::Seconds(10);
  while (true) {
    absl::SleepFor(absl::Milliseconds(15));
    usage_after =
        ASSERT_NO_ERRNO_AND_VALUE(c().ReadIntegerControlFile("memory.current"));
    if (usage_after >= usage + kMemSize - kMemFloorSlack &&
        usage_after <= usage + kMemSize + kMemCeilingSlack) {
      break;
    }
    if (absl::Now() >= deadline) {
      break;
    }
  }
  EXPECT_GE(usage_after, usage + kMemSize - kMemFloorSlack);
  EXPECT_LE(usage_after, usage + kMemSize + kMemCeilingSlack);
}

TEST_F(Cgroup2Test, MemoryIsChargedToNearestAncestorWithController) {
  DisableSave ds;                                // Avoid S/R memory overhead.
  constexpr size_t kMemSize = 10 * 1024 * 1024;  // 10 MB
  constexpr size_t kMemFloorSlack = 2 * 1024 * 1024;    // 2 MB
  constexpr size_t kMemCeilingSlack = 5 * 1024 * 1024;  // 5 MB

  // Give `c()` memory delegation.
  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));
  // Create `child` (this has memory since `c()` delegated it).
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  // Remember base usage for `child`
  const uint64_t base_usage_child =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadIntegerControlFile("memory.current"));

  // Create `grandchild` and move into it. Memory delegation not active here.
  Cgroup grandchild =
      ASSERT_NO_ERRNO_AND_VALUE(child.CreateChild("grandchild"));
  ASSERT_NO_ERRNO(grandchild.Enter(getpid()));

  // Consume memory when in `grandchild`.
  void* mem2 = mmap(nullptr, kMemSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem2, MAP_FAILED);
  auto clean_mem2 = Cleanup([&] { munmap(mem2, kMemSize); });
  memset(mem2, 1, kMemSize);
  // Loop to wait past the sentry's internal 10ms memory usage stats update
  // throttle window (f.nextCommitScan in pgalloc.go).
  uint64_t usage_child = 0;
  const absl::Time deadline = absl::Now() + absl::Seconds(10);
  while (true) {
    absl::SleepFor(absl::Milliseconds(15));
    usage_child = ASSERT_NO_ERRNO_AND_VALUE(
        child.ReadIntegerControlFile("memory.current"));
    if (usage_child >= base_usage_child + kMemSize - kMemFloorSlack &&
        usage_child <= base_usage_child + kMemSize + kMemCeilingSlack) {
      break;
    }
    if (absl::Now() >= deadline) {
      break;
    }
  }

  // `child` should now reflect base_usage_child + kMemSize approximately.
  EXPECT_GE(usage_child, base_usage_child + kMemSize - kMemFloorSlack);
  EXPECT_LE(usage_child, base_usage_child + kMemSize + kMemCeilingSlack);

  // Move to `child` and remove `grandchild`.
  // Note: we can't move back to `c()` because it has `+memory` in
  // `subtree_control` and cgroup v2 forbids internal processes in nodes with
  // enabled controllers.
  ASSERT_NO_ERRNO(child.Enter(getpid()));
  // Destroy `grandchild`.
  ASSERT_NO_ERRNO(Rmdir(grandchild.Path()));

  // `child` should STILL reflect base_usage_child + kMemSize, because the pages
  // mapped under mem2 still exists in its subtree.
  const uint64_t usage_child_after =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadIntegerControlFile("memory.current"));
  EXPECT_GE(usage_child_after, base_usage_child + kMemSize - kMemFloorSlack);
  EXPECT_LE(usage_child_after, base_usage_child + kMemSize + kMemCeilingSlack);
}

TEST_F(Cgroup2Test, OperationsOnDeletedCgroupFDs) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  // Open FDs to an interface file and the cgroup dir itself before deletion.
  FileDescriptor procs_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Relpath("cgroup.procs"), O_RDWR));
  FileDescriptor dir_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(child.Path(), O_RDONLY | O_DIRECTORY));

  // Delete the cgroup.
  ASSERT_NO_ERRNO(Rmdir(child.Path()));

  // Setup buffers for playing around.
  char pid_buf[32];
  int len = snprintf(pid_buf, sizeof(pid_buf), "%d", getpid());
  char read_buf[256];

  // Write to deleted cgroup.procs should yield ENODEV.
  EXPECT_THAT(write(procs_fd.get(), pid_buf, len),
              SyscallFailsWithErrno(ENODEV));
  // Read from deleted cgroup.procs should yield ENODEV.
  EXPECT_THAT(read(procs_fd.get(), read_buf, sizeof(read_buf)),
              SyscallFailsWithErrno(ENODEV));
  // Creating a dir inside the deleted cgroup should yield ENOENT.
  EXPECT_THAT(mkdirat(dir_fd.get(), "newchild", 0755),
              SyscallFailsWithErrno(ENOENT));
  // Opening an interface file in the deleted cgroup should yield ENOENT.
  EXPECT_THAT(openat(dir_fd.get(), "cgroup.procs", O_RDONLY),
              SyscallFailsWithErrno(ENOENT));
}

TEST_F(Cgroup2Test, StatFS) {
  struct statfs st;
  EXPECT_THAT(statfs(c().Path().c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, CGROUP2_SUPER_MAGIC);

  EXPECT_THAT(statfs(c().Relpath("cgroup.procs").c_str(), &st),
              SyscallSucceeds());
  EXPECT_EQ(st.f_type, CGROUP2_SUPER_MAGIC);

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(c().Relpath("cgroup.controllers"), O_RDONLY));
  EXPECT_THAT(fstatfs(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.f_type, CGROUP2_SUPER_MAGIC);
}

TEST_F(Cgroup2Test, ReadWriteOnFileDescriptorOfDisabledController) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "pids"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+pids"));

  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));
  std::string pids_max_path = child.Relpath("pids.max");
  FileDescriptor pids_max_fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(pids_max_path, O_RDWR));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "-pids"));

  char buf[256];
  EXPECT_THAT(read(pids_max_fd.get(), buf, sizeof(buf)),
              SyscallFailsWithErrno(ENODEV));
}

TEST_F(Cgroup2Test, MemoryLimits) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "memory"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+memory"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));

  // Check default values.
  EXPECT_THAT(parent.ReadControlFile("memory.max"),
              IsPosixErrorOkAndHolds("max\n"));
  EXPECT_THAT(parent.ReadControlFile("memory.high"),
              IsPosixErrorOkAndHolds("max\n"));

  // Write max and check.
  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.max", "100M"));
  EXPECT_THAT(parent.ReadControlFile("memory.max"),
              IsPosixErrorOkAndHolds("104857600\n"));

  // Write high and check.
  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.high", "52428800"));
  EXPECT_THAT(parent.ReadControlFile("memory.high"),
              IsPosixErrorOkAndHolds("52428800\n"));

  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.max", "1G"));
  EXPECT_THAT(parent.ReadControlFile("memory.max"),
              IsPosixErrorOkAndHolds("1073741824\n"));

  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.high", "256k"));
  EXPECT_THAT(parent.ReadControlFile("memory.high"),
              IsPosixErrorOkAndHolds("262144\n"));

  // Write max back and check.
  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.max", "max"));
  EXPECT_THAT(parent.ReadControlFile("memory.max"),
              IsPosixErrorOkAndHolds("max\n"));

  // Settle back high.
  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.high", "max"));
  EXPECT_THAT(parent.ReadControlFile("memory.high"),
              IsPosixErrorOkAndHolds("max\n"));

  // Page-rounding checks.
  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.max", "5000"));
  EXPECT_THAT(parent.ReadControlFile("memory.max"),
              IsPosixErrorOkAndHolds("4096\n"));

  ASSERT_NO_ERRNO(parent.WriteControlFile("memory.high", "5000"));
  EXPECT_THAT(parent.ReadControlFile("memory.high"),
              IsPosixErrorOkAndHolds("4096\n"));

  // Check invalid formats.
  EXPECT_THAT(parent.WriteControlFile("memory.max", "-1"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("memory.max", "abc"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("memory.max", "100xyz"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("memory.max", "abc100"),
              PosixErrorIs(EINVAL));
}

TEST_F(Cgroup2Test, CpuLimits) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup parent = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("parent"));

  // Check default values.
  EXPECT_THAT(parent.ReadControlFile("cpu.max"),
              IsPosixErrorOkAndHolds("max 100000\n"));
  EXPECT_THAT(parent.ReadControlFile("cpu.weight"),
              IsPosixErrorOkAndHolds("100\n"));

  // Write max and check.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cpu.max", "20000 100000"));
  EXPECT_THAT(parent.ReadControlFile("cpu.max"),
              IsPosixErrorOkAndHolds("20000 100000\n"));

  ASSERT_NO_ERRNO(parent.WriteControlFile("cpu.max", "max 500000"));
  EXPECT_THAT(parent.ReadControlFile("cpu.max"),
              IsPosixErrorOkAndHolds("max 500000\n"));

  // Write weight and check.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cpu.weight", "500"));
  EXPECT_THAT(parent.ReadControlFile("cpu.weight"),
              IsPosixErrorOkAndHolds("500\n"));

  // Invalid formats.
  // Single parameter writes to cpu.max should succeed.
  ASSERT_NO_ERRNO(parent.WriteControlFile("cpu.max", "20000"));
  EXPECT_THAT(parent.ReadControlFile("cpu.max"),
              IsPosixErrorOkAndHolds("20000 500000\n"));

  EXPECT_THAT(parent.WriteControlFile("cpu.max", "abc 100000"),
              PosixErrorIs(EINVAL));
  EXPECT_THAT(parent.WriteControlFile("cpu.weight", "0"), PosixErrorIs(ERANGE));
  EXPECT_THAT(parent.WriteControlFile("cpu.weight", "10001"),
              PosixErrorIs(ERANGE));
  EXPECT_THAT(parent.WriteControlFile("cpu.weight", "abc"),
              PosixErrorIs(EINVAL));
}

// The helpers below are for use in forked children: they only use raw
// syscalls and operate on caller-provided buffers to be async-signal-safe.

// Reads the cgroup2 ("0::") entry from the /proc/<pid>/cgroup file at
// proc_path and copies the path portion (after "0::") into out. Returns false
// on failure.
bool ReadV2PathRaw(const char* proc_path, char* out, size_t out_len) {
  char data[4096];
  int fd = open(proc_path, O_RDONLY);
  if (fd < 0) {
    return false;
  }
  ssize_t n = read(fd, data, sizeof(data) - 1);
  close(fd);
  if (n <= 0) {
    return false;
  }
  data[n] = '\0';
  char* entry = strstr(data, "0::");
  if (entry == nullptr) {
    return false;
  }
  entry += 3;
  char* end = strchr(entry, '\n');
  if (end != nullptr) {
    *end = '\0';
  }
  strncpy(out, entry, out_len);
  out[out_len - 1] = '\0';
  return true;
}

// Writes val to the file at path. Returns 0 on success, the failing errno
// otherwise.
int WriteFileErrno(const char* path, absl::string_view val) {
  if (path == nullptr) {
    return EINVAL;
  }
  const int fd = open(path, O_WRONLY);
  if (fd < 0) {
    return errno;
  }
  const ssize_t n = WriteFd(fd, val.data(), val.size());
  const int err = (n < 0 || static_cast<size_t>(n) != val.size()) ? errno : 0;
  close(fd);
  return err;
}

// Async-signal-safe. Returns 0 on success, the write(2) errno otherwise.
int WriteFdErrno(int fd, absl::string_view val) {
  const ssize_t n = WriteFd(fd, val.data(), val.size());
  return (n < 0 || static_cast<size_t>(n) != val.size()) ? errno : 0;
}

// Whether the cgroup2 mount at `mountpoint` has the nsdelegate flag applied.
// Mounting with the option always succeeds, but Linux silently ignores it
// unless the mounting process is in the init cgroup namespace (see
// apply_cgroup_root_flags in kernel/cgroup/cgroup.c), so environments that
// themselves run inside a cgroup namespace (e.g. containerized CI sandboxes)
// cannot turn it on. Tests of nsdelegate behavior must skip there.
PosixErrorOr<bool> NsdelegateApplied(absl::string_view mountpoint) {
  ASSIGN_OR_RETURN_ERRNO(std::vector<ProcMountsEntry> entries,
                         ProcSelfMountsEntries());
  for (const ProcMountsEntry& e : entries) {
    if (e.mount_point == mountpoint && e.fstype == "cgroup2") {
      return absl::StrContains(e.mount_opts, "nsdelegate");
    }
  }
  return PosixError(ENOENT, absl::StrCat("no cgroup2 mount at ", mountpoint));
}

// Copies the "root" field (field 4) of the /proc/self/mountinfo entry whose
// mount point is `mp`, into `out`. Returns false if no such entry exists.
bool MountInfoRootRaw(absl::string_view mp, char* out, size_t out_len) {
  if (out == nullptr || out_len == 0) {
    return false;
  }
  static char data[1 << 16];
  const int fd = open("/proc/self/mountinfo", O_RDONLY);
  if (fd < 0) {
    return false;
  }
  const ssize_t total = ReadFd(fd, data, sizeof(data));
  close(fd);
  if (total < 0) {
    return false;
  }

  absl::string_view content(data, total);
  while (!content.empty()) {
    const size_t newline_pos = content.find('\n');
    absl::string_view line = content.substr(0, newline_pos);
    if (newline_pos != absl::string_view::npos) {
      content.remove_prefix(newline_pos + 1);
    } else {
      content = absl::string_view();
    }

    // Fields: mountID parentID major:minor root mountpoint ...
    absl::string_view fields[5];
    bool parsed = true;
    for (int i = 0; i < 5; ++i) {
      const size_t space_pos = line.find(' ');
      if (space_pos == absl::string_view::npos && i < 4) {
        parsed = false;
        break;
      }
      fields[i] = line.substr(0, space_pos);
      if (space_pos != absl::string_view::npos) {
        line.remove_prefix(space_pos + 1);
      }
    }
    if (parsed && fields[4] == mp) {
      const size_t copied = fields[3].copy(out, out_len - 1);
      out[copied] = '\0';
      return true;
    }
  }
  return false;
}

// readlink() into out, NUL-terminating the result. Returns false on failure.
bool ReadLinkRaw(const char* path, char* out, size_t out_len) {
  if (path == nullptr || out == nullptr || out_len == 0) {
    return false;
  }
  const ssize_t n = readlink(path, out, out_len - 1);
  if (n < 0) {
    return false;
  }
  out[n] = '\0';
  return true;
}

TEST_F(Cgroup2Test, CgroupNamespaceUnshare) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_unshare"));
  Cgroup sub = ASSERT_NO_ERRNO_AND_VALUE(cg.CreateChild("sub"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string sub_procs = sub.Relpath("cgroup.procs");

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    char before[256];
    char after[256];
    TEST_CHECK(ReadLinkRaw("/proc/self/ns/cgroup", before, sizeof(before)));
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    TEST_CHECK(ReadLinkRaw("/proc/self/ns/cgroup", after, sizeof(after)));
    TEST_CHECK(strcmp(before, after) != 0);

    // The namespace root is the cgroup we were in when unsharing.
    char path[256];
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/") == 0, path);

    // Moving to a sub-cgroup is reflected relative to the namespace root.
    TEST_CHECK(WriteFileErrno(sub_procs.c_str(), "0") == 0);
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/sub") == 0, path);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST_F(Cgroup2Test, CgroupNamespaceUnshareRequiresCapability) {
  c();  // Initialize the fixture, skipping the test if necessary.
  AutoCapability cap(CAP_SYS_ADMIN, false);
  EXPECT_THAT(unshare(CLONE_NEWCGROUP), SyscallFailsWithErrno(EPERM));
}

TEST_F(Cgroup2Test, CgroupNamespaceClone) {
  c();  // Initialize the fixture, skipping the test if necessary.
  const std::string self_ns =
      ASSERT_NO_ERRNO_AND_VALUE(ReadLink("/proc/self/ns/cgroup"));

  const pid_t pid = syscall(SYS_clone, CLONE_NEWCGROUP | SIGCHLD, 0, 0, 0, 0);
  if (pid == 0) {
    char path[256];
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/") == 0, path);
    char link[256];
    TEST_CHECK(ReadLinkRaw("/proc/self/ns/cgroup", link, sizeof(link)));
    TEST_CHECK(strcmp(link, self_ns.c_str()) != 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// A process in a sibling cgroup namespace is shown with a "/.." relative path.
TEST_F(Cgroup2Test, CgroupNamespaceSiblingPaths) {
  Cgroup ca = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_a"));
  Cgroup cb = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_b"));
  const std::string cb_procs = cb.Relpath("cgroup.procs");

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Park a process in ns_a.
  const pid_t parked = fork();
  if (parked == 0) {
    close(wfd.get());
    char token;
    TEST_CHECK(read(rfd.get(), &token, 1) == 0);
    _exit(0);
  }
  ASSERT_GT(parked, 0);
  ASSERT_NO_ERRNO(ca.Enter(parked));
  const std::string parked_proc = absl::StrFormat("/proc/%d/cgroup", parked);

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(cb_procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    char path[256];
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/") == 0, path);
    // The parked process is in a sibling cgroup, outside our namespace.
    TEST_CHECK(ReadV2PathRaw(parked_proc.c_str(), path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/../ns_a") == 0, path);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  wfd.reset();  // Release the parked process.
  ASSERT_THAT(waitpid(parked, &status, 0), SyscallSucceedsWithValue(parked));
}

TEST_F(Cgroup2Test, CgroupNamespaceSetns) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_setns"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string canonical = cg.CanonicalPath();

  const pid_t pid = fork();
  if (pid == 0) {
    int initns = open("/proc/self/ns/cgroup", O_RDONLY);
    TEST_PCHECK(initns >= 0);
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    char path[256];
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/") == 0, path);

    // Return to the initial namespace; the full path becomes visible again.
    TEST_PCHECK(setns(initns, CLONE_NEWCGROUP) == 0);
    TEST_CHECK(ReadV2PathRaw("/proc/self/cgroup", path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, canonical.c_str()) == 0, path);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST_F(Cgroup2Test, CgroupNamespaceSetnsPidfd) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_pidfd"));
  const std::string procs = cg.Relpath("cgroup.procs");

  int ready_fds[2];
  int release_fds[2];
  ASSERT_THAT(pipe(ready_fds), SyscallSucceeds());
  ASSERT_THAT(pipe(release_fds), SyscallSucceeds());
  FileDescriptor ready_r(ready_fds[0]), ready_w(ready_fds[1]);
  FileDescriptor release_r(release_fds[0]), release_w(release_fds[1]);

  // The target process unshares into a new cgroup namespace rooted at
  // ns_pidfd, then waits.
  const pid_t target = fork();
  if (target == 0) {
    close(ready_r.get());
    close(release_w.get());
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    char token = 't';
    TEST_CHECK(write(ready_w.get(), &token, 1) == 1);
    close(ready_w.get());
    TEST_CHECK(read(release_r.get(), &token, 1) == 0);
    _exit(0);
  }
  ASSERT_GT(target, 0);
  ready_w.reset();
  char token;
  ASSERT_THAT(read(ready_r.get(), &token, 1), SyscallSucceedsWithValue(1));
  const std::string target_proc = absl::StrFormat("/proc/%d/cgroup", target);

  const pid_t pid = fork();
  if (pid == 0) {
    int pidfd = syscall(SYS_pidfd_open, target, 0);
    TEST_PCHECK(pidfd >= 0);
    TEST_PCHECK(setns(pidfd, CLONE_NEWCGROUP) == 0);
    // The target sits at the root of the namespace we just joined.
    char path[256];
    TEST_CHECK(ReadV2PathRaw(target_proc.c_str(), path, sizeof(path)));
    TEST_CHECK_MSG(strcmp(path, "/") == 0, path);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  release_w.reset();
  ASSERT_THAT(waitpid(target, &status, 0), SyscallSucceedsWithValue(target));
}

// Mounting cgroup2 from inside a cgroup namespace roots the mount at the
// namespace root cgroup.
TEST_F(Cgroup2Test, CgroupNamespaceMount) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("ns_mount"));
  ASSERT_NO_ERRNO(cg.CreateChild("inner"));
  const std::string procs = cg.Relpath("cgroup.procs");

  TempPath mntdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = mntdir.path();
  const std::string inner_path = JoinPath(dir, "inner");
  // cgroup.type only exists on non-root cgroups, so its presence at the mount
  // root proves the mount is rooted at the (non-root) namespace root.
  const std::string type_path = JoinPath(dir, "cgroup.type");
  // The fixture's "test" cgroup exists at the hierarchy root, and must not be
  // visible at the mount root.
  const std::string outside_path = JoinPath(dir, "test");

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    TEST_PCHECK(mount("none", dir.c_str(), "cgroup2", 0, nullptr) == 0);
    TEST_CHECK(access(inner_path.c_str(), F_OK) == 0);
    TEST_CHECK(access(type_path.c_str(), F_OK) == 0);
    TEST_CHECK(access(outside_path.c_str(), F_OK) != 0);
    TEST_PCHECK(umount2(dir.c_str(), MNT_DETACH) == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  // In case the child died before unmounting.
  umount2(dir.c_str(), MNT_DETACH);
}

// Verifies the mountinfo "root" field for cgroup2 mounts with and without a
// cgroup namespace.
//
//   mount rooted at        read from init ns    read from cgroupns @ /test/mi
//   ---------------        -----------------    -----------------------------
//   the real root          "/"                  "/../.."
//   /test/mi               "/test/mi"           "/"
TEST_F(Cgroup2Test, MountInfoRootIsCgroupNamespaceRelative) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("mi"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string canonical = cg.CanonicalPath();  // "/test/mi"
  // The fixture's mount of the full hierarchy.
  const std::string full_mp = root().Path();

  TempPath mntdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string ns_mp = mntdir.path();

  int ready_fds[2];
  int done_fds[2];
  ASSERT_THAT(pipe(ready_fds), SyscallSucceeds());
  ASSERT_THAT(pipe(done_fds), SyscallSucceeds());
  FileDescriptor ready_r(ready_fds[0]), ready_w(ready_fds[1]);
  FileDescriptor done_r(done_fds[0]), done_w(done_fds[1]);

  const pid_t child = fork();
  if (child == 0) {
    close(ready_r.get());
    close(done_w.get());
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    TEST_PCHECK(mount("none", ns_mp.c_str(), "cgroup2", 0, nullptr) == 0);

    char field[256];
    // Read from inside the namespace, the mount rooted at the namespace root
    // shows "/"...
    TEST_CHECK(MountInfoRootRaw(ns_mp.c_str(), field, sizeof(field)));
    TEST_CHECK_MSG(strcmp(field, "/") == 0, field);
    // ... and the full-hierarchy mount shows the real root relative to the
    // namespace root.
    TEST_CHECK(MountInfoRootRaw(full_mp.c_str(), field, sizeof(field)));
    TEST_CHECK_MSG(strcmp(field, "/../..") == 0, field);

    char token = 't';
    TEST_CHECK(write(ready_w.get(), &token, 1) == 1);
    TEST_CHECK(read(done_r.get(), &token, 1) == 0);
    TEST_PCHECK(umount2(ns_mp.c_str(), MNT_DETACH) == 0);
    _exit(0);
  }
  ASSERT_GT(child, 0);
  ready_w.reset();
  done_r.reset();

  char token;
  ASSERT_THAT(read(ready_r.get(), &token, 1), SyscallSucceedsWithValue(1));

  // The mounts are shared with the child, but this process reads from the
  // init cgroup namespace: the namespaced mount shows its real path, and the
  // full-hierarchy mount shows "/".
  char field[256];
  EXPECT_TRUE(MountInfoRootRaw(ns_mp.c_str(), field, sizeof(field)));
  EXPECT_STREQ(field, canonical.c_str());
  EXPECT_TRUE(MountInfoRootRaw(full_mp.c_str(), field, sizeof(field)));
  EXPECT_STREQ(field, "/");

  done_w.reset();  // Release the child.
  int status;
  ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  // In case the child died before unmounting.
  umount2(ns_mp.c_str(), MNT_DETACH);
}

int64_t ParseCpuUsageUsec(const Cgroup& cg) {
  PosixErrorOr<std::string> stat_or = cg.ReadControlFile("cpu.stat");
  if (!stat_or.ok()) return -1;
  for (absl::string_view line : absl::StrSplit(stat_or.ValueOrDie(), '\n')) {
    line = absl::StripAsciiWhitespace(line);
    constexpr absl::string_view kUsagePrefix = "usage_usec ";
    if (absl::StartsWith(line, kUsagePrefix)) {
      int64_t usage_usec = -1;
      if (absl::SimpleAtoi(line.substr(kUsagePrefix.size()), &usage_usec)) {
        return usage_usec;
      }
    }
  }
  return -1;
}

// PollCpuUsageUsecGreaterThan polls until the CPU usage exceeds the given
// target. This handles test flakiness in gVisor: CPU clocks are not updated
// perfectly synchronously upon task completion. Instead, a background timer
// samples running tasks every ~10ms (linux.ClockTick). Tests that race to
// assert CPU usage immediately after a workload finishes natively via KVM can
// incorrectly read zero if the tick hasn't fired yet.
int64_t PollCpuUsageUsecGreaterThan(const Cgroup& cg, int64_t target) {
  int64_t usage = ParseCpuUsageUsec(cg);
  absl::Time deadline = absl::Now() + absl::Seconds(10);
  while (usage <= target && absl::Now() < deadline) {
    absl::SleepFor(absl::Milliseconds(15));
    usage = ParseCpuUsageUsec(cg);
  }
  return usage;
}

TEST_F(Cgroup2Test, CpuStat) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("child"));

  std::string stat_before =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadControlFile("cpu.stat"));
  EXPECT_THAT(stat_before, HasSubstr("usage_usec "));

  int fds_start[2];
  ASSERT_THAT(pipe(fds_start), SyscallSucceeds());

  pid_t pid = fork();
  ASSERT_THAT(pid, SyscallSucceeds());
  if (pid == 0) {
    close(fds_start[1]);
    char c;
    if (read(fds_start[0], &c, 1) != 1) _exit(1);
    close(fds_start[0]);
    volatile int x = 0;
    for (int i = 0; i < 50000000; ++i) {
      x++;
    }
    _exit(0);
  }
  close(fds_start[0]);
  ASSERT_NO_ERRNO(child.Enter(pid));
  char c = 'g';
  ASSERT_THAT(write(fds_start[1], &c, 1), SyscallSucceeds());
  close(fds_start[1]);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  int64_t usage_usec = PollCpuUsageUsecGreaterThan(child, 0);
  EXPECT_GT(usage_usec, 0);
}

TEST_F(Cgroup2Test, CpuStatMigration) {
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup cg_a = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("cg_a"));
  Cgroup cg_b = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("cg_b"));

  int fds_start[2];
  int fds_phase1[2];
  int fds_proceed[2];
  ASSERT_THAT(pipe(fds_start), SyscallSucceeds());
  ASSERT_THAT(pipe(fds_phase1), SyscallSucceeds());
  ASSERT_THAT(pipe(fds_proceed), SyscallSucceeds());

  pid_t pid = fork();
  if (pid == 0) {
    close(fds_start[1]);
    close(fds_phase1[0]);
    close(fds_proceed[1]);

    char c;
    if (read(fds_start[0], &c, 1) != 1) _exit(1);
    close(fds_start[0]);

    // Burn some CPU in cg_a.
    volatile int x = 0;
    for (int i = 0; i < 50000000; ++i) {
      x++;
    }
    c = '1';
    if (write(fds_phase1[1], &c, 1) != 1) _exit(1);
    close(fds_phase1[1]);

    if (read(fds_proceed[0], &c, 1) != 1) _exit(1);
    close(fds_proceed[0]);

    // Burn some CPU in cg_b.
    for (int i = 0; i < 50000000; ++i) {
      x++;
    }
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  close(fds_start[0]);
  close(fds_phase1[1]);
  close(fds_proceed[0]);

  ASSERT_NO_ERRNO(cg_a.Enter(pid));
  // Commence first loop in the child.
  char c = 'g';
  ASSERT_THAT(write(fds_start[1], &c, 1), SyscallSucceeds());
  close(fds_start[1]);
  // Loop ended, child burned cpu in cg_a.
  ASSERT_THAT(read(fds_phase1[0], &c, 1), SyscallSucceeds());
  close(fds_phase1[0]);

  int64_t usage_a_before_migration = PollCpuUsageUsecGreaterThan(cg_a, 0);
  EXPECT_GT(usage_a_before_migration, 0);

  ASSERT_NO_ERRNO(cg_b.Enter(pid));  // Move to cg_b, loop yet to run.

  int64_t usage_b_post_migration = ParseCpuUsageUsec(cg_b);
  int64_t usage_a_post_migration = ParseCpuUsageUsec(cg_a);
  EXPECT_GE(usage_b_post_migration, 0);
  EXPECT_LT(usage_b_post_migration, 30000);  // Bounded setup (< 30 ms).
  EXPECT_GE(usage_a_post_migration, usage_a_before_migration);

  // Commence second loop in the child.
  c = '2';
  ASSERT_THAT(write(fds_proceed[1], &c, 1), SyscallSucceeds());
  close(fds_proceed[1]);

  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  int64_t usage_b_final =
      PollCpuUsageUsecGreaterThan(cg_b, usage_b_post_migration);
  int64_t usage_a_final = ParseCpuUsageUsec(cg_a);
  EXPECT_GT(usage_b_final, usage_b_post_migration);
  EXPECT_EQ(usage_a_final, usage_a_post_migration);
}

// BurnCpuMs busy-loops, consuming CPU, for at least ms milliseconds of wall
// time. The loop never blocks, so the CPU time consumed tracks wall time. Safe
// to call in a forked child: it only touches CLOCK_MONOTONIC.
void BurnCpuMs(int ms) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  volatile uint64_t x = 0;
  for (;;) {
    for (int i = 0; i < 200000; ++i) x++;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t el_ms = (now.tv_sec - start.tv_sec) * 1000 +
                    (now.tv_nsec - start.tv_nsec) / 1000000;
    if (el_ms >= ms) break;
  }
}

// cpu.stat of a cgroup must include live tasks residing in descendant cgroups
// that have not enabled their own cpu controller.
TEST_F(Cgroup2Test, CpuStatCountsControllerlessDescendants) {
  DisableSave ds;  // clock involved.
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("a"));
  // a does not enable +cpu, so sub has no cpu controller of its own; a's
  // controller is the nearest one.
  Cgroup sub = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("sub"));

  int start[2], stop[2];
  ASSERT_THAT(pipe(start), SyscallSucceeds());
  ASSERT_THAT(pipe(stop), SyscallSucceeds());

  pid_t pid = fork();
  if (pid == 0) {
    close(start[1]);
    close(stop[1]);
    char ch;
    if (read(start[0], &ch, 1) != 1) _exit(1);
    int flags = fcntl(stop[0], F_GETFL);
    fcntl(stop[0], F_SETFL, flags | O_NONBLOCK);
    for (;;) {
      BurnCpuMs(50);
      if (read(stop[0], &ch, 1) == 0 || errno != EAGAIN) break;
    }
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  close(start[0]);
  close(stop[0]);

  ASSERT_NO_ERRNO(sub.Enter(pid));
  char ch = 'g';
  ASSERT_THAT(write(start[1], &ch, 1), SyscallSucceeds());

  // a's cpu.stat must reflect the task burning in sub.
  int64_t usage = PollCpuUsageUsecGreaterThan(a, 100000);
  EXPECT_GT(usage, 100000);

  close(stop[1]);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
}

// Migrating a task between two cgroups that share the same nearest cpu
// controller must not discard the CPU it burned before the migration.
TEST_F(Cgroup2Test, CpuStatSameInstanceMigrationKeepsUsage) {
  DisableSave ds;  // clock involved.
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("a"));
  // a does not enable +cpu, so x and y both resolve to a's controller.
  Cgroup x = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("x"));
  Cgroup y = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("y"));

  int start[2], stop[2];
  ASSERT_THAT(pipe(start), SyscallSucceeds());
  ASSERT_THAT(pipe(stop), SyscallSucceeds());

  // The child burns continuously so a's usage keeps growing while we poll; a
  // frozen counter could stall exactly on the poll target and never exceed it.
  pid_t pid = fork();
  if (pid == 0) {
    close(start[1]);
    close(stop[1]);
    char ch;
    if (read(start[0], &ch, 1) != 1) _exit(1);
    int flags = fcntl(stop[0], F_GETFL);
    fcntl(stop[0], F_SETFL, flags | O_NONBLOCK);
    for (;;) {
      BurnCpuMs(50);
      if (read(stop[0], &ch, 1) == 0 || errno != EAGAIN) break;
    }
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  close(start[0]);
  close(stop[0]);

  ASSERT_NO_ERRNO(x.Enter(pid));
  char ch = 'g';
  ASSERT_THAT(write(start[1], &ch, 1), SyscallSucceeds());

  int64_t usage_before = PollCpuUsageUsecGreaterThan(a, 100000);
  EXPECT_GT(usage_before, 100000);

  // Migrate to a sibling that shares a's controller.
  ASSERT_NO_ERRNO(y.Enter(pid));

  int64_t usage_after = ParseCpuUsageUsec(a);
  EXPECT_GE(usage_after, usage_before);

  close(stop[1]);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
}

// Disabling +cpu on a cgroup must reparent the disabled controller's
// accumulated usage to the parent, not discard it.
TEST_F(Cgroup2Test, CpuStatDisableReparentsUsage) {
  DisableSave ds;  // clock involved.
  std::string controllers =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadControlFile("cgroup.controllers"));
  SKIP_IF(!absl::StrContains(controllers, "cpu"));

  ASSERT_NO_ERRNO(c().WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("a"));
  ASSERT_NO_ERRNO(a.WriteControlFile("cgroup.subtree_control", "+cpu"));
  Cgroup b = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("b"));

  int start[2], stop[2];
  ASSERT_THAT(pipe(start), SyscallSucceeds());
  ASSERT_THAT(pipe(stop), SyscallSucceeds());

  // The child burns continuously so b's usage keeps growing while we poll; a
  // frozen counter could stall exactly on the poll target and never exceed it.
  pid_t pid = fork();
  if (pid == 0) {
    close(start[1]);
    close(stop[1]);
    char ch;
    if (read(start[0], &ch, 1) != 1) _exit(1);
    int flags = fcntl(stop[0], F_GETFL);
    fcntl(stop[0], F_SETFL, flags | O_NONBLOCK);
    for (;;) {
      BurnCpuMs(50);
      if (read(stop[0], &ch, 1) == 0 || errno != EAGAIN) break;
    }
    _exit(0);
  }
  ASSERT_THAT(pid, SyscallSucceeds());
  close(start[0]);
  close(stop[0]);

  ASSERT_NO_ERRNO(b.Enter(pid));
  char ch = 'g';
  ASSERT_THAT(write(start[1], &ch, 1), SyscallSucceeds());

  // Confirm substantial usage on b's live, growing counter.
  int64_t live = PollCpuUsageUsecGreaterThan(b, 100000);
  EXPECT_GT(live, 100000);

  // Stop and reap the child so its usage is committed to b's controller.
  close(stop[1]);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());

  // a's recursive cpu.stat includes b's committed usage.
  int64_t usage_before = PollCpuUsageUsecGreaterThan(a, 0);
  EXPECT_GT(usage_before, 0);

  // Disabling +cpu destroys b's controller; its usage must survive on a.
  ASSERT_NO_ERRNO(a.WriteControlFile("cgroup.subtree_control", "-cpu"));

  int64_t usage_after = ParseCpuUsageUsec(a);
  EXPECT_GE(usage_after, usage_before);
}

// With nsdelegate, cgroup namespace roots are delegation boundaries: only
// delegatable files on the namespace root remain writable from inside the
// namespace.
TEST_F(Cgroup2Test, NsdelegateRootWrites) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd"));
  Cgroup inner = ASSERT_NO_ERRNO_AND_VALUE(cg.CreateChild("inner"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string max_depth = cg.Relpath("cgroup.max.depth");
  const std::string inner_max_depth = inner.Relpath("cgroup.max.depth");

  // Setting the flag requires a mount from the init cgroup namespace, and is
  // system wide.
  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup r2 = ASSERT_NO_ERRNO_AND_VALUE(m2.MountCgroup2fs("nsdelegate"));

  // Skip if the environment could not actually turn nsdelegate on.
  const bool nsdelegate_applied =
      ASSERT_NO_ERRNO_AND_VALUE(NsdelegateApplied(r2.Path()));
  SKIP_IF(!nsdelegate_applied);

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    // Non-delegatable file on the namespace root: EPERM.
    TEST_CHECK(WriteFileErrno(max_depth.c_str(), "max") == EPERM);
    // Delegatable file on the namespace root: allowed.
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    // Non-delegatable file below the namespace root: allowed.
    TEST_CHECK(WriteFileErrno(inner_max_depth.c_str(), "max") == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Mounting without the option from the init namespace clears the flag;
  // the same write is then allowed.
  Mounter m3(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  ASSERT_NO_ERRNO(m3.MountCgroup2fs());

  const pid_t pid2 = fork();
  if (pid2 == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    TEST_CHECK(WriteFileErrno(max_depth.c_str(), "max") == 0);
    _exit(0);
  }
  ASSERT_GT(pid2, 0);
  ASSERT_THAT(waitpid(pid2, &status, 0), SyscallSucceedsWithValue(pid2));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// With nsdelegate, processes can't be migrated into or out of the namespace
// by a process inside it.
TEST_F(Cgroup2Test, NsdelegateMigrationContainment) {
  Cgroup ca = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_a"));
  Cgroup sub = ASSERT_NO_ERRNO_AND_VALUE(ca.CreateChild("sub"));
  Cgroup cb = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_b"));
  const std::string ca_procs = ca.Relpath("cgroup.procs");
  const std::string sub_procs = sub.Relpath("cgroup.procs");
  const std::string cb_procs = cb.Relpath("cgroup.procs");

  int fds[2];
  ASSERT_THAT(pipe(fds), SyscallSucceeds());
  FileDescriptor rfd(fds[0]);
  FileDescriptor wfd(fds[1]);

  // Park a process in nsd_b, outside the namespace created below.
  const pid_t parked = fork();
  if (parked == 0) {
    close(wfd.get());
    char token;
    TEST_CHECK(read(rfd.get(), &token, 1) == 0);
    _exit(0);
  }
  ASSERT_GT(parked, 0);
  ASSERT_NO_ERRNO(cb.Enter(parked));
  const std::string parked_pid = absl::StrCat(parked);

  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup r2 = ASSERT_NO_ERRNO_AND_VALUE(m2.MountCgroup2fs("nsdelegate"));
  auto clean = Cleanup([] {
    // Clear the system-wide flag.
    Mounter m3(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    ASSERT_NO_ERRNO(m3.MountCgroup2fs());
  });

  // Skip if the environment could not actually turn nsdelegate on.
  const bool nsdelegate_applied =
      ASSERT_NO_ERRNO_AND_VALUE(NsdelegateApplied(r2.Path()));
  SKIP_IF(!nsdelegate_applied);

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(ca_procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    // Destination outside the namespace: ENOENT.
    TEST_CHECK(WriteFileErrno(cb_procs.c_str(), "0") == ENOENT);
    // Source outside the namespace: ENOENT.
    TEST_CHECK(WriteFileErrno(ca_procs.c_str(), parked_pid.c_str()) == ENOENT);
    // Both inside the namespace: allowed.
    TEST_CHECK(WriteFileErrno(sub_procs.c_str(), "0") == 0);
    TEST_CHECK(WriteFileErrno(ca_procs.c_str(), "0") == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  // Migrations by processes in the init namespace are unrestricted.
  EXPECT_NO_ERRNO(ca.Enter(parked));

  wfd.reset();  // Release the parked process.
  ASSERT_THAT(waitpid(parked, &status, 0), SyscallSucceedsWithValue(parked));
}

// With nsdelegate, CLONE_INTO_CGROUP is subject to the same namespace
// containment rule as cgroup.procs migrations.
TEST_F(Cgroup2Test, NsdelegateCloneIntoCgroup) {
  Cgroup cin = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_ci"));
  Cgroup cout = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_ci_out"));
  const std::string cin_procs = cin.Relpath("cgroup.procs");
  const std::string cin_path = cin.Path();
  const std::string cout_path = cout.Path();

  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup r2 = ASSERT_NO_ERRNO_AND_VALUE(m2.MountCgroup2fs("nsdelegate"));
  auto clean = Cleanup([] {
    // Clear the system-wide flag.
    Mounter m3(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    ASSERT_NO_ERRNO(m3.MountCgroup2fs());
  });

  // Skip if the environment could not actually turn nsdelegate on.
  const bool nsdelegate_applied =
      ASSERT_NO_ERRNO_AND_VALUE(NsdelegateApplied(r2.Path()));
  SKIP_IF(!nsdelegate_applied);

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(cin_procs.c_str(), "0") == 0);
    const int inside_fd = open(cin_path.c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(inside_fd >= 0);
    const int outside_fd = open(cout_path.c_str(), O_RDONLY | O_DIRECTORY);
    TEST_PCHECK(outside_fd >= 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);

    struct clone_args cl_args = {};
    cl_args.flags = CLONE_INTO_CGROUP;
    cl_args.exit_signal = SIGCHLD;

    // Destination outside the namespace: ENOENT.
    cl_args.cgroup = static_cast<uint64_t>(outside_fd);
    TEST_CHECK(clone3(&cl_args, sizeof(cl_args)) < 0);
    TEST_CHECK(errno == ENOENT);

    // Destination inside the namespace: allowed.
    cl_args.cgroup = static_cast<uint64_t>(inside_fd);
    const pid_t grandchild = clone3(&cl_args, sizeof(cl_args));
    TEST_PCHECK(grandchild >= 0);
    if (grandchild == 0) {
      _exit(0);
    }
    int status;
    TEST_PCHECK(waitpid(grandchild, &status, 0) == grandchild);
    TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// The nsdelegate option is ignored on mounts from non-init cgroupns's.
TEST_F(Cgroup2Test, NsdelegateIgnoredFromNonInitNamespace) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_noninit"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string max_depth = cg.Relpath("cgroup.max.depth");

  // Make sure the flag is off.
  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  ASSERT_NO_ERRNO(m2.MountCgroup2fs());

  TempPath mntdir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = mntdir.path();

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    TEST_PCHECK(mount("none", dir.c_str(), "cgroup2", 0, "nsdelegate") == 0);
    // The flag was not applied: writes to the namespace root are allowed.
    TEST_CHECK(WriteFileErrno(max_depth.c_str(), "max") == 0);
    TEST_PCHECK(umount2(dir.c_str(), MNT_DETACH) == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  // In case the child died before unmounting.
  umount2(dir.c_str(), MNT_DETACH);
}

// The nsdelegate write check uses the cgroup namespace captured at open(2)
// time, not the writer's namespace at write(2) time: an FD opened in the
// init namespace remains writable after the writer enters a cgroup
// namespace rooted at the FD's cgroup.
TEST_F(Cgroup2Test, NsdelegateWriteUsesOpenTimeNamespaceInitOpener) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_otn_a"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string max_depth = cg.Relpath("cgroup.max.depth");

  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup r2 = ASSERT_NO_ERRNO_AND_VALUE(m2.MountCgroup2fs("nsdelegate"));
  auto clean = Cleanup([] {
    // Clear the system-wide flag.
    Mounter m3(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    ASSERT_NO_ERRNO(m3.MountCgroup2fs());
  });

  // Skip if the environment could not actually turn nsdelegate on.
  const bool nsdelegate_applied =
      ASSERT_NO_ERRNO_AND_VALUE(NsdelegateApplied(r2.Path()));
  SKIP_IF(!nsdelegate_applied);

  const pid_t pid = fork();
  if (pid == 0) {
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    // Opened before unshare: the FD captures the init cgroup namespace.
    const int fd = open(max_depth.c_str(), O_WRONLY);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    // A write through a freshly opened FD from inside the namespace
    // is rejected...
    TEST_CHECK(WriteFileErrno(max_depth.c_str(), "max") == EPERM);
    // ...but the FD opened from the init namespace writes successfully.
    TEST_CHECK(WriteFdErrno(fd, "max") == 0);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

// The converse: an FD opened inside a cgroup namespace rooted at the FD's
// cgroup stays subject to the nsdelegate EPERM even when the write comes
// from a task that has since returned to the init namespace.
TEST_F(Cgroup2Test, NsdelegateWriteUsesOpenTimeNamespaceNamespacedOpener) {
  Cgroup cg = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("nsd_otn_b"));
  const std::string procs = cg.Relpath("cgroup.procs");
  const std::string max_depth = cg.Relpath("cgroup.max.depth");

  Mounter m2(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup r2 = ASSERT_NO_ERRNO_AND_VALUE(m2.MountCgroup2fs("nsdelegate"));
  auto clean = Cleanup([] {
    // Clear the system-wide flag.
    Mounter m3(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    ASSERT_NO_ERRNO(m3.MountCgroup2fs());
  });

  // Skip if the environment could not actually turn nsdelegate on.
  const bool nsdelegate_applied =
      ASSERT_NO_ERRNO_AND_VALUE(NsdelegateApplied(r2.Path()));
  SKIP_IF(!nsdelegate_applied);

  const pid_t pid = fork();
  if (pid == 0) {
    const int initns = open("/proc/self/ns/cgroup", O_RDONLY);
    TEST_PCHECK(initns >= 0);
    TEST_CHECK(WriteFileErrno(procs.c_str(), "0") == 0);
    TEST_PCHECK(unshare(CLONE_NEWCGROUP) == 0);
    // Opened inside the namespace: the FD captures the non-init namespace
    // whose root is this cgroup.
    const int fd = open(max_depth.c_str(), O_WRONLY);
    TEST_PCHECK(fd >= 0);
    // Return to the init namespace.
    TEST_PCHECK(setns(initns, CLONE_NEWCGROUP) == 0);
    // A write using a fresh open from the init namespace is allowed...
    TEST_CHECK(WriteFileErrno(max_depth.c_str(), "max") == 0);
    // ...but the FD opened inside the namespace is rejected.
    TEST_CHECK(WriteFdErrno(fd, "max") == EPERM);
    _exit(0);
  }
  ASSERT_GT(pid, 0);
  int status;
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST_F(Cgroup2Test, Xattr) {
  const char* path = c().Path().c_str();
  const char name[] = "trusted.test";
  const char val = 'a';
  const size_t size = sizeof(val);

  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0), SyscallSucceeds());

  char got = '\0';
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallSucceedsWithValue(size));
  EXPECT_EQ(val, got);

  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)),
              SyscallSucceedsWithValue(sizeof(name)));
  EXPECT_STREQ(list, name);

  EXPECT_THAT(removexattr(path, name), SyscallSucceeds());
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallFailsWithErrno(ENODATA));
}

TEST_F(Cgroup2Test, TrustedXattrWithoutCapSysAdmin) {
  const char* path = c().Path().c_str();
  AutoCapability cap(CAP_SYS_ADMIN, false);

  const char name[] = "trusted.test";
  const char val = 'a';
  const size_t size = sizeof(val);

  EXPECT_THAT(setxattr(path, name, &val, size, /*flags=*/0),
              SyscallFailsWithErrno(EPERM));

  char got = '\0';
  EXPECT_THAT(getxattr(path, name, &got, size), SyscallFailsWithErrno(ENODATA));

  char list[sizeof(name)];
  EXPECT_THAT(listxattr(path, list, sizeof(list)), SyscallSucceedsWithValue(0));

  EXPECT_THAT(removexattr(path, name), SyscallFailsWithErrno(EPERM));
}

TEST_F(Cgroup2Test, DetachedMountBindFails) {
  Mounter m(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
  Cgroup c = ASSERT_NO_ERRNO_AND_VALUE(m.MountCgroup2fs());

  // Hold an open fd on the mount so that it survives the lazy umount, then
  // name it again through /proc/self/fd.
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(c.Path(), O_RDONLY | O_DIRECTORY));
  ASSERT_THAT(umount2(c.Path().c_str(), MNT_DETACH), SyscallSucceeds());
  m.release(c);

  const TempPath target = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string fd_path = absl::StrFormat("/proc/self/fd/%d", fd.get());
  EXPECT_THAT(mount(fd_path.c_str(), target.path().c_str(), "", MS_BIND, 0),
              SyscallFailsWithErrno(EINVAL));
}

// An ancestor's cgroup.events must report "populated 1" while any descendant
// has a live task, even after a mid-level cgroup's own tasks all leave.
// Regression test for ancestor counters being decremented when a mid-level
// cgroup drained while its child was still populated; the child's later
// drain then decremented again, leaving the counter permanently negative.
TEST_F(Cgroup2Test, PopulatedAccountsForDescendantsWhenMidLevelDrains) {
  Cgroup w = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("pop_w"));
  Cgroup a = ASSERT_NO_ERRNO_AND_VALUE(w.CreateChild("pop_a"));
  Cgroup b = ASSERT_NO_ERRNO_AND_VALUE(a.CreateChild("pop_b"));
  Cgroup drain = ASSERT_NO_ERRNO_AND_VALUE(c().CreateChild("pop_drain"));

  // Two children block on a pipe: one in a, one in a's child b.
  int go_fds[2];
  ASSERT_THAT(pipe(go_fds), SyscallSucceeds());
  FileDescriptor go_r(go_fds[0]);
  FileDescriptor go_w(go_fds[1]);

  pid_t t1 = fork();
  if (t1 == 0) {
    go_w.reset();
    char token;
    TEST_PCHECK(read(go_r.get(), &token, 1) >= 0);
    _exit(0);
  }
  ASSERT_GT(t1, 0);
  pid_t t2 = fork();
  if (t2 == 0) {
    go_w.reset();
    char token;
    TEST_PCHECK(read(go_r.get(), &token, 1) >= 0);
    _exit(0);
  }
  ASSERT_GT(t2, 0);
  go_r.reset();

  ASSERT_NO_ERRNO(a.Enter(t1));
  ASSERT_NO_ERRNO(b.Enter(t2));
  EXPECT_THAT(w.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  EXPECT_THAT(a.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  EXPECT_THAT(b.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));

  // Drain a; b's task keeps a's subtree populated.
  ASSERT_NO_ERRNO(drain.Enter(t1));
  EXPECT_THAT(a.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")))
      << "mid-level cgroup reports populated 0 while its child has a task";
  EXPECT_THAT(w.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")))
      << "ancestor reports populated 0 while a descendant has a task";

  // Drain b; the subtree is now empty.
  ASSERT_NO_ERRNO(drain.Enter(t2));
  EXPECT_THAT(a.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));
  EXPECT_THAT(w.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 0")));

  // Repopulate a; w must flip back to 1 (catches a negative counter).
  ASSERT_NO_ERRNO(a.Enter(t1));
  EXPECT_THAT(a.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")));
  EXPECT_THAT(w.ReadControlFile("cgroup.events"),
              IsPosixErrorOkAndHolds(HasSubstr("populated 1")))
      << "ancestor stuck at populated 0: populated-children counter went "
         "negative when the mid-level cgroup and its child drained";

  // Release and reap the children.
  go_w.reset();
  int status;
  ASSERT_EQ(waitpid(t1, &status, 0), t1);
  EXPECT_TRUE(WIFEXITED(status));
  ASSERT_EQ(waitpid(t2, &status, 0), t2);
  EXPECT_TRUE(WIFEXITED(status));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
