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
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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
#include "absl/strings/match.h"
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
  // Sleep to wait past the sentry's internal 10ms memory usage stats update
  // throttle window (f.nextCommitScan in pgalloc.go).
  absl::SleepFor(absl::Milliseconds(15));
  const uint64_t usage_after =
      ASSERT_NO_ERRNO_AND_VALUE(c().ReadIntegerControlFile("memory.current"));
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
  // Sleep to wait past the sentry's internal 10ms memory usage stats update
  // throttle window (f.nextCommitScan in pgalloc.go).
  absl::SleepFor(absl::Milliseconds(15));

  // `child` should now reflect base_usage_child + kMemSize approximately.
  const uint64_t usage_child =
      ASSERT_NO_ERRNO_AND_VALUE(child.ReadIntegerControlFile("memory.current"));
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

}  // namespace
}  // namespace testing
}  // namespace gvisor
