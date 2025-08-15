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

#include "test/syscalls/linux/exec.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cassert>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

#ifndef SUID_DUMP_DISABLE
#define SUID_DUMP_DISABLE 0
#endif /* SUID_DUMP_DISABLE */
#ifndef SUID_DUMP_USER
#define SUID_DUMP_USER 1
#endif /* SUID_DUMP_USER */
#ifndef SUID_DUMP_ROOT
#define SUID_DUMP_ROOT 2
#endif /* SUID_DUMP_ROOT */

constexpr char kBasicWorkload[] = "test/syscalls/linux/exec_basic_workload";
constexpr char kCheckEuidProgram[] = "test/syscalls/linux/exec_check_creds";
constexpr char kExitScript[] = "test/syscalls/linux/exit_script";
constexpr char kStateWorkload[] = "test/syscalls/linux/exec_state_workload";
constexpr char kProcExeWorkload[] =
    "test/syscalls/linux/exec_proc_exe_workload";
constexpr char kAssertClosedWorkload[] =
    "test/syscalls/linux/exec_assert_closed_workload";
constexpr char kPriorityWorkload[] = "test/syscalls/linux/priority_execve";

constexpr char kExit42[] = "--exec_exit_42";
constexpr char kExecWithThread[] = "--exec_exec_with_thread";
constexpr char kExecFromThread[] = "--exec_exec_from_thread";
constexpr char kExecInParent[] = "--exec_exec_in_parent";
constexpr char kWriteAndWaitForPid[] = "--exec_write_and_wait_for_pid";

// Runs file specified by dirfd and pathname with argv and checks that the exit
// status is expect_status and that stderr contains expect_stderr.
void CheckExecHelper(const absl::optional<int32_t> dirfd,
                     const std::string& pathname, const ExecveArray& argv,
                     const ExecveArray& envv, const int flags,
                     int expect_status, const std::string& expect_stderr) {
  int pipe_fds[2];
  ASSERT_THAT(pipe2(pipe_fds, O_CLOEXEC), SyscallSucceeds());

  FileDescriptor read_fd(pipe_fds[0]);
  FileDescriptor write_fd(pipe_fds[1]);

  pid_t child;
  int execve_errno;

  const auto remap_stderr = [pipe_fds] {
    // Remap stdin and stdout to /dev/null.
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
      _exit(errno);
    }

    int ret = dup2(fd, 0);
    if (ret < 0) {
      _exit(errno);
    }

    ret = dup2(fd, 1);
    if (ret < 0) {
      _exit(errno);
    }

    // And stderr to the pipe.
    ret = dup2(pipe_fds[1], 2);
    if (ret < 0) {
      _exit(errno);
    }

    // Here, we'd ideally close all other FDs inherited from the parent.
    // However, that's not worth the effort and CloexecNormalFile and
    // CloexecEventfd depend on that not happening.
  };

  Cleanup kill;
  if (dirfd.has_value()) {
    kill = ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(*dirfd, pathname, argv,
                                                     envv, flags, remap_stderr,
                                                     &child, &execve_errno));
  } else {
    kill = ASSERT_NO_ERRNO_AND_VALUE(
        ForkAndExec(pathname, argv, envv, remap_stderr, &child, &execve_errno));
  }

  ASSERT_EQ(0, execve_errno);

  // Not needed anymore.
  write_fd.reset();

  // Read stderr until the child exits.
  std::string output;
  constexpr int kSize = 128;
  char buf[kSize];
  int n;
  do {
    ASSERT_THAT(n = ReadFd(read_fd.get(), buf, kSize), SyscallSucceeds());
    if (n > 0) {
      output.append(buf, n);
    }
  } while (n > 0);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  EXPECT_EQ(status, expect_status) << output;

  // Process cleanup no longer needed.
  kill.Release();

  EXPECT_TRUE(absl::StrContains(output, expect_stderr)) << output;
}

void CheckExec(const std::string& filename, const ExecveArray& argv,
               const ExecveArray& envv, int expect_status,
               const std::string& expect_stderr) {
  CheckExecHelper(/*dirfd=*/absl::optional<int32_t>(), filename, argv, envv,
                  /*flags=*/0, expect_status, expect_stderr);
}

void CheckExecveat(const int32_t dirfd, const std::string& pathname,
                   const ExecveArray& argv, const ExecveArray& envv,
                   const int flags, int expect_status,
                   const std::string& expect_stderr) {
  CheckExecHelper(absl::optional<int32_t>(dirfd), pathname, argv, envv, flags,
                  expect_status, expect_stderr);
}

TEST(ExecTest, EmptyPath) {
  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExec("", {}, {}, nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOENT);
}

TEST(ExecTest, Basic) {
  CheckExec(RunfilePath(kBasicWorkload), {RunfilePath(kBasicWorkload)}, {},
            ArgEnvExitStatus(0, 0),
            absl::StrCat(RunfilePath(kBasicWorkload), "\n"));
}

TEST(ExecTest, OneArg) {
  CheckExec(RunfilePath(kBasicWorkload), {RunfilePath(kBasicWorkload), "1"}, {},
            ArgEnvExitStatus(1, 0),
            absl::StrCat(RunfilePath(kBasicWorkload), "\n1\n"));
}

TEST(ExecTest, FiveArg) {
  CheckExec(RunfilePath(kBasicWorkload),
            {RunfilePath(kBasicWorkload), "1", "2", "3", "4", "5"}, {},
            ArgEnvExitStatus(5, 0),
            absl::StrCat(RunfilePath(kBasicWorkload), "\n1\n2\n3\n4\n5\n"));
}

TEST(ExecTest, OneEnv) {
  CheckExec(RunfilePath(kBasicWorkload), {RunfilePath(kBasicWorkload)}, {"1"},
            ArgEnvExitStatus(0, 1),
            absl::StrCat(RunfilePath(kBasicWorkload), "\n1\n"));
}

TEST(ExecTest, FiveEnv) {
  CheckExec(RunfilePath(kBasicWorkload), {RunfilePath(kBasicWorkload)},
            {"1", "2", "3", "4", "5"}, ArgEnvExitStatus(0, 5),
            absl::StrCat(RunfilePath(kBasicWorkload), "\n1\n2\n3\n4\n5\n"));
}

TEST(ExecTest, OneArgOneEnv) {
  CheckExec(RunfilePath(kBasicWorkload), {RunfilePath(kBasicWorkload), "arg"},
            {"env"}, ArgEnvExitStatus(1, 1),
            absl::StrCat(RunfilePath(kBasicWorkload), "\narg\nenv\n"));
}

TEST(ExecTest, InterpreterScript) {
  CheckExec(RunfilePath(kExitScript), {RunfilePath(kExitScript), "25"}, {},
            ArgEnvExitStatus(25, 0), "");
}

std::string GetShortTestTmpdir() {
#ifdef ANDROID
  // Using GetAbsoluteTestTmpdir() can cause the tmp directory path to exceed
  // the max length of the interpreter script path (127).
  //
  // However, existing systems that are built with the ANDROID configuration
  // have their temp directory in a different location, and must respect the
  // TEST_TMPDIR.
  return GetAbsoluteTestTmpdir();
#else
  return "/tmp";
#endif  // ANDROID
}

// Everything after the path in the interpreter script is a single argument.
TEST(ExecTest, InterpreterScriptArgSplit) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path(), " foo bar"), 0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo bar\n", script.path(), "\n"));
}

// Original argv[0] is replaced with the script path.
TEST(ExecTest, InterpreterScriptArgvZero) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  CheckExec(script.path(), {"REPLACED"}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// Original argv[0] is replaced with the script path, exactly as passed to
// execve.
TEST(ExecTest, InterpreterScriptArgvZeroRelative) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  auto cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  auto script_relative =
      ASSERT_NO_ERRNO_AND_VALUE(GetRelativePath(cwd, script.path()));

  CheckExec(script_relative, {"REPLACED"}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script_relative, "\n"));
}

// argv[0] is added as the script path, even if there was none.
TEST(ExecTest, InterpreterScriptArgvZeroAdded) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  CheckExec(script.path(), {}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// A NUL byte in the script line ends parsing.
TEST(ExecTest, InterpreterScriptArgNUL) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(),
      absl::StrCat("#!", link.path(), " foo", std::string(1, '\0'), "bar"),
      0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo\n", script.path(), "\n"));
}

// Trailing whitespace following interpreter path is ignored.
TEST(ExecTest, InterpreterScriptTrailingWhitespace) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path(), "  \n"), 0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// Multiple whitespace characters between interpreter and arg allowed.
TEST(ExecTest, InterpreterScriptArgWhitespace) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path(), "  foo"), 0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo\n", script.path(), "\n"));
}

TEST(ExecTest, InterpreterScriptNoPath) {
  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetShortTestTmpdir(), "#!\n\n", 0755));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOEXEC);
}

// AT_EXECFN is the path passed to execve.
TEST(ExecTest, ExecFn) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kStateWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path(), " PrintExecFn"),
      0755));

  // Pass the script as a relative path and assert that is what appears in
  // AT_EXECFN.
  auto cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  auto script_relative =
      ASSERT_NO_ERRNO_AND_VALUE(GetRelativePath(cwd, script.path()));

  CheckExec(script_relative, {script_relative}, {}, ArgEnvExitStatus(0, 0),
            absl::StrCat(script_relative, "\n"));
}

TEST(ExecTest, ExecName) {
  std::string path = RunfilePath(kStateWorkload);

  CheckExec(path, {path, "PrintExecName"}, {}, ArgEnvExitStatus(0, 0),
            absl::StrCat(Basename(path).substr(0, 15), "\n"));
}

TEST(ExecTest, ExecNameScript) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetShortTestTmpdir(), RunfilePath(kStateWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetShortTestTmpdir(), absl::StrCat("#!", link.path(), " PrintExecName"),
      0755));

  std::string script_path = script.path();

  CheckExec(script_path, {script_path}, {}, ArgEnvExitStatus(0, 0),
            absl::StrCat(Basename(script_path).substr(0, 15), "\n"));
}

// execve may be called by a multithreaded process.
TEST(ExecTest, WithSiblingThread) {
  CheckExec("/proc/self/exe", {"/proc/self/exe", kExecWithThread}, {},
            W_EXITCODE(42, 0), "");
}

// execve may be called from a thread other than the leader of a multithreaded
// process.
TEST(ExecTest, FromSiblingThread) {
  CheckExec("/proc/self/exe", {"/proc/self/exe", kExecFromThread}, {},
            W_EXITCODE(42, 0), "");
}

TEST(ExecTest, NotFound) {
  char* const argv[] = {nullptr};
  char* const envp[] = {nullptr};
  EXPECT_THAT(execve("/file/does/not/exist", argv, envp),
              SyscallFailsWithErrno(ENOENT));
}

TEST(ExecTest, NoExecPerm) {
  char* const argv[] = {nullptr};
  char* const envp[] = {nullptr};
  auto f = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  EXPECT_THAT(execve(f.path().c_str(), argv, envp),
              SyscallFailsWithErrno(EACCES));
}

// A signal handler we never expect to be called.
void SignalHandler(int signo) {
  std::cerr << "Signal " << signo << " raised." << std::endl;
  exit(1);
}

// Signal handlers are reset on execve(2), unless they have default or ignored
// disposition.
TEST(ExecStateTest, HandlerReset) {
  struct sigaction sa;
  sa.sa_handler = SignalHandler;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

  ExecveArray args = {
      RunfilePath(kStateWorkload),
      "CheckSigHandler",
      absl::StrCat(SIGUSR1),
      absl::StrCat(absl::Hex(reinterpret_cast<uintptr_t>(SIG_DFL))),
  };

  CheckExec(RunfilePath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
}

// Ignored signal dispositions are not reset.
TEST(ExecStateTest, IgnorePreserved) {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

  ExecveArray args = {
      RunfilePath(kStateWorkload),
      "CheckSigHandler",
      absl::StrCat(SIGUSR1),
      absl::StrCat(absl::Hex(reinterpret_cast<uintptr_t>(SIG_IGN))),
  };

  CheckExec(RunfilePath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
}

// Signal masks are not reset on exec
TEST(ExecStateTest, SignalMask) {
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  ASSERT_THAT(sigprocmask(SIG_BLOCK, &s, nullptr), SyscallSucceeds());

  ExecveArray args = {
      RunfilePath(kStateWorkload),
      "CheckSigBlocked",
      absl::StrCat(SIGUSR1),
  };

  CheckExec(RunfilePath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
}

// itimers persist across execve.
// N.B. Timers created with timer_create(2) should not be preserved!
TEST(ExecStateTest, ItimerPreserved) {
  // The fork in ForkAndExec clears itimers, so only set them up after fork.
  auto setup_itimer = [] {
    // Ignore SIGALRM, as we don't actually care about timer
    // expirations.
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    int ret = sigaction(SIGALRM, &sa, nullptr);
    if (ret < 0) {
      _exit(errno);
    }

    struct itimerval itv;
    itv.it_interval.tv_sec = 1;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = 1;
    itv.it_value.tv_usec = 0;
    ret = setitimer(ITIMER_REAL, &itv, nullptr);
    if (ret < 0) {
      _exit(errno);
    }
  };

  std::string filename = RunfilePath(kStateWorkload);
  ExecveArray argv = {
      filename,
      "CheckItimerEnabled",
      absl::StrCat(ITIMER_REAL),
  };

  pid_t child;
  int execve_errno;
  auto kill = ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(filename, argv, {}, setup_itimer, &child, &execve_errno));
  ASSERT_EQ(0, execve_errno);

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  EXPECT_EQ(0, status);

  // Process cleanup no longer needed.
  kill.Release();
}

TEST(ProcSelfExe, ChangesAcrossExecve) {
  // See exec_proc_exe_workload for more details. We simply
  // assert that the /proc/self/exe link changes across execve.
  CheckExec(RunfilePath(kProcExeWorkload),
            {RunfilePath(kProcExeWorkload),
             ASSERT_NO_ERRNO_AND_VALUE(ProcessExePath(getpid()))},
            {}, W_EXITCODE(0, 0), "");
}

TEST(ExecTest, CloexecNormalFile) {
  TempPath tempFile = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "bar", 0755));
  const FileDescriptor fd_closed_on_exec =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tempFile.path(), O_RDONLY | O_CLOEXEC));

  CheckExec(RunfilePath(kAssertClosedWorkload),
            {RunfilePath(kAssertClosedWorkload),
             absl::StrCat(fd_closed_on_exec.get())},
            {}, W_EXITCODE(0, 0), "");

  // The assert closed workload exits with code 2 if the file still exists.  We
  // can use this to do a negative test.
  const FileDescriptor fd_open_on_exec =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tempFile.path(), O_RDONLY));

  CheckExec(
      RunfilePath(kAssertClosedWorkload),
      {RunfilePath(kAssertClosedWorkload), absl::StrCat(fd_open_on_exec.get())},
      {}, W_EXITCODE(2, 0), "");
}

TEST(ExecTest, CloexecEventfd) {
  int efd;
  ASSERT_THAT(efd = eventfd(0, EFD_CLOEXEC), SyscallSucceeds());
  FileDescriptor fd(efd);

  CheckExec(RunfilePath(kAssertClosedWorkload),
            {RunfilePath(kAssertClosedWorkload), absl::StrCat(fd.get())}, {},
            W_EXITCODE(0, 0), "");
}

constexpr int kLinuxMaxSymlinks = 40;

TEST(ExecTest, SymlinkLimitExceeded) {
  std::string path = RunfilePath(kBasicWorkload);

  // Hold onto TempPath objects so they are not destructed prematurely.
  std::vector<TempPath> symlinks;
  for (int i = 0; i < kLinuxMaxSymlinks + 1; i++) {
    symlinks.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), path)));
    path = symlinks[i].path();
  }

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(path, {path}, {}, /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ELOOP);
}

TEST(ExecTest, SymlinkLimitRefreshedForInterpreter) {
  std::string tmp_dir = GetAbsoluteTestTmpdir();
  std::string interpreter_path = "/bin/echo";
  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      tmp_dir, absl::StrCat("#!", interpreter_path), 0755));
  std::string script_path = script.path();

  // Hold onto TempPath objects so they are not destructed prematurely.
  std::vector<TempPath> interpreter_symlinks;
  std::vector<TempPath> script_symlinks;
  // Replace both the interpreter and script paths with symlink chains of just
  // over half the symlink limit each; this is the minimum required to test that
  // the symlink limit applies separately to each traversal, while tolerating
  // some symlinks in the resolution of (the original) interpreter_path and
  // script_path.
  for (int i = 0; i < (kLinuxMaxSymlinks / 2) + 1; i++) {
    interpreter_symlinks.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateSymlinkTo(tmp_dir, interpreter_path)));
    interpreter_path = interpreter_symlinks[i].path();
    script_symlinks.push_back(ASSERT_NO_ERRNO_AND_VALUE(
        TempPath::CreateSymlinkTo(tmp_dir, script_path)));
    script_path = script_symlinks[i].path();
  }

  CheckExec(script_path, {script_path}, {}, ArgEnvExitStatus(0, 0), "");
}

TEST(ExecveatTest, BasicWithFDCWD) {
  std::string path = RunfilePath(kBasicWorkload);
  CheckExecveat(AT_FDCWD, path, {path}, {}, /*flags=*/0, ArgEnvExitStatus(0, 0),
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, Basic) {
  std::string absolute_path = RunfilePath(kBasicWorkload);
  std::string parent_dir = std::string(Dirname(absolute_path));
  std::string base = std::string(Basename(absolute_path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));

  CheckExecveat(dirfd.get(), base, {absolute_path}, {}, /*flags=*/0,
                ArgEnvExitStatus(0, 0), absl::StrCat(absolute_path, "\n"));
}

TEST(ExecveatTest, FDNotADirectory) {
  std::string absolute_path = RunfilePath(kBasicWorkload);
  std::string base = std::string(Basename(absolute_path));
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(absolute_path, 0));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(fd.get(), base, {absolute_path}, {},
                                            /*flags=*/0, /*child=*/nullptr,
                                            &execve_errno));
  EXPECT_EQ(execve_errno, ENOTDIR);
}

TEST(ExecveatTest, AbsolutePathWithFDCWD) {
  std::string path = RunfilePath(kBasicWorkload);
  CheckExecveat(AT_FDCWD, path, {path}, {}, ArgEnvExitStatus(0, 0), 0,
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, AbsolutePath) {
  std::string path = RunfilePath(kBasicWorkload);
  // File descriptor should be ignored when an absolute path is given.
  const int32_t badFD = -1;
  CheckExecveat(badFD, path, {path}, {}, ArgEnvExitStatus(0, 0), 0,
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, EmptyPathBasic) {
  std::string path = RunfilePath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  CheckExecveat(fd.get(), "", {path}, {}, AT_EMPTY_PATH, ArgEnvExitStatus(0, 0),
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, EmptyPathWithDirFD) {
  std::string path = RunfilePath(kBasicWorkload);
  std::string parent_dir = std::string(Dirname(path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(dirfd.get(), "", {path}, {},
                                            AT_EMPTY_PATH,
                                            /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, EACCES);
}

TEST(ExecveatTest, EmptyPathWithoutEmptyPathFlag) {
  std::string path = RunfilePath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(
      fd.get(), "", {path}, {}, /*flags=*/0, /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOENT);
}

TEST(ExecveatTest, AbsolutePathWithEmptyPathFlag) {
  std::string path = RunfilePath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  CheckExecveat(fd.get(), path, {path}, {}, AT_EMPTY_PATH,
                ArgEnvExitStatus(0, 0), absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, RelativePathWithEmptyPathFlag) {
  std::string absolute_path = RunfilePath(kBasicWorkload);
  std::string parent_dir = std::string(Dirname(absolute_path));
  std::string base = std::string(Basename(absolute_path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));

  CheckExecveat(dirfd.get(), base, {absolute_path}, {}, AT_EMPTY_PATH,
                ArgEnvExitStatus(0, 0), absl::StrCat(absolute_path, "\n"));
}

TEST(ExecveatTest, SymlinkNoFollowWithRelativePath) {
  std::string parent_dir = GetAbsoluteTestTmpdir();
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent_dir, RunfilePath(kBasicWorkload)));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));
  std::string base = std::string(Basename(link.path()));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(dirfd.get(), base, {base}, {},
                                            AT_SYMLINK_NOFOLLOW,
                                            /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ELOOP);
}

TEST(ExecveatTest, UnshareFiles) {
  TempPath tempFile = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "bar", 0755));
  const FileDescriptor fd_closed_on_exec =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tempFile.path(), O_RDONLY | O_CLOEXEC));

  ExecveArray argv = {"test"};
  ExecveArray envp;
  std::string child_path = RunfilePath(kBasicWorkload);
  pid_t child =
      syscall(__NR_clone, SIGCHLD | CLONE_VFORK | CLONE_FILES, 0, 0, 0, 0);
  if (child == 0) {
    execve(child_path.c_str(), argv.get(), envp.get());
    _exit(1);
  }
  ASSERT_THAT(child, SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child, &status, 0), SyscallSucceeds());
  EXPECT_EQ(status, 0);

  struct stat st;
  EXPECT_THAT(fstat(fd_closed_on_exec.get(), &st), SyscallSucceeds());
}

TEST(ExecveatTest, SymlinkNoFollowWithAbsolutePath) {
  std::string parent_dir = GetAbsoluteTestTmpdir();
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(parent_dir, RunfilePath(kBasicWorkload)));
  std::string path = link.path();

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(AT_FDCWD, path, {path}, {},
                                            AT_SYMLINK_NOFOLLOW,
                                            /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ELOOP);
}

TEST(ExecveatTest, SymlinkNoFollowAndEmptyPath) {
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(
      GetAbsoluteTestTmpdir(), RunfilePath(kBasicWorkload)));
  std::string path = link.path();
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, 0));

  CheckExecveat(fd.get(), "", {path}, {}, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                ArgEnvExitStatus(0, 0), absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, SymlinkNoFollowIgnoreSymlinkAncestor) {
  TempPath parent_link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo(GetAbsoluteTestTmpdir(), "/bin"));
  std::string path_with_symlink = JoinPath(parent_link.path(), "echo");

  CheckExecveat(AT_FDCWD, path_with_symlink, {path_with_symlink}, {},
                AT_SYMLINK_NOFOLLOW, ArgEnvExitStatus(0, 0), "");
}

TEST(ExecveatTest, SymlinkNoFollowWithNormalFile) {
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/bin", O_DIRECTORY));

  CheckExecveat(dirfd.get(), "echo", {"echo"}, {}, AT_SYMLINK_NOFOLLOW,
                ArgEnvExitStatus(0, 0), "");
}

TEST(ExecveatTest, BasicWithCloexecFD) {
  std::string path = RunfilePath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_CLOEXEC));

  CheckExecveat(fd.get(), "", {path}, {}, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH,
                ArgEnvExitStatus(0, 0), absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, InterpreterScriptWithCloexecFD) {
  std::string path = RunfilePath(kExitScript);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_CLOEXEC));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(fd.get(), "", {path}, {},
                                            AT_EMPTY_PATH, /*child=*/nullptr,
                                            &execve_errno));
  EXPECT_EQ(execve_errno, ENOENT);
}

TEST(ExecveatTest, InterpreterScriptWithCloexecDirFD) {
  std::string absolute_path = RunfilePath(kExitScript);
  std::string parent_dir = std::string(Dirname(absolute_path));
  std::string base = std::string(Basename(absolute_path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_CLOEXEC | O_DIRECTORY));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(dirfd.get(), base, {base}, {},
                                            /*flags=*/0, /*child=*/nullptr,
                                            &execve_errno));
  EXPECT_EQ(execve_errno, ENOENT);
}

TEST(ExecveatTest, InvalidFlags) {
  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(
      /*dirfd=*/-1, "", {}, {}, /*flags=*/0xFFFF, /*child=*/nullptr,
      &execve_errno));
  EXPECT_EQ(execve_errno, EINVAL);
}

// Priority consistent across calls to execve()
TEST(GetpriorityTest, ExecveMaintainsPriority) {
  int prio = 16;
  ASSERT_THAT(setpriority(PRIO_PROCESS, getpid(), prio), SyscallSucceeds());

  // To avoid trying to use negative exit values, check for
  // 20 - prio. Since prio should always be in the range [-20, 19],
  // this leave expected_exit_code in the range [1, 40].
  int expected_exit_code = 20 - prio;

  // Program run (priority_execve) will exit(X) where
  // X=getpriority(PRIO_PROCESS,0). Check that this exit value is prio.
  CheckExec(RunfilePath(kPriorityWorkload), {RunfilePath(kPriorityWorkload)},
            {}, W_EXITCODE(expected_exit_code, 0), "");
}

// Test that setpgid() fails on child processes after they call execve().
TEST(ExecTest, Setpgid) {
  const pid_t pid = fork();
  int status;
  ASSERT_NE(pid, -1);
  if (pid == 0) {
    ASSERT_THAT(ptrace(PTRACE_TRACEME, 0, 0, 0), SyscallSucceeds());
    raise(SIGSTOP);
    char* argv[] = {nullptr};
    char* envp[] = {nullptr};
    ASSERT_THAT(execve("/proc/self/exe", argv, envp), SyscallSucceeds());
  }

  EXPECT_THAT(setpgid(pid, pid), SyscallSucceeds())
      << "setpgid failed before execve";
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid))
      << "waitpid failed";
  ASSERT_THAT(WIFSTOPPED(status), 1);
  ASSERT_THAT(WSTOPSIG(status), SIGSTOP);
  ASSERT_THAT(
      ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC),
      SyscallSucceeds())
      << "ptrace failed";
  ASSERT_THAT(ptrace(PTRACE_CONT, pid, 0, 0), SyscallSucceeds())
      << "ptrace (PTRACE_CONT) failed";
  ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceedsWithValue(pid))
      << "waitpid failed";
  ASSERT_THAT(WIFSTOPPED(status), 1);
  ASSERT_THAT(WSTOPSIG(status), SIGTRAP);
  EXPECT_THAT(setpgid(pid, pid), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(setpgid(pid, getpid()), SyscallFailsWithErrno(EACCES));
  EXPECT_THAT(setpgid(getpid(), pid), SyscallSucceeds());
}

PosixErrorOr<TempPath> CreateSuidExecutable(std::string path) {
  std::string exec_blob;
  PosixError perr = GetContents(path, &exec_blob);
  RETURN_IF_ERRNO(perr);

  // Note that this wouldn't work if /tmp/ is mounted with nosuid.
  mode_t mode = 0755 | S_ISUID;
  return TempPath::CreateFileWith(GetShortTestTmpdir(), exec_blob, mode);
}

PosixErrorOr<TempPath> CreateSgidExecutable(std::string path) {
  std::string exec_blob;
  PosixError perr = GetContents(path, &exec_blob);
  RETURN_IF_ERRNO(perr);

  // Note that this wouldn't work if /tmp/ is mounted with nosuid.
  mode_t mode = 0755 | S_ISGID;
  return TempPath::CreateFileWith(GetShortTestTmpdir(), exec_blob, mode);
}

constexpr int kUnprivilegedUid = 12345;
constexpr int kUnprivilegedGid = 12345;

TEST(ExecTest, SUIDExecGainsUID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  TempPath suid_exe = ASSERT_NO_ERRNO_AND_VALUE(
      CreateSuidExecutable(RunfilePath(kCheckEuidProgram)));

  int privilegedUid = geteuid();
  // Use a separate thread so as to not pollute the other tests with the
  // unprivileged uid we're about to set.
  ScopedThread([&] {
    ASSERT_THAT(syscall(SYS_setresuid, kUnprivilegedUid, kUnprivilegedUid,
                        kUnprivilegedUid),
                SyscallSucceeds());
    ASSERT_EQ(geteuid(), kUnprivilegedUid);

    int dumpability;
    ASSERT_THAT(prctl(PR_SET_DUMPABLE, SUID_DUMP_USER), SyscallSucceeds());
    ASSERT_THAT(dumpability = prctl(PR_GET_DUMPABLE), SyscallSucceeds());
    ASSERT_EQ(dumpability, SUID_DUMP_USER);

    const ExecveArray argv = {
        suid_exe.path(),
        /*want_euid=*/absl::StrCat(privilegedUid),  // gained back original euid
        /*want_egid=*/absl::StrCat(getegid()),
        /*want_dumpability=*/absl::StrCat(SUID_DUMP_DISABLE)};  // but lost this
    CheckExec(suid_exe.path(), argv, /*envv=*/{}, /*expect_status=*/0,
              /*expect_stderr=*/"");
  });
}

TEST(ExecTest, SGIDExecGainsGID) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  TempPath suid_exe = ASSERT_NO_ERRNO_AND_VALUE(
      CreateSgidExecutable(RunfilePath(kCheckEuidProgram)));

  int privilegedGid = getegid();
  // Use a separate thread so as to not pollute the other tests with the
  // unprivileged gid we're about to set.
  ScopedThread([&] {
    ASSERT_THAT(syscall(SYS_setresgid, kUnprivilegedGid, kUnprivilegedGid,
                        kUnprivilegedGid),
                SyscallSucceeds());
    ASSERT_EQ(getegid(), kUnprivilegedGid);

    int dumpability;
    ASSERT_THAT(prctl(PR_SET_DUMPABLE, SUID_DUMP_USER), SyscallSucceeds());
    ASSERT_THAT(dumpability = prctl(PR_GET_DUMPABLE), SyscallSucceeds());
    ASSERT_EQ(dumpability, SUID_DUMP_USER);

    const ExecveArray argv = {
        suid_exe.path(),
        /*want_euid=*/absl::StrCat(geteuid()),
        /*want_egid=*/absl::StrCat(privilegedGid),  // gained back original gid
        /*want_dumpability=*/absl::StrCat(SUID_DUMP_DISABLE)};  // but lost this
    CheckExec(suid_exe.path(), argv, /*envv=*/{}, /*expect_status=*/0,
              /*expect_stderr=*/"");
  });
}

TEST(ExecTest, SUIDExecDoesntGainUIDWithNoNewPrivs) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  TempPath suid_exe = ASSERT_NO_ERRNO_AND_VALUE(
      CreateSuidExecutable(RunfilePath(kCheckEuidProgram)));

  // Use a separate thread so as to not pollute the other tests with the
  // unprivileged uid we're about to set.
  ScopedThread([&] {
    ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), SyscallSucceeds());
    ASSERT_THAT(syscall(SYS_setresuid, kUnprivilegedUid, kUnprivilegedUid,
                        kUnprivilegedUid),
                SyscallSucceeds());
    ASSERT_EQ(geteuid(), kUnprivilegedUid);

    const ExecveArray argv = {
        suid_exe.path(),
        /*want_euid=*/absl::StrCat(kUnprivilegedUid),  // remained unprivileged
        /*want_egid=*/absl::StrCat(getegid()),
        /*want_dumpability=*/absl::StrCat(SUID_DUMP_USER)};
    CheckExec(suid_exe.path(), argv, /*envv=*/{}, /*expect_status=*/0,
              /*expect_stderr=*/"");
  });
}

TEST(ExecTest, SUIDExecDoesntGainUIDForInterpreterScript) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  std::string contents = "#!/bin/sh\n[ \"$(id -u)\" -eq \"$1\" ]\n";

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetShortTestTmpdir(), contents, 0755));
  TempPath suid_exe =
      ASSERT_NO_ERRNO_AND_VALUE(CreateSuidExecutable(script.path()));

  // Use a separate thread so as to not pollute the other tests with the
  // unprivileged uid we're about to set.
  ScopedThread([&] {
    ASSERT_THAT(syscall(SYS_setresuid, kUnprivilegedUid, kUnprivilegedUid,
                        kUnprivilegedUid),
                SyscallSucceeds());
    ASSERT_EQ(geteuid(), kUnprivilegedUid);

    const ExecveArray argv = {
        suid_exe.path(),
        /*$1=*/absl::StrCat(kUnprivilegedUid),  // remained unprivileged
    };
    CheckExec(suid_exe.path(), argv, /*envv=*/{}, /*expect_status=*/0,
              /*expect_stderr=*/"");
  });
}

struct CloneExecArgs {
  const char* path;
  char* const* argv;
};

int DoExecveAfterClone(void* args_void) {
  const CloneExecArgs* args = static_cast<const CloneExecArgs*>(args_void);
  execve(args->path, args->argv, nullptr);
  _exit(1);
}

// Clones a new process with CLONE_FS and execve's into the provided path, and
// then checks that the child's exit status is as expected. This is a version
// of CheckExec that uses clone(2) with CLONE_FS instead of fork(2).
void CheckCloneFsExec(const std::string& path, const ExecveArray& argv,
                      int want_status) {
  CloneExecArgs args = {path.c_str(), argv.get()};
  struct clone_arg {
    char stack[1024] __attribute__((aligned(16)));
    char stack_ptr[0];
  } ca;
  pid_t child_pid;
  ASSERT_THAT(child_pid = clone(DoExecveAfterClone, ca.stack_ptr,
                                CLONE_FS | SIGCHLD, (void*)&args),
              SyscallSucceeds());

  int status;
  ASSERT_THAT(RetryEINTR(waitpid)(child_pid, &status, 0), SyscallSucceeds());
  EXPECT_EQ(status, want_status);
}

TEST(ExecTest, SUIDExecDoesntGainUIDWithSharedFSContext) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  TempPath suid_exe = ASSERT_NO_ERRNO_AND_VALUE(
      CreateSuidExecutable(RunfilePath(kCheckEuidProgram)));

  // Use a separate thread so as to not pollute the other tests with the
  // unprivileged uid we're about to set. ScopedThread will clone with CLONE_FS.
  ScopedThread([&] {
    ASSERT_THAT(syscall(SYS_setresuid, kUnprivilegedUid, kUnprivilegedUid,
                        kUnprivilegedUid),
                SyscallSucceeds());
    ASSERT_EQ(geteuid(), kUnprivilegedUid);

    const ExecveArray argv = {
        suid_exe.path(),
        /*want_euid=*/absl::StrCat(kUnprivilegedUid),  // remained unprivileged
        /*want_egid=*/absl::StrCat(getegid()),
        /*want_dumpability=*/absl::StrCat(SUID_DUMP_USER)};
    CheckCloneFsExec(suid_exe.path(), argv, /*want_status=*/0);
  });
}

TEST(ExecTest, SUIDExecDoesntGainUIDWithPtracerAttached) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  TempPath suid_exe = ASSERT_NO_ERRNO_AND_VALUE(
      CreateSuidExecutable(RunfilePath(kCheckEuidProgram)));

  int sockets[2];  // Used to establish a ptrace_attach before an execve.
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), SyscallSucceeds());

  const ExecveArray traceeArgv = {
      suid_exe.path(),
      /*want_euid=*/absl::StrCat(kUnprivilegedUid),  // remained unprivileged
      /*want_egid=*/absl::StrCat(getegid()),
      /*want_dumpability=*/absl::StrCat(SUID_DUMP_USER)};

  const pid_t tracee_pid = fork();
  if (tracee_pid == 0) {
    TEST_PCHECK(close(sockets[1]) == 0);
    TEST_PCHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == 0);
    // Indicate that the prctl has been set.
    TEST_PCHECK(WriteFd(sockets[0], "x", 1) == 1);

    // Wait until tracer has attached before execing.
    char done;
    TEST_PCHECK(ReadFd(sockets[0], &done, 1) == 1);

    // Become an unprivileged user, to test whether execing into the privileged
    // suid_exe will bestow the original uid.
    TEST_PCHECK(syscall(SYS_setresuid, kUnprivilegedUid, kUnprivilegedUid,
                        kUnprivilegedUid) == 0);
    TEST_PCHECK(geteuid() == kUnprivilegedUid);
    execve(traceeArgv.get()[0], traceeArgv.get(), nullptr);
    TEST_PCHECK_MSG(false, "survived execve");
  }
  ASSERT_THAT(tracee_pid, SyscallSucceeds());
  ASSERT_THAT(close(sockets[0]), SyscallSucceeds());

  const pid_t tracer_pid = fork();
  if (tracer_pid == 0) {
    // Wait until tracee has called prctl, or else we won't be able to attach.
    char done;
    TEST_PCHECK(ReadFd(sockets[1], &done, 1) == 1);

    TEST_PCHECK(ptrace(PTRACE_ATTACH, tracee_pid, 0, 0) == 0);
    // Indicate that we have attached.
    TEST_PCHECK(WriteFd(sockets[1], &done, 1) == 1);

    // Priv gain isn't prevented when the tracer has this cap, so drop it.
    TEST_PCHECK(SetCapability(CAP_SYS_PTRACE, false).ok());

    // Block until tracee enters signal-delivery-stop as a result of the
    // SIGSTOP sent by PTRACE_ATTACH. And then continue it.
    int status;
    TEST_PCHECK(waitpid(tracee_pid, &status, 0) == tracee_pid);
    TEST_CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    TEST_PCHECK(ptrace(PTRACE_CONT, tracee_pid, 0, 0) == 0);

    // The tracee enters signal-delivery-stop as a result of the SIGTRAP sent
    // by the kernel *after* execve returns. A waitpid() by the tracer will
    // annul the SIGTRAP and cause the tracee to exit normally, allowing the
    // parent's waitpid() to correctly judge the tracee's exit code.
    TEST_PCHECK(waitpid(tracee_pid, &status, 0) == tracee_pid);
    TEST_PCHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    _exit(0);
  }
  ASSERT_THAT(tracer_pid, SyscallSucceeds());

  int status;
  // Verify the tracee's (exec_check_creds's) exit code
  ASSERT_THAT(waitpid(tracee_pid, &status, 0), SyscallSucceeds());
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

TEST(ExecTest, ReadProcMemAfterExecFromChild) {
  // Fork and exec in the parent process.
  CheckExec("/proc/self/exe", {"/proc/self/exe", kExecInParent}, {},
            W_EXITCODE(42, 0), "");
}

/*
This function, along with writeAndWaitForPid, sets up the test case to verify
that a /proc/self/mem file descriptor is not leaked across an execve similar to
b/382136040.

The setup is as follows:

This function opens /proc/self/mem in a process we'll call P1.
* P1 forks, creating a child process P2.
* P1 (the parent) then execves to become a new process, P3, which runs
writeAndWaitForPid.
* P2 (the child) holds the memfd from P1. It waits for a
signal from P3.
* P3 maps some memory with a secret value and then signals P2 via
a pipe.
* P2, upon receiving the signal, tries to read from the secret's memory
location using the memfd it inherited. The test asserts that this pread in P2
fails, because the memfd should be tied to the (now defunct) address space of
P1, not the new address space of P3.
*/
void execInParent() {
  auto mem_fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self/mem", O_RDONLY));
  int pipe_fd[2] = {};
  TEST_PCHECK(pipe(pipe_fd) == 0);

  const auto readSecret = [&] {
    // Close writing end of the pipe.
    close(pipe_fd[1]);
    // Await parent OK to read the secret.
    uintptr_t addr;
    TEST_PCHECK_MSG(ReadFd(pipe_fd[0], &addr, sizeof(addr)) == sizeof(addr),
                    "Failed to read mmap address from the pipe.");
    // Close the reading end of the pipe.
    TEST_PCHECK(close(pipe_fd[0]) == 0);
    // Parent sent the signal. Read the secret.
    // Use /proc/mem fd from parent to try to read the secret.
    char secret[] = "secret";
    char output[sizeof(secret)];
    TEST_PCHECK_MSG(
        pread(mem_fd.get(), output, sizeof(output), addr) != sizeof(secret),
        "pread succeeded. It should have failed.");
  };
  pid_t pid = fork();
  // In child process.
  if (pid == 0) {
    readSecret();
    TEST_CHECK_MSG(!::testing::Test::HasFailure(),
                   "EXPECT*/ASSERT* failed. These are not async-signal-safe "
                   "and must not be called from fn.");
    _exit(0);
  }
  // In parent process.
  MaybeSave();
  TEST_PCHECK(close(pipe_fd[0]) == 0);
  TEST_CHECK(pid != -1);

  // Execve with args{function name, child_pid, pipe_fd[1]}
  const ExecveArray argv = {"/proc/self/exe", kWriteAndWaitForPid,
                            absl::StrCat(pid) /*child_pid*/,
                            absl::StrCat(pipe_fd[1])};
  const ExecveArray envv;
  execve("/proc/self/exe", argv.get(), envv.get());
}
/*
This function is the new program image after execve in execInParent. It maps a
"secret" value at a known address, signals the child of the original process to
proceed, and then waits for it to exit.
*/
void writeAndWaitForPid(int child_pid, int pipe_fd) {
  // mmap the same address that the child process will try to read.
  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(
      MmapAnon(kPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE));
  const char secret[] = "secret";
  absl::SNPrintF((char*)m.addr(), sizeof(secret), "%s", secret);

  // Tell the child process to read the secret location.
  uintptr_t addr = m.addr();
  TEST_PCHECK_MSG(WriteFd(pipe_fd, &addr, sizeof(addr)) == sizeof(addr),
                  "Failed to write mmap address to the pipe.");
  TEST_PCHECK(close(pipe_fd) == 0);

  // Wait for child process to read before the exit.
  int status;
  TEST_PCHECK_MSG(waitpid(child_pid, &status, 0) == child_pid,
                  "waitpid failed.");
  TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  exit(42);
}

void ExecWithThread() {
  // Used to ensure that the thread has actually started.
  absl::Mutex mu;
  bool started = false;

  ScopedThread t([&] {
    mu.Lock();
    started = true;
    mu.Unlock();

    while (true) {
      pause();
    }
  });

  mu.LockWhen(absl::Condition(&started));
  mu.Unlock();

  const ExecveArray argv = {"/proc/self/exe", kExit42};
  const ExecveArray envv;

  execve("/proc/self/exe", argv.get(), envv.get());
  exit(errno);
}

void ExecFromThread() {
  ScopedThread t([] {
    const ExecveArray argv = {"/proc/self/exe", kExit42};
    const ExecveArray envv;

    execve("/proc/self/exe", argv.get(), envv.get());
    exit(errno);
  });

  while (true) {
    pause();
  }
}

bool ValidateProcCmdlineVsArgv(const int argc, const char* const* argv) {
  auto contents_or = GetContents("/proc/self/cmdline");
  if (!contents_or.ok()) {
    std::cerr << "Unable to get /proc/self/cmdline: " << contents_or.error()
              << std::endl;
    return false;
  }
  auto contents = contents_or.ValueOrDie();
  if (contents.back() != '\0') {
    std::cerr << "Non-null terminated /proc/self/cmdline!" << std::endl;
    return false;
  }
  contents.pop_back();
  std::vector<std::string> procfs_cmdline = absl::StrSplit(contents, '\0');

  if (static_cast<int>(procfs_cmdline.size()) != argc) {
    std::cerr << "argc = " << argc << " != " << procfs_cmdline.size()
              << std::endl;
    return false;
  }

  for (int i = 0; i < argc; ++i) {
    if (procfs_cmdline[i] != argv[i]) {
      std::cerr << "Procfs command line argument " << i << " mismatch "
                << procfs_cmdline[i] << " != " << argv[i] << std::endl;
      return false;
    }
  }
  return true;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  // Start by validating that the stack argv is consistent with procfs.
  if (!gvisor::testing::ValidateProcCmdlineVsArgv(argc, argv)) {
    return 1;
  }

  // Some of these tests require no background threads, so check for them before
  // TestInit.
  for (int i = 0; i < argc; i++) {
    absl::string_view arg(argv[i]);

    if (arg == gvisor::testing::kExit42) {
      return 42;
    }
    if (arg == gvisor::testing::kExecWithThread) {
      gvisor::testing::ExecWithThread();
      return 1;
    }
    if (arg == gvisor::testing::kExecFromThread) {
      gvisor::testing::ExecFromThread();
      return 1;
    }
    if (arg == gvisor::testing::kExecInParent) {
      gvisor::testing::execInParent();
      return 1;
    }
    if (arg == gvisor::testing::kWriteAndWaitForPid) {
      int pid;
      if (!absl::SimpleAtoi(argv[i + 1], &pid)) {
        return 1;
      }
      int fd;
      if (!absl::SimpleAtoi(argv[i + 2], &fd)) {
        return 1;
      }
      gvisor::testing::writeAndWaitForPid(pid, fd);
      return 1;
    }
  }

  gvisor::testing::TestInit(&argc, &argv);
  return gvisor::testing::RunAllTests();
}
