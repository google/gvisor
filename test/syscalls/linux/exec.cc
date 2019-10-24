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
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kBasicWorkload[] = "exec_basic_workload";
constexpr char kExitScript[] = "exit_script";
constexpr char kStateWorkload[] = "exec_state_workload";
constexpr char kProcExeWorkload[] = "exec_proc_exe_workload";
constexpr char kAssertClosedWorkload[] = "exec_assert_closed_workload";
constexpr char kPriorityWorkload[] = "priority_execve";

std::string WorkloadPath(absl::string_view binary) {
  std::string full_path;
  char* test_src = getenv("TEST_SRCDIR");
  if (test_src) {
    full_path = JoinPath(test_src, "__main__/test/syscalls/linux", binary);
  }

  TEST_CHECK(full_path.empty() == false);
  return full_path;
}

constexpr char kExit42[] = "--exec_exit_42";
constexpr char kExecWithThread[] = "--exec_exec_with_thread";
constexpr char kExecFromThread[] = "--exec_exec_from_thread";

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
  EXPECT_EQ(status, expect_status);

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
  CheckExec(WorkloadPath(kBasicWorkload), {WorkloadPath(kBasicWorkload)}, {},
            ArgEnvExitStatus(0, 0),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\n"));
}

TEST(ExecTest, OneArg) {
  CheckExec(WorkloadPath(kBasicWorkload), {WorkloadPath(kBasicWorkload), "1"},
            {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\n1\n"));
}

TEST(ExecTest, FiveArg) {
  CheckExec(WorkloadPath(kBasicWorkload),
            {WorkloadPath(kBasicWorkload), "1", "2", "3", "4", "5"}, {},
            ArgEnvExitStatus(5, 0),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\n1\n2\n3\n4\n5\n"));
}

TEST(ExecTest, OneEnv) {
  CheckExec(WorkloadPath(kBasicWorkload), {WorkloadPath(kBasicWorkload)}, {"1"},
            ArgEnvExitStatus(0, 1),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\n1\n"));
}

TEST(ExecTest, FiveEnv) {
  CheckExec(WorkloadPath(kBasicWorkload), {WorkloadPath(kBasicWorkload)},
            {"1", "2", "3", "4", "5"}, ArgEnvExitStatus(0, 5),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\n1\n2\n3\n4\n5\n"));
}

TEST(ExecTest, OneArgOneEnv) {
  CheckExec(WorkloadPath(kBasicWorkload), {WorkloadPath(kBasicWorkload), "arg"},
            {"env"}, ArgEnvExitStatus(1, 1),
            absl::StrCat(WorkloadPath(kBasicWorkload), "\narg\nenv\n"));
}

TEST(ExecTest, InterpreterScript) {
  CheckExec(WorkloadPath(kExitScript), {WorkloadPath(kExitScript), "25"}, {},
            ArgEnvExitStatus(25, 0), "");
}

// Everything after the path in the interpreter script is a single argument.
TEST(ExecTest, InterpreterScriptArgSplit) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path(), " foo bar"),
      0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo bar\n", script.path(), "\n"));
}

// Original argv[0] is replaced with the script path.
TEST(ExecTest, InterpreterScriptArgvZero) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  CheckExec(script.path(), {"REPLACED"}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// Original argv[0] is replaced with the script path, exactly as passed to
// execve.
TEST(ExecTest, InterpreterScriptArgvZeroRelative) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  auto cwd = ASSERT_NO_ERRNO_AND_VALUE(GetCWD());
  auto script_relative =
      ASSERT_NO_ERRNO_AND_VALUE(GetRelativePath(cwd, script.path()));

  CheckExec(script_relative, {"REPLACED"}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script_relative, "\n"));
}

// argv[0] is added as the script path, even if there was none.
TEST(ExecTest, InterpreterScriptArgvZeroAdded) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path()), 0755));

  CheckExec(script.path(), {}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// A NUL byte in the script line ends parsing.
TEST(ExecTest, InterpreterScriptArgNUL) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(),
      absl::StrCat("#!", link.path(), " foo", std::string(1, '\0'), "bar"),
      0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo\n", script.path(), "\n"));
}

// Trailing whitespace following interpreter path is ignored.
TEST(ExecTest, InterpreterScriptTrailingWhitespace) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path(), "  "), 0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(1, 0),
            absl::StrCat(link.path(), "\n", script.path(), "\n"));
}

// Multiple whitespace characters between interpreter and arg allowed.
TEST(ExecTest, InterpreterScriptArgWhitespace) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kBasicWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path(), "  foo"), 0755));

  CheckExec(script.path(), {script.path()}, {}, ArgEnvExitStatus(2, 0),
            absl::StrCat(link.path(), "\nfoo\n", script.path(), "\n"));
}

TEST(ExecTest, InterpreterScriptNoPath) {
  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "#!", 0755));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(
      ForkAndExec(script.path(), {script.path()}, {}, nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOEXEC);
}

// AT_EXECFN is the path passed to execve.
TEST(ExecTest, ExecFn) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kStateWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::StrCat("#!", link.path(), " PrintExecFn"),
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
  std::string path = WorkloadPath(kStateWorkload);

  CheckExec(path, {path, "PrintExecName"}, {}, ArgEnvExitStatus(0, 0),
            absl::StrCat(Basename(path).substr(0, 15), "\n"));
}

TEST(ExecTest, ExecNameScript) {
  // Symlink through /tmp to ensure the path is short enough.
  TempPath link = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateSymlinkTo("/tmp", WorkloadPath(kStateWorkload)));

  TempPath script = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(),
      absl::StrCat("#!", link.path(), " PrintExecName"), 0755));

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
      WorkloadPath(kStateWorkload),
      "CheckSigHandler",
      absl::StrCat(SIGUSR1),
      absl::StrCat(absl::Hex(reinterpret_cast<uintptr_t>(SIG_DFL))),
  };

  CheckExec(WorkloadPath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
}

// Ignored signal dispositions are not reset.
TEST(ExecStateTest, IgnorePreserved) {
  struct sigaction sa;
  sa.sa_handler = SIG_IGN;
  ASSERT_THAT(sigaction(SIGUSR1, &sa, nullptr), SyscallSucceeds());

  ExecveArray args = {
      WorkloadPath(kStateWorkload),
      "CheckSigHandler",
      absl::StrCat(SIGUSR1),
      absl::StrCat(absl::Hex(reinterpret_cast<uintptr_t>(SIG_IGN))),
  };

  CheckExec(WorkloadPath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
}

// Signal masks are not reset on exec
TEST(ExecStateTest, SignalMask) {
  sigset_t s;
  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  ASSERT_THAT(sigprocmask(SIG_BLOCK, &s, nullptr), SyscallSucceeds());

  ExecveArray args = {
      WorkloadPath(kStateWorkload),
      "CheckSigBlocked",
      absl::StrCat(SIGUSR1),
  };

  CheckExec(WorkloadPath(kStateWorkload), args, {}, W_EXITCODE(0, 0), "");
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

  std::string filename = WorkloadPath(kStateWorkload);
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
  CheckExec(WorkloadPath(kProcExeWorkload),
            {WorkloadPath(kProcExeWorkload),
             ASSERT_NO_ERRNO_AND_VALUE(ProcessExePath(getpid()))},
            {}, W_EXITCODE(0, 0), "");
}

TEST(ExecTest, CloexecNormalFile) {
  TempPath tempFile = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "bar", 0755));
  const FileDescriptor fd_closed_on_exec =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tempFile.path(), O_RDONLY | O_CLOEXEC));

  CheckExec(WorkloadPath(kAssertClosedWorkload),
            {WorkloadPath(kAssertClosedWorkload),
             absl::StrCat(fd_closed_on_exec.get())},
            {}, W_EXITCODE(0, 0), "");

  // The assert closed workload exits with code 2 if the file still exists.  We
  // can use this to do a negative test.
  const FileDescriptor fd_open_on_exec =
      ASSERT_NO_ERRNO_AND_VALUE(Open(tempFile.path(), O_RDONLY));

  CheckExec(WorkloadPath(kAssertClosedWorkload),
            {WorkloadPath(kAssertClosedWorkload),
             absl::StrCat(fd_open_on_exec.get())},
            {}, W_EXITCODE(2, 0), "");
}

TEST(ExecTest, CloexecEventfd) {
  int efd;
  ASSERT_THAT(efd = eventfd(0, EFD_CLOEXEC), SyscallSucceeds());
  FileDescriptor fd(efd);

  CheckExec(WorkloadPath(kAssertClosedWorkload),
            {WorkloadPath(kAssertClosedWorkload), absl::StrCat(fd.get())}, {},
            W_EXITCODE(0, 0), "");
}

TEST(ExecveatTest, BasicWithFDCWD) {
  std::string path = WorkloadPath(kBasicWorkload);
  CheckExecveat(AT_FDCWD, path, {path}, {}, /*flags=*/0, ArgEnvExitStatus(0, 0),
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, Basic) {
  std::string absolute_path = WorkloadPath(kBasicWorkload);
  std::string parent_dir = std::string(Dirname(absolute_path));
  std::string relative_path = std::string(Basename(absolute_path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));

  CheckExecveat(dirfd.get(), relative_path, {absolute_path}, {}, /*flags=*/0,
                ArgEnvExitStatus(0, 0), absl::StrCat(absolute_path, "\n"));
}

TEST(ExecveatTest, FDNotADirectory) {
  std::string absolute_path = WorkloadPath(kBasicWorkload);
  std::string relative_path = std::string(Basename(absolute_path));
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(absolute_path, 0));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(fd.get(), relative_path,
                                            {absolute_path}, {}, /*flags=*/0,
                                            /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOTDIR);
}

TEST(ExecveatTest, AbsolutePathWithFDCWD) {
  std::string path = WorkloadPath(kBasicWorkload);
  CheckExecveat(AT_FDCWD, path, {path}, {}, ArgEnvExitStatus(0, 0), 0,
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, AbsolutePath) {
  std::string path = WorkloadPath(kBasicWorkload);
  // File descriptor should be ignored when an absolute path is given.
  const int32_t badFD = -1;
  CheckExecveat(badFD, path, {path}, {}, ArgEnvExitStatus(0, 0), 0,
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, EmptyPathBasic) {
  std::string path = WorkloadPath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  CheckExecveat(fd.get(), "", {path}, {}, AT_EMPTY_PATH, ArgEnvExitStatus(0, 0),
                absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, EmptyPathWithDirFD) {
  std::string path = WorkloadPath(kBasicWorkload);
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
  std::string path = WorkloadPath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  int execve_errno;
  ASSERT_NO_ERRNO_AND_VALUE(ForkAndExecveat(
      fd.get(), "", {path}, {}, /*flags=*/0, /*child=*/nullptr, &execve_errno));
  EXPECT_EQ(execve_errno, ENOENT);
}

TEST(ExecveatTest, AbsolutePathWithEmptyPathFlag) {
  std::string path = WorkloadPath(kBasicWorkload);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_PATH));

  CheckExecveat(fd.get(), path, {path}, {}, AT_EMPTY_PATH,
                ArgEnvExitStatus(0, 0), absl::StrCat(path, "\n"));
}

TEST(ExecveatTest, RelativePathWithEmptyPathFlag) {
  std::string absolute_path = WorkloadPath(kBasicWorkload);
  std::string parent_dir = std::string(Dirname(absolute_path));
  std::string relative_path = std::string(Basename(absolute_path));
  const FileDescriptor dirfd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(parent_dir, O_DIRECTORY));

  CheckExecveat(dirfd.get(), relative_path, {absolute_path}, {}, AT_EMPTY_PATH,
                ArgEnvExitStatus(0, 0), absl::StrCat(absolute_path, "\n"));
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
  CheckExec(WorkloadPath(kPriorityWorkload), {WorkloadPath(kPriorityWorkload)},
            {}, W_EXITCODE(expected_exit_code, 0), "");
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
    std::cerr << "Unable to get /proc/self/cmdline: " << contents_or.error();
    return false;
  }
  auto contents = contents_or.ValueOrDie();
  if (contents.back() != '\0') {
    std::cerr << "Non-null terminated /proc/self/cmdline!";
    return false;
  }
  contents.pop_back();
  std::vector<std::string> procfs_cmdline = absl::StrSplit(contents, '\0');

  if (static_cast<int>(procfs_cmdline.size()) != argc) {
    std::cerr << "argc = " << argc << " != " << procfs_cmdline.size();
    return false;
  }

  for (int i = 0; i < argc; ++i) {
    if (procfs_cmdline[i] != argv[i]) {
      std::cerr << "Procfs command line argument " << i << " mismatch "
                << procfs_cmdline[i] << " != " << argv[i];
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
  }

  gvisor::testing::TestInit(&argc, &argv);

  return RUN_ALL_TESTS();
}
