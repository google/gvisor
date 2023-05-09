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

constexpr char kBasicWorkload[] = "test/syscalls/linux/exec_basic_workload";
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
  }

  gvisor::testing::TestInit(&argc, &argv);
  return gvisor::testing::RunAllTests();
}
