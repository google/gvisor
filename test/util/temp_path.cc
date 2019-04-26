// Copyright 2018 Google LLC
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

#include "test/util/temp_path.h"

#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <iostream>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

std::atomic<uint64_t> global_temp_file_number = ATOMIC_VAR_INIT(1);

// Return a new temp filename, intended to be unique system-wide.
//
// The global file number helps maintain file naming consistency across
// different runs of a test.
//
// The timestamp is necessary because the test infrastructure invokes each
// test case in a separate process (resetting global_temp_file_number) and
// potentially in parallel, which allows for races between selecting and using a
// name.
std::string NextTempBasename() {
  return absl::StrCat("gvisor_test_temp_", global_temp_file_number++, "_",
                      absl::ToUnixNanos(absl::Now()));
}

void TryDeleteRecursively(std::string const& path) {
  if (!path.empty()) {
    int undeleted_dirs = 0;
    int undeleted_files = 0;
    auto status = RecursivelyDelete(path, &undeleted_dirs, &undeleted_files);
    if (undeleted_dirs || undeleted_files || !status.ok()) {
      std::cerr << path << ": failed to delete " << undeleted_dirs
                << " directories and " << undeleted_files
                << " files: " << status;
    }
  }
}

}  // namespace

constexpr mode_t TempPath::kDefaultFileMode;
constexpr mode_t TempPath::kDefaultDirMode;

std::string NewTempAbsPathInDir(absl::string_view const dir) {
  return JoinPath(dir, NextTempBasename());
}

std::string NewTempAbsPath() { return NewTempAbsPathInDir(GetAbsoluteTestTmpdir()); }

std::string NewTempRelPath() { return NextTempBasename(); }

std::string GetAbsoluteTestTmpdir() {
  char* env_tmpdir = getenv("TEST_TMPDIR");
  std::string tmp_dir = env_tmpdir != nullptr ? std::string(env_tmpdir) : "/tmp";

  return MakeAbsolute(tmp_dir, "").ValueOrDie();
}

PosixErrorOr<TempPath> TempPath::CreateFileWith(absl::string_view const parent,
                                                absl::string_view const content,
                                                mode_t const mode) {
  return CreateIn(parent, [=](absl::string_view path) -> PosixError {
    // SetContents will call open(O_WRONLY) with the given mode. If the
    // mode is not user-writable, save/restore cannot preserve the fd. Hence
    // the little permission dance that's done here.
    auto res = CreateWithContents(path, content, mode | 0200);
    RETURN_IF_ERRNO(res);

    return Chmod(path, mode);
  });
}

PosixErrorOr<TempPath> TempPath::CreateDirWith(absl::string_view const parent,
                                               mode_t const mode) {
  return CreateIn(parent,
                  [=](absl::string_view path) { return Mkdir(path, mode); });
}

PosixErrorOr<TempPath> TempPath::CreateSymlinkTo(absl::string_view const parent,
                                                 std::string const& dest) {
  return CreateIn(parent, [=](absl::string_view path) {
    int ret = symlink(dest.c_str(), std::string(path).c_str());
    if (ret != 0) {
      return PosixError(errno, "symlink failed");
    }
    return NoError();
  });
}

PosixErrorOr<TempPath> TempPath::CreateFileIn(absl::string_view const parent) {
  return TempPath::CreateFileWith(parent, absl::string_view(),
                                  kDefaultFileMode);
}

PosixErrorOr<TempPath> TempPath::CreateDirIn(absl::string_view const parent) {
  return TempPath::CreateDirWith(parent, kDefaultDirMode);
}

PosixErrorOr<TempPath> TempPath::CreateFileMode(mode_t mode) {
  return TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), absl::string_view(),
                                  mode);
}

PosixErrorOr<TempPath> TempPath::CreateFile() {
  return TempPath::CreateFileIn(GetAbsoluteTestTmpdir());
}

PosixErrorOr<TempPath> TempPath::CreateDir() {
  return TempPath::CreateDirIn(GetAbsoluteTestTmpdir());
}

TempPath::~TempPath() { TryDeleteRecursively(path_); }

TempPath::TempPath(TempPath&& orig) { reset(orig.release()); }

TempPath& TempPath::operator=(TempPath&& orig) {
  reset(orig.release());
  return *this;
}

std::string TempPath::reset(std::string newpath) {
  std::string path = path_;
  TryDeleteRecursively(path_);
  path_ = std::move(newpath);
  return path;
}

std::string TempPath::release() {
  std::string path = path_;
  path_ = std::string();
  return path;
}

}  // namespace testing
}  // namespace gvisor
