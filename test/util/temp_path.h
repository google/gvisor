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

#ifndef GVISOR_TEST_UTIL_TEMP_PATH_H_
#define GVISOR_TEST_UTIL_TEMP_PATH_H_

#include <sys/stat.h>

#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Return a new temp filename, intended to be unique system-wide.
std::string NextTempBasename();

// Returns an absolute path for a file in `dir` that does not yet exist.
// Distinct calls to NewTempAbsPathInDir from the same process, even from
// multiple threads, are guaranteed to return different paths. Distinct calls to
// NewTempAbsPathInDir from different processes are not synchronized.
std::string NewTempAbsPathInDir(absl::string_view const dir);

// Like NewTempAbsPathInDir, but the returned path is in the test's temporary
// directory, as provided by the testing framework.
std::string NewTempAbsPath();

// Like NewTempAbsPathInDir, but the returned path is relative (to the current
// working directory).
std::string NewTempRelPath();

// Returns the absolute path for the test temp dir.
std::string GetAbsoluteTestTmpdir();

// Represents a temporary file or directory.
class TempPath {
 public:
  // Default creation mode for files.
  static constexpr mode_t kDefaultFileMode = 0644;

  // Default creation mode for directories.
  static constexpr mode_t kDefaultDirMode = 0755;

  // Creates a temporary file in directory `parent` with mode `mode` and
  // contents `content`.
  static PosixErrorOr<TempPath> CreateFileWith(absl::string_view parent,
                                               absl::string_view content,
                                               mode_t mode);

  // Creates an empty temporary subdirectory in directory `parent` with mode
  // `mode`.
  static PosixErrorOr<TempPath> CreateDirWith(absl::string_view parent,
                                              mode_t mode);

  // Creates a temporary symlink in directory `parent` to destination `dest`.
  static PosixErrorOr<TempPath> CreateSymlinkTo(absl::string_view parent,
                                                std::string const& dest);

  // Creates an empty temporary file in directory `parent` with mode
  // kDefaultFileMode.
  static PosixErrorOr<TempPath> CreateFileIn(absl::string_view parent);

  // Creates an empty temporary subdirectory in directory `parent` with mode
  // kDefaultDirMode.
  static PosixErrorOr<TempPath> CreateDirIn(absl::string_view parent);

  // Creates an empty temporary file in the test's temporary directory with mode
  // `mode`.
  static PosixErrorOr<TempPath> CreateFileMode(mode_t mode);

  // Creates an empty temporary file in the test's temporary directory with
  // mode kDefaultFileMode.
  static PosixErrorOr<TempPath> CreateFile();

  // Creates an empty temporary subdirectory in the test's temporary directory
  // with mode kDefaultDirMode.
  static PosixErrorOr<TempPath> CreateDir();

  // Constructs a TempPath that represents nothing.
  TempPath() = default;

  // Constructs a TempPath that represents the given path, which will be deleted
  // when the TempPath is destroyed.
  explicit TempPath(std::string path) : path_(std::move(path)) {}

  // Attempts to delete the represented temporary file or directory (in the
  // latter case, also attempts to delete its contents).
  ~TempPath();

  // Attempts to delete the represented temporary file or directory, then
  // transfers ownership of the path represented by orig to this TempPath.
  TempPath(TempPath&& orig);
  TempPath& operator=(TempPath&& orig);

  // Changes the path this TempPath represents. If the TempPath already
  // represented a path, deletes and returns that path. Otherwise returns the
  // empty string.
  std::string reset(std::string newpath);
  std::string reset() { return reset(""); }

  // Forgets and returns the path this TempPath represents. The path is not
  // deleted.
  std::string release();

  // Returns the path this TempPath represents.
  std::string path() const { return path_; }

 private:
  template <typename F>
  static PosixErrorOr<TempPath> CreateIn(absl::string_view const parent,
                                         F const& f) {
    std::string path = NewTempAbsPathInDir(parent);
    RETURN_IF_ERRNO(f(path));
    return TempPath(std::move(path));
  }

  std::string path_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_TEMP_PATH_H_
