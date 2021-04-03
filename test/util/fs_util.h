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

#ifndef GVISOR_TEST_UTIL_FS_UTIL_H_
#define GVISOR_TEST_UTIL_FS_UTIL_H_

#include <dirent.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// O_LARGEFILE as defined by Linux. glibc tries to be clever by setting it to 0
// because "it isn't needed", even though Linux can return it via F_GETFL.
#if defined(__x86_64__)
constexpr int kOLargeFile = 00100000;
#elif defined(__aarch64__)
constexpr int kOLargeFile = 00400000;
#else
#error "Unknown architecture"
#endif

// From linux/magic.h. For some reason, not defined in the headers for some
// build environments.
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

// Returns a status or the current working directory.
PosixErrorOr<std::string> GetCWD();

// Returns true/false depending on whether or not path exists, or an error if it
// can't be determined.
PosixErrorOr<bool> Exists(absl::string_view path);

// Returns a stat structure for the given path or an error. If the path
// represents a symlink, it will be traversed.
PosixErrorOr<struct stat> Stat(absl::string_view path);

// Returns a stat structure for the given path or an error. If the path
// represents a symlink, it will not be traversed.
PosixErrorOr<struct stat> Lstat(absl::string_view path);

// Returns a stat struct for the given fd.
PosixErrorOr<struct stat> Fstat(int fd);

// Deletes the file or directory at path or returns an error.
PosixError Delete(absl::string_view path);

// Changes the mode of a file or returns an error.
PosixError Chmod(absl::string_view path, int mode);

// Create a special or ordinary file.
PosixError MknodAt(const FileDescriptor& dfd, absl::string_view path, int mode,
                   dev_t dev);

// Unlink the file.
PosixError UnlinkAt(const FileDescriptor& dfd, absl::string_view path,
                    int flags);

// Truncates a file to the given length or returns an error.
PosixError Truncate(absl::string_view path, int length);

// Returns true/false depending on whether or not the path is a directory or
// returns an error.
PosixErrorOr<bool> IsDirectory(absl::string_view path);

// Makes a directory or returns an error.
PosixError Mkdir(absl::string_view path, int mode = 0755);

// Removes a directory or returns an error.
PosixError Rmdir(absl::string_view path);

// Attempts to set the contents of a file or returns an error.
PosixError SetContents(absl::string_view path, absl::string_view contents);

// Creates a file with the given contents and mode or returns an error.
PosixError CreateWithContents(absl::string_view path,
                              absl::string_view contents, int mode = 0666);

// Attempts to read the entire contents of the file into the provided string
// buffer or returns an error.
PosixError GetContents(absl::string_view path, std::string* output);

// Attempts to read the entire contents of the file or returns an error.
PosixErrorOr<std::string> GetContents(absl::string_view path);

// Attempts to read the entire contents of the provided fd into the provided
// string or returns an error.
PosixError GetContentsFD(int fd, std::string* output);

// Attempts to read the entire contents of the provided fd or returns an error.
PosixErrorOr<std::string> GetContentsFD(int fd);

// Executes the readlink(2) system call or returns an error.
PosixErrorOr<std::string> ReadLink(absl::string_view path);

// WalkTree will walk a directory tree in a depth first search manner (if
// recursive). It will invoke a provided callback for each file and directory,
// the parent will always be invoked last making this appropriate for things
// such as deleting an entire directory tree.
//
// This method will return an error when it's unable to access the provided
// path, or when the path is not a directory.
PosixError WalkTree(
    absl::string_view path, bool recursive,
    const std::function<void(absl::string_view, const struct stat&)>& cb);

// Returns the base filenames for all files under a given absolute path. If
// skipdots is true the returned vector will not contain "." or "..". This
// method does not walk the tree recursively it only returns the elements
// in that directory.
PosixErrorOr<std::vector<std::string>> ListDir(absl::string_view abspath,
                                               bool skipdots);

// Check that a directory contains children nodes named in expect, and does not
// contain any children nodes named in exclude.
PosixError DirContains(absl::string_view path,
                       const std::vector<std::string>& expect,
                       const std::vector<std::string>& exclude);

// Same as DirContains, but adds a retry. Suitable for checking a directory
// being modified asynchronously.
PosixError EventuallyDirContains(absl::string_view path,
                                 const std::vector<std::string>& expect,
                                 const std::vector<std::string>& exclude);

// Attempt to recursively delete a directory or file. Returns an error and
// the number of undeleted directories and files. If either
// undeleted_dirs or undeleted_files is nullptr then it will not be used.
PosixError RecursivelyDelete(absl::string_view path, int* undeleted_dirs,
                             int* undeleted_files);

// Recursively create the directory provided or return an error.
PosixError RecursivelyCreateDir(absl::string_view path);

// Makes a path absolute with respect to an optional base. If no base is
// provided it will use the current working directory.
PosixErrorOr<std::string> MakeAbsolute(absl::string_view filename,
                                       absl::string_view base);

// Generates a relative path from the source directory to the destination
// (dest) file or directory.  This uses ../ when necessary for destinations
// which are not nested within the source.  Both source and dest are required
// to be absolute paths, and an empty string will be returned if they are not.
PosixErrorOr<std::string> GetRelativePath(absl::string_view source,
                                          absl::string_view dest);

// Returns the part of the path before the final "/", EXCEPT:
// * If there is a single leading "/" in the path, the result will be the
//   leading "/".
// * If there is no "/" in the path, the result is the empty prefix of the
//   input string.
absl::string_view Dirname(absl::string_view path);

// Return the parts of the path, split on the final "/".  If there is no
// "/" in the path, the first part of the output is empty and the second
// is the input. If the only "/" in the path is the first character, it is
// the first part of the output.
std::pair<absl::string_view, absl::string_view> SplitPath(
    absl::string_view path);

// Returns the part of the path after the final "/". If there is no
// "/" in the path, the result is the same as the input.
// Note that this function's behavior differs from the Unix basename
// command if path ends with "/". For such paths, this function returns the
// empty string.
absl::string_view Basename(absl::string_view path);

// Collapse duplicate "/"s, resolve ".." and "." path elements, remove
// trailing "/".
//
// NOTE: This respects relative vs. absolute paths, but does not
// invoke any system calls (getcwd(2)) in order to resolve relative
// paths wrt actual working directory.  That is, this is purely a
// string manipulation, completely independent of process state.
std::string CleanPath(absl::string_view path);

// Returns the full path to the executable of the given pid or a PosixError.
PosixErrorOr<std::string> ProcessExePath(int pid);

#ifdef __linux__
// IsTmpfs returns true if the file at path is backed by tmpfs.
PosixErrorOr<bool> IsTmpfs(const std::string& path);
#endif  // __linux__

// IsOverlayfs returns true if the file at path is backed by overlayfs.
PosixErrorOr<bool> IsOverlayfs(const std::string& path);

PosixError CheckSameFile(const FileDescriptor& fd1, const FileDescriptor& fd2);

namespace internal {
// Not part of the public API.
std::string JoinPathImpl(std::initializer_list<absl::string_view> paths);
}  // namespace internal

// Join multiple paths together.
// All paths will be treated as relative paths, regardless of whether or not
// they start with a leading '/'.  That is, all paths will be concatenated
// together, with the appropriate path separator inserted in between.
// Arguments must be convertible to absl::string_view.
//
// Usage:
// std::string path = JoinPath("/foo", dirname, filename);
// std::string path = JoinPath(FLAGS_test_srcdir, filename);
//
// 0, 1, 2-path specializations exist to optimize common cases.
inline std::string JoinPath() { return std::string(); }
inline std::string JoinPath(absl::string_view path) {
  return std::string(path.data(), path.size());
}

std::string JoinPath(absl::string_view path1, absl::string_view path2);
template <typename... T>
inline std::string JoinPath(absl::string_view path1, absl::string_view path2,
                            absl::string_view path3, const T&... args) {
  return internal::JoinPathImpl({path1, path2, path3, args...});
}
}  // namespace testing
}  // namespace gvisor
#endif  // GVISOR_TEST_UTIL_FS_UTIL_H_
