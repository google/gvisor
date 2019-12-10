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

#include "test/util/fs_util.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gmock/gmock.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

namespace {
PosixError WriteContentsToFD(int fd, absl::string_view contents) {
  int written = 0;
  while (static_cast<absl::string_view::size_type>(written) < contents.size()) {
    int wrote = write(fd, contents.data() + written, contents.size() - written);
    if (wrote < 0) {
      if (errno == EINTR) {
        continue;
      }
      return PosixError(
          errno, absl::StrCat("WriteContentsToFD fd: ", fd, " write failure."));
    }
    written += wrote;
  }
  return NoError();
}
}  // namespace

namespace internal {

// Given a collection of file paths, append them all together,
// ensuring that the proper path separators are inserted between them.
std::string JoinPathImpl(std::initializer_list<absl::string_view> paths) {
  std::string result;

  if (paths.size() != 0) {
    // This size calculation is worst-case: it assumes one extra "/" for every
    // path other than the first.
    size_t total_size = paths.size() - 1;
    for (const absl::string_view path : paths) total_size += path.size();
    result.resize(total_size);

    auto begin = result.begin();
    auto out = begin;
    bool trailing_slash = false;
    for (absl::string_view path : paths) {
      if (path.empty()) continue;
      if (path.front() == '/') {
        if (trailing_slash) {
          path.remove_prefix(1);
        }
      } else {
        if (!trailing_slash && out != begin) *out++ = '/';
      }
      const size_t this_size = path.size();
      memcpy(&*out, path.data(), this_size);
      out += this_size;
      trailing_slash = out[-1] == '/';
    }
    result.erase(out - begin);
  }
  return result;
}
}  // namespace internal

// Returns a status or the current working directory.
PosixErrorOr<std::string> GetCWD() {
  char buffer[PATH_MAX + 1] = {};
  if (getcwd(buffer, PATH_MAX) == nullptr) {
    return PosixError(errno, "GetCWD() failed");
  }

  return std::string(buffer);
}

PosixErrorOr<struct stat> Stat(absl::string_view path) {
  struct stat stat_buf;
  int res = stat(std::string(path).c_str(), &stat_buf);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("stat ", path));
  }
  return stat_buf;
}

PosixErrorOr<struct stat> Lstat(absl::string_view path) {
  struct stat stat_buf;
  int res = lstat(std::string(path).c_str(), &stat_buf);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("lstat ", path));
  }
  return stat_buf;
}

PosixErrorOr<struct stat> Fstat(int fd) {
  struct stat stat_buf;
  int res = fstat(fd, &stat_buf);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("fstat ", fd));
  }
  return stat_buf;
}

PosixErrorOr<bool> Exists(absl::string_view path) {
  struct stat stat_buf;
  int res = stat(std::string(path).c_str(), &stat_buf);
  if (res < 0) {
    if (errno == ENOENT) {
      return false;
    }
    return PosixError(errno, absl::StrCat("stat ", path));
  }
  return true;
}

PosixErrorOr<bool> IsDirectory(absl::string_view path) {
  ASSIGN_OR_RETURN_ERRNO(struct stat stat_buf, Lstat(path));
  if (S_ISDIR(stat_buf.st_mode)) {
    return true;
  }

  return false;
}

PosixError Delete(absl::string_view path) {
  int res = unlink(std::string(path).c_str());
  if (res < 0) {
    return PosixError(errno, absl::StrCat("unlink ", path));
  }

  return NoError();
}

PosixError Truncate(absl::string_view path, int length) {
  int res = truncate(std::string(path).c_str(), length);
  if (res < 0) {
    return PosixError(errno,
                      absl::StrCat("truncate ", path, " to length ", length));
  }

  return NoError();
}

PosixError Chmod(absl::string_view path, int mode) {
  int res = chmod(std::string(path).c_str(), mode);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("chmod ", path));
  }

  return NoError();
}

PosixError MknodAt(const FileDescriptor& dfd, absl::string_view path, int mode,
                   dev_t dev) {
  int res = mknodat(dfd.get(), std::string(path).c_str(), mode, dev);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("mknod ", path));
  }

  return NoError();
}

PosixError UnlinkAt(const FileDescriptor& dfd, absl::string_view path,
                    int flags) {
  int res = unlinkat(dfd.get(), std::string(path).c_str(), flags);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("unlink ", path));
  }

  return NoError();
}

PosixError Mkdir(absl::string_view path, int mode) {
  int res = mkdir(std::string(path).c_str(), mode);
  if (res < 0) {
    return PosixError(errno, absl::StrCat("mkdir ", path, " mode ", mode));
  }

  return NoError();
}

PosixError Rmdir(absl::string_view path) {
  int res = rmdir(std::string(path).c_str());
  if (res < 0) {
    return PosixError(errno, absl::StrCat("rmdir ", path));
  }

  return NoError();
}

PosixError SetContents(absl::string_view path, absl::string_view contents) {
  ASSIGN_OR_RETURN_ERRNO(bool exists, Exists(path));
  if (!exists) {
    return PosixError(
        ENOENT, absl::StrCat("SetContents file ", path, " doesn't exist."));
  }

  ASSIGN_OR_RETURN_ERRNO(auto fd, Open(std::string(path), O_WRONLY | O_TRUNC));
  return WriteContentsToFD(fd.get(), contents);
}

// Create a file with the given contents (if it does not already exist with the
// given mode) and then set the contents.
PosixError CreateWithContents(absl::string_view path,
                              absl::string_view contents, int mode) {
  ASSIGN_OR_RETURN_ERRNO(
      auto fd, Open(std::string(path), O_WRONLY | O_CREAT | O_TRUNC, mode));
  return WriteContentsToFD(fd.get(), contents);
}

PosixError GetContents(absl::string_view path, std::string* output) {
  ASSIGN_OR_RETURN_ERRNO(auto fd, Open(std::string(path), O_RDONLY));
  output->clear();

  // Keep reading until we hit an EOF or an error.
  return GetContentsFD(fd.get(), output);
}

PosixErrorOr<std::string> GetContents(absl::string_view path) {
  std::string ret;
  RETURN_IF_ERRNO(GetContents(path, &ret));
  return ret;
}

PosixErrorOr<std::string> GetContentsFD(int fd) {
  std::string ret;
  RETURN_IF_ERRNO(GetContentsFD(fd, &ret));
  return ret;
}

PosixError GetContentsFD(int fd, std::string* output) {
  // Keep reading until we hit an EOF or an error.
  while (true) {
    char buf[16 * 1024] = {};  // Read in 16KB chunks.
    int bytes_read = read(fd, buf, sizeof(buf));
    if (bytes_read < 0) {
      if (errno == EINTR) {
        continue;
      }
      return PosixError(errno, "GetContentsFD read failure.");
    }

    if (bytes_read == 0) {
      break;  // EOF.
    }

    output->append(buf, bytes_read);
  }
  return NoError();
}

PosixErrorOr<std::string> ReadLink(absl::string_view path) {
  char buf[PATH_MAX + 1] = {};
  int ret = readlink(std::string(path).c_str(), buf, PATH_MAX);
  if (ret < 0) {
    return PosixError(errno, absl::StrCat("readlink ", path));
  }

  return std::string(buf, ret);
}

PosixError WalkTree(
    absl::string_view path, bool recursive,
    const std::function<void(absl::string_view, const struct stat&)>& cb) {
  DIR* dir = opendir(std::string(path).c_str());
  if (dir == nullptr) {
    return PosixError(errno, absl::StrCat("opendir ", path));
  }
  auto dir_closer = Cleanup([&dir]() { closedir(dir); });
  while (true) {
    // Readdir(3): If the end of the directory stream is reached, NULL is
    // returned and errno is not changed.  If an error occurs, NULL is returned
    // and errno is set appropriately.  To distinguish end of stream and from an
    // error, set errno to zero before calling readdir() and then check the
    // value of errno if NULL is returned.
    errno = 0;
    struct dirent* dp = readdir(dir);
    if (dp == nullptr) {
      if (errno != 0) {
        return PosixError(errno, absl::StrCat("readdir ", path));
      }
      break;  // We're done.
    }

    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
      // Skip dots.
      continue;
    }

    auto full_path = JoinPath(path, dp->d_name);
    ASSIGN_OR_RETURN_ERRNO(struct stat s, Stat(full_path));
    if (S_ISDIR(s.st_mode) && recursive) {
      RETURN_IF_ERRNO(WalkTree(full_path, recursive, cb));
    } else {
      cb(full_path, s);
    }
  }
  // We're done walking so let's invoke our cleanup callback now.
  dir_closer.Release()();

  // And we have to dispatch the callback on the base directory.
  ASSIGN_OR_RETURN_ERRNO(struct stat s, Stat(path));
  cb(path, s);

  return NoError();
}

PosixErrorOr<std::vector<std::string>> ListDir(absl::string_view abspath,
                                               bool skipdots) {
  std::vector<std::string> files;

  DIR* dir = opendir(std::string(abspath).c_str());
  if (dir == nullptr) {
    return PosixError(errno, absl::StrCat("opendir ", abspath));
  }
  auto dir_closer = Cleanup([&dir]() { closedir(dir); });
  while (true) {
    // Readdir(3): If the end of the directory stream is reached, NULL is
    // returned and errno is not changed.  If an error occurs, NULL is returned
    // and errno is set appropriately.  To distinguish end of stream and from an
    // error, set errno to zero before calling readdir() and then check the
    // value of errno if NULL is returned.
    errno = 0;
    struct dirent* dp = readdir(dir);
    if (dp == nullptr) {
      if (errno != 0) {
        return PosixError(errno, absl::StrCat("readdir ", abspath));
      }
      break;  // We're done.
    }

    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
      if (skipdots) {
        continue;
      }
    }
    files.push_back(std::string(dp->d_name));
  }

  return files;
}

PosixError RecursivelyDelete(absl::string_view path, int* undeleted_dirs,
                             int* undeleted_files) {
  ASSIGN_OR_RETURN_ERRNO(bool exists, Exists(path));
  if (!exists) {
    return PosixError(ENOENT, absl::StrCat(path, " does not exist"));
  }

  ASSIGN_OR_RETURN_ERRNO(bool dir, IsDirectory(path));
  if (!dir) {
    // Nothing recursive needs to happen we can just call Delete.
    auto status = Delete(path);
    if (!status.ok() && undeleted_files) {
      (*undeleted_files)++;
    }
    return status;
  }

  return WalkTree(path, /*recursive=*/true,
                  [&](absl::string_view absolute_path, const struct stat& s) {
                    if (S_ISDIR(s.st_mode)) {
                      auto rm_status = Rmdir(absolute_path);
                      if (!rm_status.ok() && undeleted_dirs) {
                        (*undeleted_dirs)++;
                      }
                    } else {
                      auto delete_status = Delete(absolute_path);
                      if (!delete_status.ok() && undeleted_files) {
                        (*undeleted_files)++;
                      }
                    }
                  });
}

PosixError RecursivelyCreateDir(absl::string_view path) {
  if (path.empty() || path == "/") {
    return PosixError(EINVAL, "Cannot create root!");
  }

  // Does it already exist, if so we're done.
  ASSIGN_OR_RETURN_ERRNO(bool exists, Exists(path));
  if (exists) {
    return NoError();
  }

  // Do we need to create directories under us?
  auto dirname = Dirname(path);
  ASSIGN_OR_RETURN_ERRNO(exists, Exists(dirname));
  if (!exists) {
    RETURN_IF_ERRNO(RecursivelyCreateDir(dirname));
  }

  return Mkdir(path);
}

// Makes a path absolute with respect to an optional base. If no base is
// provided it will use the current working directory.
PosixErrorOr<std::string> MakeAbsolute(absl::string_view filename,
                                       absl::string_view base) {
  if (filename.empty()) {
    return PosixError(EINVAL, "filename cannot be empty.");
  }

  if (filename[0] == '/') {
    // This path is already absolute.
    return std::string(filename);
  }

  std::string actual_base;
  if (!base.empty()) {
    actual_base = std::string(base);
  } else {
    auto cwd_or = GetCWD();
    RETURN_IF_ERRNO(cwd_or.error());
    actual_base = cwd_or.ValueOrDie();
  }

  // Reverse iterate removing trailing slashes, effectively right trim '/'.
  for (int i = actual_base.size() - 1; i >= 0 && actual_base[i] == '/'; --i) {
    actual_base.erase(i, 1);
  }

  if (filename == ".") {
    return actual_base.empty() ? "/" : actual_base;
  }

  return absl::StrCat(actual_base, "/", filename);
}

std::string CleanPath(const absl::string_view unclean_path) {
  std::string path = std::string(unclean_path);
  const char *src = path.c_str();
  std::string::iterator dst = path.begin();

  // Check for absolute path and determine initial backtrack limit.
  const bool is_absolute_path = *src == '/';
  if (is_absolute_path) {
    *dst++ = *src++;
    while (*src == '/') ++src;
  }
  std::string::const_iterator backtrack_limit = dst;

  // Process all parts
  while (*src) {
    bool parsed = false;

    if (src[0] == '.') {
      //  1dot ".<whateverisnext>", check for END or SEP.
      if (src[1] == '/' || !src[1]) {
        if (*++src) {
          ++src;
        }
        parsed = true;
      } else if (src[1] == '.' && (src[2] == '/' || !src[2])) {
        // 2dot END or SEP (".." | "../<whateverisnext>").
        src += 2;
        if (dst != backtrack_limit) {
          // We can backtrack the previous part
          for (--dst; dst != backtrack_limit && dst[-1] != '/'; --dst) {
            // Empty.
          }
        } else if (!is_absolute_path) {
          // Failed to backtrack and we can't skip it either. Rewind and copy.
          src -= 2;
          *dst++ = *src++;
          *dst++ = *src++;
          if (*src) {
            *dst++ = *src;
          }
          // We can never backtrack over a copied "../" part so set new limit.
          backtrack_limit = dst;
        }
        if (*src) {
          ++src;
        }
        parsed = true;
      }
    }

    // If not parsed, copy entire part until the next SEP or EOS.
    if (!parsed) {
      while (*src && *src != '/') {
        *dst++ = *src++;
      }
      if (*src) {
        *dst++ = *src++;
      }
    }

    // Skip consecutive SEP occurrences
    while (*src == '/') {
      ++src;
    }
  }

  // Calculate and check the length of the cleaned path.
  int path_length = dst - path.begin();
  if (path_length != 0) {
    // Remove trailing '/' except if it is root path ("/" ==> path_length := 1)
    if (path_length > 1 && path[path_length - 1] == '/') {
      --path_length;
    }
    path.resize(path_length);
  } else {
    // The cleaned path is empty; assign "." as per the spec.
    path.assign(1, '.');
  }
  return path;
}

PosixErrorOr<std::string> GetRelativePath(absl::string_view source,
                                          absl::string_view dest) {
  if (!absl::StartsWith(source, "/") || !absl::StartsWith(dest, "/")) {
    // At least one of the inputs is not an absolute path.
    return PosixError(
        EINVAL,
        "GetRelativePath: At least one of the inputs is not an absolute path.");
  }
  const std::string clean_source = CleanPath(source);
  const std::string clean_dest = CleanPath(dest);
  auto source_parts = absl::StrSplit(clean_source, '/', absl::SkipEmpty());
  auto dest_parts = absl::StrSplit(clean_dest, '/', absl::SkipEmpty());
  auto source_iter = source_parts.begin();
  auto dest_iter = dest_parts.begin();

  // Advance past common prefix.
  while (source_iter != source_parts.end() && dest_iter != dest_parts.end() &&
         *source_iter == *dest_iter) {
    ++source_iter;
    ++dest_iter;
  }

  // Build result backtracking.
  std::string result = "";
  while (source_iter != source_parts.end()) {
    absl::StrAppend(&result, "../");
    ++source_iter;
  }

  // Add remaining path to dest.
  while (dest_iter != dest_parts.end()) {
    absl::StrAppend(&result, *dest_iter, "/");
    ++dest_iter;
  }

  if (result.empty()) {
    return std::string(".");
  }

  // Remove trailing slash.
  result.erase(result.size() - 1);
  return result;
}

absl::string_view Dirname(absl::string_view path) {
  return SplitPath(path).first;
}

absl::string_view Basename(absl::string_view path) {
  return SplitPath(path).second;
}

std::pair<absl::string_view, absl::string_view> SplitPath(
    absl::string_view path) {
  std::string::size_type pos = path.find_last_of('/');

  // Handle the case with no '/' in 'path'.
  if (pos == absl::string_view::npos) {
    return std::make_pair(path.substr(0, 0), path);
  }

  // Handle the case with a single leading '/' in 'path'.
  if (pos == 0) {
    return std::make_pair(path.substr(0, 1), absl::ClippedSubstr(path, 1));
  }

  return std::make_pair(path.substr(0, pos),
                        absl::ClippedSubstr(path, pos + 1));
}

std::string JoinPath(absl::string_view path1, absl::string_view path2) {
  if (path1.empty()) {
    return std::string(path2);
  }
  if (path2.empty()) {
    return std::string(path1);
  }

  if (path1.back() == '/') {
    if (path2.front() == '/') {
      return absl::StrCat(path1, absl::ClippedSubstr(path2, 1));
    }
  } else {
    if (path2.front() != '/') {
      return absl::StrCat(path1, "/", path2);
    }
  }
  return absl::StrCat(path1, path2);
}

PosixErrorOr<std::string> ProcessExePath(int pid) {
  if (pid <= 0) {
    return PosixError(EINVAL, "Invalid pid specified");
  }

  return ReadLink(absl::StrCat("/proc/", pid, "/exe"));
}

}  // namespace testing
}  // namespace gvisor
