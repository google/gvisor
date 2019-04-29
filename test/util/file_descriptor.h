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

#ifndef GVISOR_TEST_UTIL_FILE_DESCRIPTOR_H_
#define GVISOR_TEST_UTIL_FILE_DESCRIPTOR_H_

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "gmock/gmock.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

// FileDescriptor is an RAII type class which takes ownership of a file
// descriptor. It will close the FD when this object goes out of scope.
class FileDescriptor {
 public:
  // Constructs an empty FileDescriptor (one that does not own a file
  // descriptor).
  FileDescriptor() = default;

  // Constructs a FileDescriptor that owns fd. If fd is negative, constructs an
  // empty FileDescriptor.
  explicit FileDescriptor(int fd) { set_fd(fd); }

  FileDescriptor(FileDescriptor&& orig) : fd_(orig.release()) {}

  FileDescriptor& operator=(FileDescriptor&& orig) {
    reset(orig.release());
    return *this;
  }

  PosixErrorOr<FileDescriptor> Dup() const {
    if (fd_ < 0) {
      return PosixError(EINVAL, "Attempting to Dup unset fd");
    }

    int fd = dup(fd_);
    if (fd < 0) {
      return PosixError(errno, absl::StrCat("dup ", fd_));
    }
    MaybeSave();
    return FileDescriptor(fd);
  }

  FileDescriptor(FileDescriptor const& other) = delete;
  FileDescriptor& operator=(FileDescriptor const& other) = delete;

  ~FileDescriptor() { reset(); }

  // If this object is non-empty, returns the owned file descriptor. (Ownership
  // is retained by the FileDescriptor.) Otherwise returns -1.
  int get() const { return fd_; }

  // If this object is non-empty, transfers ownership of the file descriptor to
  // the caller and returns it. Otherwise returns -1.
  int release() {
    int const fd = fd_;
    fd_ = -1;
    return fd;
  }

  // If this object is non-empty, closes the owned file descriptor (recording a
  // test failure if the close fails).
  void reset() { reset(-1); }

  // Like no-arg reset(), but the FileDescriptor takes ownership of fd after
  // closing its existing file descriptor.
  void reset(int fd) {
    if (fd_ >= 0) {
      TEST_PCHECK(close(fd_) == 0);
      MaybeSave();
    }
    set_fd(fd);
  }

 private:
  // Wrapper that coerces negative fd values other than -1 to -1 so that get()
  // etc. return -1.
  void set_fd(int fd) { fd_ = std::max(fd, -1); }

  int fd_ = -1;
};

// Wrapper around open(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> Open(std::string const& path, int flags,
                                         mode_t mode = 0) {
  int fd = open(path.c_str(), flags, mode);
  if (fd < 0) {
    return PosixError(errno, absl::StrFormat("open(%s, %#x, %#o)", path.c_str(),
                                             flags, mode));
  }
  MaybeSave();
  return FileDescriptor(fd);
}

// Wrapper around openat(2) that returns a FileDescriptor.
inline PosixErrorOr<FileDescriptor> OpenAt(int dirfd, std::string const& path,
                                           int flags, mode_t mode = 0) {
  int fd = openat(dirfd, path.c_str(), flags, mode);
  if (fd < 0) {
    return PosixError(errno, absl::StrFormat("openat(%d, %s, %#x, %#o)", dirfd,
                                             path, flags, mode));
  }
  MaybeSave();
  return FileDescriptor(fd);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_FILE_DESCRIPTOR_H_
