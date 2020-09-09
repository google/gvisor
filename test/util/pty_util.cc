// Copyright 2019 The gVisor Authors.
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

#include "test/util/pty_util.h"

#include <sys/ioctl.h>
#include <termios.h>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& main) {
  PosixErrorOr<int> n = ReplicaID(main);
  if (!n.ok()) {
    return PosixErrorOr<FileDescriptor>(n.error());
  }
  return Open(absl::StrCat("/dev/pts/", n.ValueOrDie()), O_RDWR | O_NONBLOCK);
}

PosixErrorOr<int> ReplicaID(const FileDescriptor& main) {
  // Get pty index.
  int n;
  int ret = ioctl(main.get(), TIOCGPTN, &n);
  if (ret < 0) {
    return PosixError(errno, "ioctl(TIOCGPTN) failed");
  }

  // Unlock pts.
  int unlock = 0;
  ret = ioctl(main.get(), TIOCSPTLCK, &unlock);
  if (ret < 0) {
    return PosixError(errno, "ioctl(TIOSPTLCK) failed");
  }

  return n;
}

}  // namespace testing
}  // namespace gvisor
