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

#include "test/util/epoll_util.h"

#include <sys/epoll.h>

#include "gmock/gmock.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<FileDescriptor> NewEpollFD(int size) {
  // "Since Linux 2.6.8, the size argument is ignored, but must be greater than
  // zero." - epoll_create(2)
  int fd = epoll_create(size);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "epoll_create");
  }
  return FileDescriptor(fd);
}

PosixError RegisterEpollFD(int epoll_fd, int target_fd, int events,
                           uint64_t data) {
  struct epoll_event event;
  event.events = events;
  event.data.u64 = data;
  int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_fd, &event);
  MaybeSave();
  if (rc < 0) {
    return PosixError(errno, "epoll_ctl");
  }
  return NoError();
}

}  // namespace testing
}  // namespace gvisor
