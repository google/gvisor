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

#ifndef GVISOR_TEST_UTIL_EPOLL_UTIL_H_
#define GVISOR_TEST_UTIL_EPOLL_UTIL_H_

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Returns a new epoll file descriptor.
PosixErrorOr<FileDescriptor> NewEpollFD(int size = 1);

// Registers `target_fd` with the epoll instance represented by `epoll_fd` for
// the epoll events `events`. Events on `target_fd` will be indicated by setting
// data.u64 to `data` in the returned epoll_event.
PosixError RegisterEpollFD(int epoll_fd, int target_fd, int events,
                           uint64_t data);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_EPOLL_UTIL_H_
