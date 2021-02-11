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

#ifndef GVISOR_TEST_UTIL_PTY_UTIL_H_
#define GVISOR_TEST_UTIL_PTY_UTIL_H_

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Opens the replica end of the passed master as R/W and nonblocking. It does
// not set the replica as the controlling TTY.
PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master);

// Identical to the above OpenReplica, but flags are all specified by the
// caller.
PosixErrorOr<FileDescriptor> OpenReplica(const FileDescriptor& master,
                                         int flags);

// Get the number of the replica end of the master.
PosixErrorOr<int> ReplicaID(const FileDescriptor& master);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_PTY_UTIL_H_
