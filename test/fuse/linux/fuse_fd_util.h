// Copyright 2020 The gVisor Authors.
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

#ifndef GVISOR_TEST_FUSE_FUSE_FD_UTIL_H_
#define GVISOR_TEST_FUSE_FUSE_FD_UTIL_H_

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "test/fuse/linux/fuse_base.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

class FuseFdTest : public FuseTest {
 public:
  // Sets the FUSE server to respond to a FUSE_OPEN with corresponding flags and
  // fh. Then does a real file system open on the absolute path to get an fd.
  PosixErrorOr<FileDescriptor> OpenPath(const std::string &path,
                                        uint32_t flags = O_RDONLY,
                                        uint64_t fh = 1);

  // Returns a cleanup object that closes the fd when it is destroyed. After
  // the close is done, tells the FUSE server to skip this FUSE_RELEASE.
  Cleanup CloseFD(FileDescriptor &fd);
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_FUSE_FUSE_FD_UTIL_H_
