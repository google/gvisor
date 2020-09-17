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

#include "test/fuse/linux/fuse_fd_util.h"

#include <fcntl.h>
#include <linux/fuse.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <string>
#include <vector>

#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fuse_util.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

PosixErrorOr<FileDescriptor> FuseFdTest::OpenPath(const std::string &path,
                                                  uint32_t flags, uint64_t fh) {
  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_open_out),
  };
  struct fuse_open_out out_payload = {
      .fh = fh,
      .open_flags = flags,
  };
  auto iov_out = FuseGenerateIovecs(out_header, out_payload);
  SetServerResponse(FUSE_OPEN, iov_out);

  auto res = Open(path.c_str(), flags);
  if (res.ok()) {
    SkipServerActualRequest();
  }
  return res;
}

Cleanup FuseFdTest::CloseFD(FileDescriptor &fd) {
  return Cleanup([&] {
    close(fd.release());
    SkipServerActualRequest();
  });
}

}  // namespace testing
}  // namespace gvisor
