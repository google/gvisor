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

#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "fuse_base.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

class InitTestNormal : public FuseTest {
 public:
  bool CompareRequest(void* expected_mem, size_t expected_len, void* real_mem,
                      size_t real_len) override {
    if (expected_len != real_len) return false;
    struct fuse_in_header* real_header =
      reinterpret_cast<struct fuse_in_header*>(real_mem);

    if (real_header->opcode != FUSE_INIT) {
      std::cerr << "expect header opcode " << FUSE_INIT << " but got "
                << real_header->opcode << std::endl;
      return false;
    }
    return true;
  }

  PosixError ConsumeFuseInit() override {
    return PosixError(0);
  }
};

TEST_F(InitTestNormal, InitNormal) {
  struct iovec iov_in[2];
  struct iovec iov_out[2];

  struct fuse_in_header in_header = {
      .len = sizeof(struct fuse_in_header) + sizeof(struct fuse_init_in),
      .opcode = FUSE_INIT,
      .unique = 2,
  };
  struct fuse_init_in in_payload = {};
  iov_in[0].iov_len = sizeof(in_header);
  iov_in[0].iov_base = &in_header;
  iov_in[1].iov_len = sizeof(in_payload);
  iov_in[1].iov_base = &in_payload;

  struct fuse_out_header out_header = {
      .len = sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out),
      .error = 0,
      .unique = 2,
  };
  // Returns an empty init out payload since this is just a test.
  struct fuse_init_out out_payload;
  iov_out[0].iov_len = sizeof(out_header);
  iov_out[0].iov_base = &out_header;
  iov_out[1].iov_len = sizeof(out_payload);
  iov_out[1].iov_base = &out_payload;

  SetExpected(iov_in, 2, iov_out, 2);

  WaitCompleted();
}

// TODO(gvisor.dev/issues/3097): Add testing for blocking before initialization behavior after more syscalls available.

}  // namespace

}  // namespace testing
}  // namespace gvisor
