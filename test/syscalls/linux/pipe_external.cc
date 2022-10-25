// Copyright 2022 The gVisor Authors.
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

#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <string>
#include <tuple>

#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/test_util.h"

// This file contains tests specific to connecting to host UDS managed outside
// the sandbox / test.
//
// A set of ultity sockets will be created externally in $TEST_UDS_TREE and
// $TEST_UDS_ATTACH_TREE for these tests to interact with.

namespace gvisor {
namespace testing {

namespace {

struct ProtocolSocket {
  int protocol;
  std::string name;
};

// Parameter is pipe/UDS root dir.
using HostPipeTest = ::testing::TestWithParam<std::string>;

TEST_P(HostPipeTest, Read) {
  const std::string env = GetParam();

  const char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string path = JoinPath(root, "pipe", "in");
  FileDescriptor reader = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));

  char lastValue = 0;
  ssize_t length = 0;
  while (length < 1024 * 1024) {
    char buf[1024];

    ssize_t read = ReadFd(reader.get(), buf, sizeof(buf));
    ASSERT_THAT(read, SyscallSucceeds());
    for (uint i = 0; i < read; ++i) {
      ASSERT_EQ(static_cast<char>(lastValue + i), buf[i]);
    }
    lastValue += read;
    length += read;
  }
}

TEST_P(HostPipeTest, Write) {
  const std::string env = GetParam();

  const char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string path = JoinPath(root, "pipe", "out");
  FileDescriptor writer = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));

  char lastValue = 0;
  ssize_t length = 0;
  while (length < 1024 * 1024) {
    char buf[1024];
    for (int i = 0; i < sizeof(buf); ++i) {
      buf[i] = i + lastValue;
    }

    ASSERT_THAT(WriteFd(writer.get(), buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    lastValue += sizeof(buf);
    length += sizeof(buf);
  }
}

INSTANTIATE_TEST_SUITE_P(Paths, HostPipeTest,
                         // Test access via standard path and attach point.
                         ::testing::Values("TEST_UDS_TREE",
                                           "TEST_UDS_ATTACH_TREE"));

}  // namespace

}  // namespace testing
}  // namespace gvisor
