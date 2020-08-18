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

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

// MatchesStringLength checks that a tuple argument of (struct iovec *, int)
// corresponding to an iovec array and its length, contains data that matches
// the string length strlen.
MATCHER_P(MatchesStringLength, strlen, "") {
  struct iovec* iovs = arg.first;
  int niov = arg.second;
  int offset = 0;
  for (int i = 0; i < niov; i++) {
    offset += iovs[i].iov_len;
  }
  if (offset != static_cast<int>(strlen)) {
    *result_listener << offset;
    return false;
  }
  return true;
}

// MatchesStringValue checks that a tuple argument of (struct iovec *, int)
// corresponding to an iovec array and its length, contains data that matches
// the string value str.
MATCHER_P(MatchesStringValue, str, "") {
  struct iovec* iovs = arg.first;
  int len = strlen(str);
  int niov = arg.second;
  int offset = 0;
  for (int i = 0; i < niov; i++) {
    struct iovec iov = iovs[i];
    if (len < offset) {
      *result_listener << "strlen " << len << " < offset " << offset;
      return false;
    }
    if (strncmp(static_cast<char*>(iov.iov_base), &str[offset], iov.iov_len)) {
      absl::string_view iovec_string(static_cast<char*>(iov.iov_base),
                                     iov.iov_len);
      *result_listener << iovec_string << " @offset " << offset;
      return false;
    }
    offset += iov.iov_len;
  }
  return true;
}

extern const char kReadvTestData[] =
    "127.0.0.1      localhost"
    ""
    "# The following lines are desirable for IPv6 capable hosts"
    "::1     ip6-localhost ip6-loopback"
    "fe00::0 ip6-localnet"
    "ff00::0 ip6-mcastprefix"
    "ff02::1 ip6-allnodes"
    "ff02::2 ip6-allrouters"
    "ff02::3 ip6-allhosts"
    "192.168.1.100 a"
    "93.184.216.34          foo.bar.example.com xcpu";
extern const size_t kReadvTestDataSize = sizeof(kReadvTestData);

static void ReadAllOneProvidedBuffer(int fd, std::vector<char>* buffer) {
  struct iovec iovs[1];
  iovs[0].iov_base = buffer->data();
  iovs[0].iov_len = kReadvTestDataSize;

  ASSERT_THAT(readv(fd, iovs, 1), SyscallSucceedsWithValue(kReadvTestDataSize));

  std::pair<struct iovec*, int> iovec_desc(iovs, 1);
  EXPECT_THAT(iovec_desc, MatchesStringLength(kReadvTestDataSize));
  EXPECT_THAT(iovec_desc, MatchesStringValue(kReadvTestData));
}

void ReadAllOneBuffer(int fd) {
  std::vector<char> buffer(kReadvTestDataSize);
  ReadAllOneProvidedBuffer(fd, &buffer);
}

void ReadAllOneLargeBuffer(int fd) {
  std::vector<char> buffer(10 * kReadvTestDataSize);
  ReadAllOneProvidedBuffer(fd, &buffer);
}

void ReadOneHalfAtATime(int fd) {
  int len0 = kReadvTestDataSize / 2;
  int len1 = kReadvTestDataSize - len0;
  std::vector<char> buffer0(len0);
  std::vector<char> buffer1(len1);

  struct iovec iovs[2];
  iovs[0].iov_base = buffer0.data();
  iovs[0].iov_len = len0;
  iovs[1].iov_base = buffer1.data();
  iovs[1].iov_len = len1;

  ASSERT_THAT(readv(fd, iovs, 2), SyscallSucceedsWithValue(kReadvTestDataSize));

  std::pair<struct iovec*, int> iovec_desc(iovs, 2);
  EXPECT_THAT(iovec_desc, MatchesStringLength(kReadvTestDataSize));
  EXPECT_THAT(iovec_desc, MatchesStringValue(kReadvTestData));
}

void ReadOneBufferPerByte(int fd) {
  std::vector<char> buffer(kReadvTestDataSize);
  std::vector<struct iovec> iovs(kReadvTestDataSize);
  char* buffer_ptr = buffer.data();
  struct iovec* iovs_ptr = iovs.data();

  for (int i = 0; i < static_cast<int>(kReadvTestDataSize); i++) {
    struct iovec iov = {
        .iov_base = &buffer_ptr[i],
        .iov_len = 1,
    };
    iovs_ptr[i] = iov;
  }

  ASSERT_THAT(readv(fd, iovs_ptr, kReadvTestDataSize),
              SyscallSucceedsWithValue(kReadvTestDataSize));

  std::pair<struct iovec*, int> iovec_desc(iovs.data(), kReadvTestDataSize);
  EXPECT_THAT(iovec_desc, MatchesStringLength(kReadvTestDataSize));
  EXPECT_THAT(iovec_desc, MatchesStringValue(kReadvTestData));
}

void ReadBuffersOverlapping(int fd) {
  // overlap the first overlap_bytes.
  int overlap_bytes = 8;
  std::vector<char> buffer(kReadvTestDataSize);

  // overlapping causes us to get more data.
  int expected_size = kReadvTestDataSize + overlap_bytes;
  std::vector<char> expected(expected_size);
  char* expected_ptr = expected.data();
  memcpy(expected_ptr, &kReadvTestData[overlap_bytes], overlap_bytes);
  memcpy(&expected_ptr[overlap_bytes], &kReadvTestData[overlap_bytes],
         kReadvTestDataSize - overlap_bytes);

  struct iovec iovs[2];
  iovs[0].iov_base = buffer.data();
  iovs[0].iov_len = overlap_bytes;
  iovs[1].iov_base = buffer.data();
  iovs[1].iov_len = kReadvTestDataSize;

  ASSERT_THAT(readv(fd, iovs, 2), SyscallSucceedsWithValue(kReadvTestDataSize));

  std::pair<struct iovec*, int> iovec_desc(iovs, 2);
  EXPECT_THAT(iovec_desc, MatchesStringLength(expected_size));
  EXPECT_THAT(iovec_desc, MatchesStringValue(expected_ptr));
}

void ReadBuffersDiscontinuous(int fd) {
  // Each iov is 1 byte separated by 1 byte.
  std::vector<char> buffer(kReadvTestDataSize * 2);
  std::vector<struct iovec> iovs(kReadvTestDataSize);

  char* buffer_ptr = buffer.data();
  struct iovec* iovs_ptr = iovs.data();

  for (int i = 0; i < static_cast<int>(kReadvTestDataSize); i++) {
    struct iovec iov = {
        .iov_base = &buffer_ptr[i * 2],
        .iov_len = 1,
    };
    iovs_ptr[i] = iov;
  }

  ASSERT_THAT(readv(fd, iovs_ptr, kReadvTestDataSize),
              SyscallSucceedsWithValue(kReadvTestDataSize));

  std::pair<struct iovec*, int> iovec_desc(iovs.data(), kReadvTestDataSize);
  EXPECT_THAT(iovec_desc, MatchesStringLength(kReadvTestDataSize));
  EXPECT_THAT(iovec_desc, MatchesStringValue(kReadvTestData));
}

void ReadIovecsCompletelyFilled(int fd) {
  int half = kReadvTestDataSize / 2;
  std::vector<char> buffer(kReadvTestDataSize);
  char* buffer_ptr = buffer.data();
  memset(buffer.data(), '\0', kReadvTestDataSize);

  struct iovec iovs[2];
  iovs[0].iov_base = buffer.data();
  iovs[0].iov_len = half;
  iovs[1].iov_base = &buffer_ptr[half];
  iovs[1].iov_len = half;

  ASSERT_THAT(readv(fd, iovs, 2), SyscallSucceedsWithValue(half * 2));

  std::pair<struct iovec*, int> iovec_desc(iovs, 2);
  EXPECT_THAT(iovec_desc, MatchesStringLength(half * 2));
  EXPECT_THAT(iovec_desc, MatchesStringValue(kReadvTestData));

  char* str = static_cast<char*>(iovs[0].iov_base);
  str[iovs[0].iov_len - 1] = '\0';
  ASSERT_EQ(half - 1, strlen(str));
}

}  // namespace testing
}  // namespace gvisor
