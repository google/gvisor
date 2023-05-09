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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "test/syscalls/linux/ip_socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/socket_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

class SendFileTest : public ::testing::TestWithParam<int> {
 protected:
  PosixErrorOr<std::unique_ptr<SocketPair>> Sockets(int type) {
    // Bind a server socket.
    int family = GetParam();
    switch (family) {
      case AF_INET: {
        if (type == SOCK_STREAM) {
          return SocketPairKind{
              "TCP", AF_INET, type, 0,
              TCPAcceptBindSocketPairCreator(AF_INET, type, 0, false)}
              .Create();
        } else {
          return SocketPairKind{
              "UDP", AF_INET, type, 0,
              UDPBidirectionalBindSocketPairCreator(AF_INET, type, 0, false)}
              .Create();
        }
      }
      case AF_UNIX: {
        if (type == SOCK_STREAM) {
          return SocketPairKind{
              "UNIX", AF_UNIX, type, 0,
              FilesystemAcceptBindSocketPairCreator(AF_UNIX, type, 0)}
              .Create();
        } else {
          return SocketPairKind{
              "UNIX", AF_UNIX, type, 0,
              FilesystemBidirectionalBindSocketPairCreator(AF_UNIX, type, 0)}
              .Create();
        }
      }
      default:
        return PosixError(EINVAL);
    }
  }
};

// Sends large file to exercise the path that read and writes data multiple
// times, esp. when more data is read than can be written.
TEST_P(SendFileTest, SendMultiple) {
  std::vector<char> data(5 * 1024 * 1024);
  RandomizeBuffer(data.data(), data.size());

  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(data.data(), data.size()),
      TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Create sockets.
  auto socks = ASSERT_NO_ERRNO_AND_VALUE(Sockets(SOCK_STREAM));

  // Thread that reads data from socket and dumps to a file.
  ScopedThread th([&] {
    FileDescriptor outf =
        ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

    // Read until socket is closed.
    char buf[10240];
    for (int cnt = 0;; cnt++) {
      int r = RetryEINTR(read)(socks->first_fd(), buf, sizeof(buf));
      // We cannot afford to save on every read() call.
      if (cnt % 1000 == 0) {
        ASSERT_THAT(r, SyscallSucceeds());
      } else {
        const DisableSave ds;
        ASSERT_THAT(r, SyscallSucceeds());
      }
      if (r == 0) {
        // EOF
        break;
      }
      int w = RetryEINTR(write)(outf.get(), buf, r);
      // We cannot afford to save on every write() call.
      if (cnt % 1010 == 0) {
        ASSERT_THAT(w, SyscallSucceedsWithValue(r));
      } else {
        const DisableSave ds;
        ASSERT_THAT(w, SyscallSucceedsWithValue(r));
      }
    }
  });

  // Open the input file as read only.
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  int cnt = 0;
  for (size_t sent = 0; sent < data.size(); cnt++) {
    const size_t remain = data.size() - sent;
    std::cout << "sendfile, size=" << data.size() << ", sent=" << sent
              << ", remain=" << remain << std::endl;

    // Send data and verify that sendfile returns the correct value.
    int res = sendfile(socks->second_fd(), inf.get(), nullptr, remain);
    // We cannot afford to save on every sendfile() call.
    if (cnt % 120 == 0) {
      MaybeSave();
    }
    if (res == 0) {
      // EOF
      break;
    }
    if (res > 0) {
      sent += res;
    } else {
      ASSERT_TRUE(errno == EINTR || errno == EAGAIN) << "errno=" << errno;
    }
  }

  // Close socket to stop thread.
  close(socks->release_second_fd());
  th.Join();

  // Verify that the output file has the correct data.
  const FileDescriptor outf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));
  std::vector<char> actual(data.size(), '\0');
  ASSERT_THAT(RetryEINTR(read)(outf.get(), actual.data(), actual.size()),
              SyscallSucceedsWithValue(actual.size()));
  ASSERT_EQ(memcmp(data.data(), actual.data(), data.size()), 0);
}

TEST_P(SendFileTest, Shutdown) {
  // Create a socket.
  auto socks = ASSERT_NO_ERRNO_AND_VALUE(Sockets(SOCK_STREAM));

  // If this is a TCP socket, then turn off linger.
  if (GetParam() == AF_INET) {
    struct linger sl;
    sl.l_onoff = 1;
    sl.l_linger = 0;
    ASSERT_THAT(
        setsockopt(socks->first_fd(), SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)),
        SyscallSucceeds());
  }

  // Create a 1m file with random data.
  std::vector<char> data(1024 * 1024);
  RandomizeBuffer(data.data(), data.size());
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(data.data(), data.size()),
      TempPath::kDefaultFileMode));
  const FileDescriptor inf =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDONLY));

  // Read some data, then shutdown the socket. We don't actually care about
  // checking the contents (other tests do that), so we just re-use the same
  // buffer as above.
  ScopedThread t([&]() {
    size_t done = 0;
    while (done < data.size()) {
      int n = RetryEINTR(read)(socks->first_fd(), data.data(), data.size());
      ASSERT_THAT(n, SyscallSucceeds());
      done += n;
    }
    // Close the server side socket.
    close(socks->release_first_fd());
  });

  // Continuously stream from the file to the socket. Note we do not assert
  // that a specific amount of data has been written at any time, just that some
  // data is written. Eventually, we should get a connection reset error.
  while (1) {
    off_t offset = 0;  // Always read from the start.
    int n = sendfile(socks->second_fd(), inf.get(), &offset, data.size());
    EXPECT_THAT(n, AnyOf(SyscallFailsWithErrno(ECONNRESET),
                         SyscallFailsWithErrno(EPIPE), SyscallSucceeds()));
    if (n <= 0) {
      break;
    }
  }
}

TEST_P(SendFileTest, SendpageFromEmptyFileToUDP) {
  auto socks = ASSERT_NO_ERRNO_AND_VALUE(Sockets(SOCK_DGRAM));

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDWR));

  // The value to the count argument has to be so that it is impossible to
  // allocate a buffer of this size. In Linux, sendfile transfer at most
  // 0x7ffff000 (MAX_RW_COUNT) bytes.
  EXPECT_THAT(sendfile(socks->first_fd(), fd.get(), 0x0, 0x8000000000004),
              SyscallSucceedsWithValue(0));
}

INSTANTIATE_TEST_SUITE_P(AddressFamily, SendFileTest,
                         ::testing::Values(AF_UNIX, AF_INET));

}  // namespace
}  // namespace testing
}  // namespace gvisor
