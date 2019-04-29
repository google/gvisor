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
#include "test/syscalls/linux/socket_test_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {
namespace {

// Sends large file to exercise the path that read and writes data multiple
// times, esp. when more data is read than can be written.
TEST(SendFileTest, SendMultiple) {
  std::vector<char> data(5 * 1024 * 1024);
  RandomizeBuffer(data.data(), data.size());

  // Create temp files.
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), absl::string_view(data.data(), data.size()),
      TempPath::kDefaultFileMode));
  const TempPath out_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());

  // Use a socket for target file to make the write window small.
  const FileDescriptor server(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(server.get(), SyscallSucceeds());

  struct sockaddr_in server_addr = {};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  ASSERT_THAT(
      bind(server.get(), reinterpret_cast<struct sockaddr *>(&server_addr),
           sizeof(server_addr)),
      SyscallSucceeds());
  ASSERT_THAT(listen(server.get(), 1), SyscallSucceeds());

  // Thread that reads data from socket and dumps to a file.
  ScopedThread th([&server, &out_file, &server_addr] {
    socklen_t addrlen = sizeof(server_addr);
    const FileDescriptor fd(RetryEINTR(accept)(
        server.get(), reinterpret_cast<struct sockaddr *>(&server_addr),
        &addrlen));
    ASSERT_THAT(fd.get(), SyscallSucceeds());

    FileDescriptor outf =
        ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_WRONLY));

    // Read until socket is closed.
    char buf[10240];
    for (int cnt = 0;; cnt++) {
      int r = RetryEINTR(read)(fd.get(), buf, sizeof(buf));
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

  FileDescriptor outf(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  ASSERT_THAT(outf.get(), SyscallSucceeds());

  // Get the port bound by the listening socket.
  socklen_t addrlen = sizeof(server_addr);
  ASSERT_THAT(getsockname(server.get(),
                          reinterpret_cast<sockaddr *>(&server_addr), &addrlen),
              SyscallSucceeds());

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = server_addr.sin_port;
  std::cout << "Connecting on port=" << server_addr.sin_port;
  ASSERT_THAT(
      RetryEINTR(connect)(
          outf.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)),
      SyscallSucceeds());

  int cnt = 0;
  for (size_t sent = 0; sent < data.size(); cnt++) {
    const size_t remain = data.size() - sent;
    std::cout << "sendfile, size=" << data.size() << ", sent=" << sent
              << ", remain=" << remain;

    // Send data and verify that sendfile returns the correct value.
    int res = sendfile(outf.get(), inf.get(), nullptr, remain);
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
  outf.reset();
  th.Join();

  // Verify that the output file has the correct data.
  outf = ASSERT_NO_ERRNO_AND_VALUE(Open(out_file.path(), O_RDONLY));
  std::vector<char> actual(data.size(), '\0');
  ASSERT_THAT(RetryEINTR(read)(outf.get(), actual.data(), actual.size()),
              SyscallSucceedsWithValue(actual.size()));
  ASSERT_EQ(memcmp(data.data(), actual.data(), data.size()), 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
