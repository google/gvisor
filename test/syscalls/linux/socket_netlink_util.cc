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

#include <sys/socket.h>

#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vector>

#include "absl/strings/str_cat.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/syscalls/linux/socket_test_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<FileDescriptor> NetlinkBoundSocket() {
  FileDescriptor fd;
  ASSIGN_OR_RETURN_ERRNO(fd, Socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));

  struct sockaddr_nl addr = {};
  addr.nl_family = AF_NETLINK;

  RETURN_ERROR_IF_SYSCALL_FAIL(
      bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)));
  MaybeSave();

  return std::move(fd);
}

PosixErrorOr<uint32_t> NetlinkPortID(int fd) {
  struct sockaddr_nl addr;
  socklen_t addrlen = sizeof(addr);

  RETURN_ERROR_IF_SYSCALL_FAIL(
      getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrlen));
  MaybeSave();

  return static_cast<uint32_t>(addr.nl_pid);
}

PosixError NetlinkRequestResponse(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr) {
  struct iovec iov = {};
  iov.iov_base = request;
  iov.iov_len = len;

  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  // No destination required; it defaults to pid 0, the kernel.

  RETURN_ERROR_IF_SYSCALL_FAIL(RetryEINTR(sendmsg)(fd.get(), &msg, 0));

  constexpr size_t kBufferSize = 4096;
  std::vector<char> buf(kBufferSize);
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();

  // Response is a series of NLM_F_MULTI messages, ending with a NLMSG_DONE
  // message.
  int type = -1;
  do {
    int len;
    RETURN_ERROR_IF_SYSCALL_FAIL(len = RetryEINTR(recvmsg)(fd.get(), &msg, 0));

    // We don't bother with the complexity of dealing with truncated messages.
    // We must allocate a large enough buffer up front.
    if ((msg.msg_flags & MSG_TRUNC) == MSG_TRUNC) {
      return PosixError(EIO,
                        absl::StrCat("Received truncated message with flags: ",
                                     msg.msg_flags));
    }

    for (struct nlmsghdr* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
         NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
      fn(hdr);
      type = hdr->nlmsg_type;
    }
  } while (type != NLMSG_DONE && type != NLMSG_ERROR);

  if (expect_nlmsgerr) {
    EXPECT_EQ(type, NLMSG_ERROR);
  } else {
    EXPECT_EQ(type, NLMSG_DONE);
  }
  return NoError();
}

}  // namespace testing
}  // namespace gvisor
