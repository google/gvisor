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

#include "test/syscalls/linux/socket_netlink_util.h"

#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <vector>

#include "absl/strings/str_cat.h"
#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

PosixErrorOr<FileDescriptor> NetlinkBoundSocket(int protocol) {
  FileDescriptor fd;
  ASSIGN_OR_RETURN_ERRNO(fd, Socket(AF_NETLINK, SOCK_RAW, protocol));

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

  return NetlinkResponse(fd, fn, expect_nlmsgerr);
}

PosixError NetlinkResponse(
    const FileDescriptor& fd,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr) {
  constexpr size_t kBufferSize = 4096;
  std::vector<char> buf(kBufferSize);
  struct iovec iov = {};
  iov.iov_base = buf.data();
  iov.iov_len = buf.size();
  struct msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // If NLM_F_MULTI is set, response is a series of messages that ends with a
  // NLMSG_DONE message.
  int type = -1;
  int flags = 0;
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
      flags = hdr->nlmsg_flags;
      type = hdr->nlmsg_type;
      // Done should include an integer payload for dump_done_errno.
      // See net/netlink/af_netlink.c:netlink_dump
      // Some tools like the 'ip' tool check the minimum length of the
      // NLMSG_DONE message.
      if (type == NLMSG_DONE) {
        EXPECT_GE(hdr->nlmsg_len, NLMSG_LENGTH(sizeof(int)));
      }
    }
  } while ((flags & NLM_F_MULTI) && type != NLMSG_DONE && type != NLMSG_ERROR);

  if (expect_nlmsgerr) {
    EXPECT_EQ(type, NLMSG_ERROR);
  } else if (flags & NLM_F_MULTI) {
    EXPECT_EQ(type, NLMSG_DONE);
  }
  return NoError();
}

PosixError NetlinkRequestResponseSingle(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn) {
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

  int ret;
  RETURN_ERROR_IF_SYSCALL_FAIL(ret = RetryEINTR(recvmsg)(fd.get(), &msg, 0));

  // We don't bother with the complexity of dealing with truncated messages.
  // We must allocate a large enough buffer up front.
  if ((msg.msg_flags & MSG_TRUNC) == MSG_TRUNC) {
    return PosixError(
        EIO,
        absl::StrCat("Received truncated message with flags: ", msg.msg_flags));
  }

  for (struct nlmsghdr* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
       NLMSG_OK(hdr, ret); hdr = NLMSG_NEXT(hdr, ret)) {
    fn(hdr);
  }

  return NoError();
}

PosixError NetlinkRequestAckOrError(const FileDescriptor& fd, uint32_t seq,
                                    void* request, size_t len) {
  // Dummy negative number for no error message received.
  // We won't get a negative error number so there will be no confusion.
  int err = -42;
  RETURN_IF_ERRNO(NetlinkRequestResponse(
      fd, request, len,
      [&](const struct nlmsghdr* hdr) {
        EXPECT_EQ(NLMSG_ERROR, hdr->nlmsg_type);
        EXPECT_EQ(hdr->nlmsg_seq, seq);
        EXPECT_GE(hdr->nlmsg_len, sizeof(*hdr) + sizeof(struct nlmsgerr));

        const struct nlmsgerr* msg =
            reinterpret_cast<const struct nlmsgerr*>(NLMSG_DATA(hdr));
        err = -msg->error;
      },
      true));
  return PosixError(err);
}

const struct rtattr* FindRtAttr(const struct nlmsghdr* hdr,
                                const struct ifinfomsg* msg, int16_t attr) {
  const int ifi_space = NLMSG_SPACE(sizeof(*msg));
  int attrlen = hdr->nlmsg_len - ifi_space;
  const struct rtattr* rta = reinterpret_cast<const struct rtattr*>(
      reinterpret_cast<const uint8_t*>(hdr) + NLMSG_ALIGN(ifi_space));
  for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
    if (rta->rta_type == attr) {
      return rta;
    }
  }
  return nullptr;
}

}  // namespace testing
}  // namespace gvisor
