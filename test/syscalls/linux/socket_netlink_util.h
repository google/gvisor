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

#ifndef GVISOR_TEST_SYSCALLS_SOCKET_NETLINK_UTIL_H_
#define GVISOR_TEST_SYSCALLS_SOCKET_NETLINK_UTIL_H_

#include <sys/socket.h>
// socket.h has to be included before if_arp.h.
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Returns a bound netlink socket.
PosixErrorOr<FileDescriptor> NetlinkBoundSocket(int protocol);

// Returns the port ID of the passed socket.
PosixErrorOr<uint32_t> NetlinkPortID(int fd);

// Send the passed request and call fn on all response netlink messages.
//
// To be used on requests with NLM_F_MULTI reponses.
PosixError NetlinkRequestResponse(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr);

// Call fn on all response netlink messages.
//
// To be used on requests with NLM_F_MULTI reponses.
PosixError NetlinkResponse(
    const FileDescriptor& fd,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr);

// Send the passed request and call fn on all response netlink messages.
//
// To be used on requests without NLM_F_MULTI reponses.
PosixError NetlinkRequestResponseSingle(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn);

// Send the passed request then expect and return an ack or error.
PosixError NetlinkRequestAckOrError(const FileDescriptor& fd, uint32_t seq,
                                    void* request, size_t len);

// Find rtnetlink attribute in message.
const struct rtattr* FindRtAttr(const struct nlmsghdr* hdr,
                                const struct ifinfomsg* msg, int16_t attr);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_SOCKET_NETLINK_UTIL_H_
