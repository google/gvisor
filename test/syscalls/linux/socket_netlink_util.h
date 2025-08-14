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
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cstddef>
#include <cstdint>
#include <functional>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Returns a bound netlink socket.
PosixErrorOr<FileDescriptor> NetlinkBoundSocket(int protocol);

// Returns the port ID of the passed socket.
PosixErrorOr<uint32_t> NetlinkPortID(int fd);

// Send the passed request.
PosixError NetlinkRequest(const FileDescriptor& fd, void* request, size_t len);

// Send the passed request and call fn on all response netlink messages.
//
// To be used on requests with NLM_F_MULTI responses.
PosixError NetlinkRequestResponse(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr);

// Call fn on all response netlink messages.
//
// To be used on requests with NLM_F_MULTI responses.
PosixError NetlinkResponse(
    const FileDescriptor& fd,
    const std::function<void(const struct nlmsghdr* hdr)>& fn,
    bool expect_nlmsgerr);

// Send the passed request and call fn on all response netlink messages.
//
// To be used on requests without NLM_F_MULTI responses.
PosixError NetlinkRequestResponseSingle(
    const FileDescriptor& fd, void* request, size_t len,
    const std::function<void(const struct nlmsghdr* hdr)>& fn);

// Send the passed request then expect and return an ack or error.
PosixError NetlinkRequestAckOrError(const FileDescriptor& fd, uint32_t seq,
                                    void* request, size_t len);

PosixError NetlinkNetfilterBatchRequestAckOrError(const FileDescriptor& fd,
                                                  uint32_t seq_start,
                                                  uint32_t seq_end,
                                                  void* request, size_t len);

// Find rtnetlink attribute in message.
const struct rtattr* FindRtAttr(const struct nlmsghdr* hdr,
                                const struct ifinfomsg* msg, int16_t attr);

// Helper function to make a netlink message type from a subsystem ID and a
// message type.
uint16_t MakeNetlinkMsgType(uint8_t subsys_id, uint8_t msg_type);

// Helper function to initialize a netlink header.
void InitNetlinkHdr(struct nlmsghdr* hdr, uint32_t msg_len, uint16_t msg_type,
                    uint32_t seq, uint16_t flags);

// Helper function to initialize a netlink attribute.
void InitNetlinkAttr(struct nlattr* attr, int payload_size, uint16_t attr_type);

// Helper function to find a netlink attribute in a message.
const struct nfattr* FindNfAttr(const struct nlmsghdr* hdr,
                                const struct nfgenmsg* msg, int16_t attr);
}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_SOCKET_NETLINK_UTIL_H_
