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

#include "test/syscalls/linux/socket_netlink_route_util.h"

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "test/syscalls/linux/socket_netlink_util.h"

namespace gvisor {
namespace testing {
namespace {

constexpr uint32_t kSeq = 12345;

// Types of address modifications that may be performed on an interface.
enum class LinkAddrModification {
  kAdd,
  kAddExclusive,
  kReplace,
  kDelete,
};

// Populates |hdr| with appripriate values for the modification type.
PosixError PopulateNlmsghdr(LinkAddrModification modification,
                            struct nlmsghdr* hdr) {
  switch (modification) {
    case LinkAddrModification::kAdd:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
    case LinkAddrModification::kAddExclusive:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_ACK;
      return NoError();
    case LinkAddrModification::kReplace:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case LinkAddrModification::kDelete:
      hdr->nlmsg_type = RTM_DELADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
  }

  return PosixError(EINVAL);
}

// Adds or removes the specified address from the specified interface.
PosixError LinkModifyLocalAddr(int index, int family, int prefixlen,
                               const void* addr, int addrlen,
                               LinkAddrModification modification) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifaddrmsg ifaddr;
    char attrbuf[512];
  };

  struct request req = {};
  PosixError err = PopulateNlmsghdr(modification, &req.hdr);
  if (!err.ok()) {
    return err;
  }
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifaddr));
  req.hdr.nlmsg_seq = kSeq;
  req.ifaddr.ifa_index = index;
  req.ifaddr.ifa_family = family;
  req.ifaddr.ifa_prefixlen = prefixlen;

  struct rtattr* rta = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta->rta_type = IFA_LOCAL;
  rta->rta_len = RTA_LENGTH(addrlen);
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(addrlen);
  memcpy(RTA_DATA(rta), addr, addrlen);

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

}  // namespace

PosixError DumpLinks(
    const FileDescriptor& fd, uint32_t seq,
    const std::function<void(const struct nlmsghdr* hdr)>& fn) {
  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
  };

  struct request req = {};
  req.hdr.nlmsg_len = sizeof(req);
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.hdr.nlmsg_seq = seq;
  req.ifm.ifi_family = AF_UNSPEC;

  return NetlinkRequestResponse(fd, &req, sizeof(req), fn, false);
}

PosixErrorOr<std::vector<Link>> DumpLinks() {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  std::vector<Link> links;
  RETURN_IF_ERRNO(DumpLinks(fd, kSeq, [&](const struct nlmsghdr* hdr) {
    if (hdr->nlmsg_type != RTM_NEWLINK ||
        hdr->nlmsg_len < NLMSG_SPACE(sizeof(struct ifinfomsg))) {
      return;
    }
    const struct ifinfomsg* msg =
        reinterpret_cast<const struct ifinfomsg*>(NLMSG_DATA(hdr));
    const auto* rta = FindRtAttr(hdr, msg, IFLA_IFNAME);
    if (rta == nullptr) {
      // Ignore links that do not have a name.
      return;
    }

    links.emplace_back();
    links.back().index = msg->ifi_index;
    links.back().type = msg->ifi_type;
    links.back().name =
        std::string(reinterpret_cast<const char*>(RTA_DATA(rta)));
  }));
  return links;
}

PosixErrorOr<Link> LoopbackLink() {
  ASSIGN_OR_RETURN_ERRNO(auto links, DumpLinks());
  for (const auto& link : links) {
    if (link.type == ARPHRD_LOOPBACK) {
      return link;
    }
  }
  return PosixError(ENOENT, "loopback link not found");
}

PosixError LinkAddLocalAddr(int index, int family, int prefixlen,
                            const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             LinkAddrModification::kAdd);
}

PosixError LinkAddExclusiveLocalAddr(int index, int family, int prefixlen,
                                     const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             LinkAddrModification::kAddExclusive);
}

PosixError LinkReplaceLocalAddr(int index, int family, int prefixlen,
                                const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             LinkAddrModification::kReplace);
}

PosixError LinkDelLocalAddr(int index, int family, int prefixlen,
                            const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             LinkAddrModification::kDelete);
}

PosixError LinkChangeFlags(int index, unsigned int flags, unsigned int change) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifinfo;
    char pad[NLMSG_ALIGNTO];
  };

  struct request req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = kSeq;
  req.ifinfo.ifi_index = index;
  req.ifinfo.ifi_flags = flags;
  req.ifinfo.ifi_change = change;

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

PosixError LinkSetMacAddr(int index, const void* addr, int addrlen) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifinfo;
    char attrbuf[512];
  };

  struct request req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifinfo));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = kSeq;
  req.ifinfo.ifi_index = index;

  struct rtattr* rta = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta->rta_type = IFLA_ADDRESS;
  rta->rta_len = RTA_LENGTH(addrlen);
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(addrlen);
  memcpy(RTA_DATA(rta), addr, addrlen);

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

}  // namespace testing
}  // namespace gvisor
