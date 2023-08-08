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

#include <linux/fib_rules.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {
namespace {

constexpr uint32_t kSeq = 12345;
constexpr uint32_t kMetric = 999;

// Types of modifications that may be performed to a Netlink resource.
enum class NetlinkModification {
  kAdd,
  kAddExclusive,
  kReplace,
  kDelete,
};

// Populates |hdr| with appropriate values for the modification type.
PosixError PopulateLinkAddrNlmsghdr(NetlinkModification modification,
                                    struct nlmsghdr* hdr) {
  switch (modification) {
    case NetlinkModification::kAdd:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kAddExclusive:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kReplace:
      hdr->nlmsg_type = RTM_NEWADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kDelete:
      hdr->nlmsg_type = RTM_DELADDR;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
  }

  return PosixError(EINVAL);
}

// Populates |hdr| with appropriate values for the modification type.
PosixError PopulateRouteNlmsghdr(NetlinkModification modification,
                                 struct nlmsghdr* hdr) {
  switch (modification) {
    case NetlinkModification::kAdd:
      hdr->nlmsg_type = RTM_NEWROUTE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
      return NoError();
    case NetlinkModification::kAddExclusive:
      hdr->nlmsg_type = RTM_NEWROUTE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kReplace:
      hdr->nlmsg_type = RTM_NEWROUTE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kDelete:
      hdr->nlmsg_type = RTM_DELROUTE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
  }

  return PosixError(EINVAL);
}

// Populates |hdr| with appropriate values for the modification type.
PosixError PopulateRuleNlmsghdr(NetlinkModification modification,
                                struct nlmsghdr* hdr) {
  switch (modification) {
    case NetlinkModification::kAdd:
      hdr->nlmsg_type = RTM_NEWRULE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kAddExclusive:
      hdr->nlmsg_type = RTM_NEWRULE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kReplace:
      hdr->nlmsg_type = RTM_NEWRULE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case NetlinkModification::kDelete:
      hdr->nlmsg_type = RTM_DELRULE;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
  }

  return PosixError(EINVAL);
}

// Adds or removes the specified address from the specified interface.
PosixError LinkModifyLocalAddr(int index, int family, int prefixlen,
                               const void* addr, int addrlen,
                               NetlinkModification modification) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifaddrmsg ifaddr;
    char attrbuf[512];
  };

  struct request req = {};
  PosixError err = PopulateLinkAddrNlmsghdr(modification, &req.hdr);
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

// Adds or removes the specified route.
PosixError ModifyUnicastRoute(int interface, int family, int prefixlen,
                              const void* dst, int dstlen,
                              NetlinkModification modification) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct rtmsg route;
    char attrbuf[512];
  };

  struct request req = {};
  PosixError err = PopulateRouteNlmsghdr(modification, &req.hdr);
  if (!err.ok()) {
    return err;
  }
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.route));
  req.hdr.nlmsg_seq = kSeq;
  req.route.rtm_dst_len = prefixlen;
  req.route.rtm_family = family;
  req.route.rtm_type = RTN_UNICAST;

  struct rtattr* rta_oif = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta_oif->rta_type = RTA_OIF;
  rta_oif->rta_len = RTA_LENGTH(sizeof(interface));
  req.hdr.nlmsg_len =
      NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(sizeof(interface));
  memcpy(RTA_DATA(rta_oif), &interface, sizeof(interface));

  struct rtattr* rta_priority = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta_priority->rta_type = RTA_PRIORITY;
  rta_priority->rta_len = RTA_LENGTH(sizeof(kMetric));
  req.hdr.nlmsg_len =
      NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(sizeof(kMetric));
  memcpy(RTA_DATA(rta_priority), &kMetric, sizeof(kMetric));

  struct rtattr* rta_dst = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta_dst->rta_type = RTA_DST;
  rta_dst->rta_len = RTA_LENGTH(dstlen);
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(dstlen);
  memcpy(RTA_DATA(rta_dst), dst, dstlen);

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

// Adds or removes the specified route.
PosixError ModifyLookupInTableRule(int family, int table, int priority,
                                   int prefixlen, const void* dst, int dstlen,
                                   NetlinkModification modification) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct fib_rule_hdr rule;
    char attrbuf[512];
  };

  struct request req = {};
  PosixError err = PopulateRuleNlmsghdr(modification, &req.hdr);
  if (!err.ok()) {
    return err;
  }
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.rule));
  req.hdr.nlmsg_seq = kSeq;
  req.rule.family = family;
  req.rule.table = table;
  req.rule.action = FR_ACT_TO_TBL;
  req.rule.dst_len = prefixlen;

  struct rtattr* fra_priority = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  fra_priority->rta_type = FRA_PRIORITY;
  fra_priority->rta_len = RTA_LENGTH(sizeof(priority));
  req.hdr.nlmsg_len =
      NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(sizeof(priority));
  memcpy(RTA_DATA(fra_priority), &priority, sizeof(priority));

  struct rtattr* fra_dst = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  fra_dst->rta_type = FRA_DST;
  fra_dst->rta_len = RTA_LENGTH(dstlen);
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(dstlen);
  memcpy(RTA_DATA(fra_dst), dst, dstlen);

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
                             NetlinkModification::kAdd);
}

PosixError LinkAddExclusiveLocalAddr(int index, int family, int prefixlen,
                                     const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             NetlinkModification::kAddExclusive);
}

PosixError LinkReplaceLocalAddr(int index, int family, int prefixlen,
                                const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             NetlinkModification::kReplace);
}

PosixError LinkDelLocalAddr(int index, int family, int prefixlen,
                            const void* addr, int addrlen) {
  return LinkModifyLocalAddr(index, family, prefixlen, addr, addrlen,
                             NetlinkModification::kDelete);
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

PosixError AddUnicastRoute(int interface, int family, int prefixlen,
                           const void* dst, int dstlen) {
  return ModifyUnicastRoute(interface, family, prefixlen, dst, dstlen,
                            NetlinkModification::kAdd);
}

PosixError DelUnicastRoute(int interface, int family, int prefixlen,
                           const void* dst, int dstlen) {
  return ModifyUnicastRoute(interface, family, prefixlen, dst, dstlen,
                            NetlinkModification::kDelete);
}

PosixError AddExclusiveLookupInTableRule(int family, int table, int priority,
                                         int prefixlen, const void* dst,
                                         int dstlen) {
  return ModifyLookupInTableRule(family, table, priority, prefixlen, dst,
                                 dstlen, NetlinkModification::kAddExclusive);
}

PosixError DelLookupInTableRule(int family, int table, int priority,
                                int prefixlen, const void* dst, int dstlen) {
  return ModifyLookupInTableRule(family, table, priority, prefixlen, dst,
                                 dstlen, NetlinkModification::kDelete);
}

}  // namespace testing
}  // namespace gvisor
