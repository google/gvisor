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

// Types of neighbor modifications that may be performed.
enum class NeighModification {
  kSet,
  kAddExclusive,
  kReplace,
  kDelete,
};

// Populates |hdr| with appripriate values for the modification type.
PosixError PopulateNdmsghdr(NeighModification modification,
                            struct nlmsghdr* hdr) {
  switch (modification) {
    case NeighModification::kSet:
      hdr->nlmsg_type = RTM_NEWNEIGH;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case NeighModification::kAddExclusive:
      hdr->nlmsg_type = RTM_NEWNEIGH;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
      return NoError();
    case NeighModification::kReplace:
      hdr->nlmsg_type = RTM_NEWNEIGH;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_ACK;
      return NoError();
    case NeighModification::kDelete:
      hdr->nlmsg_type = RTM_DELNEIGH;
      hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
      return NoError();
  }

  return PosixError(EINVAL);
}

// Adds or removes the specified neighbor from the specified interface.
PosixError NeighModify(int index, int family,
                       const void* addr, int addrlen,
                       const void* lladdr, int lladdrlen,
                       NeighModification modification) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ndmsg ndm;
    char attrbuf[512];
  };

  struct request req = {};
  PosixError err = PopulateNdmsghdr(modification, &req.hdr);
  if (!err.ok()) {
    return err;
  }
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ndm));
  req.hdr.nlmsg_seq = kSeq;
  req.ndm.ndm_ifindex = index;
  req.ndm.ndm_family = family;
  req.ndm.ndm_state = NUD_PERMANENT;

  struct rtattr* rta_a = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  rta_a->rta_type = NDA_DST;
  rta_a->rta_len = RTA_LENGTH(addrlen);
  memcpy(RTA_DATA(rta_a), addr, addrlen);
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(addrlen);

  if (lladdr) {
    struct rtattr* rta_ll = reinterpret_cast<struct rtattr*>(
        reinterpret_cast<int8_t*>(&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
    rta_ll->rta_type = NDA_LLADDR;
    rta_ll->rta_len = RTA_LENGTH(lladdrlen);
    memcpy(RTA_DATA(rta_ll), lladdr, lladdrlen);
    req.hdr.nlmsg_len = NLMSG_ALIGN(NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_LENGTH(lladdrlen));
  }

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

PosixErrorOr<Link> EthernetLink() {
  ASSIGN_OR_RETURN_ERRNO(auto links, DumpLinks());
  for (const auto& link : links) {
    if (link.type == ARPHRD_ETHER) {
      return link;
    }
  }
  return PosixError(ENOENT, "Ethernet link not found");
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

PosixError LinkAdd(const std::string name, const std::string kind) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
    char buf[1024];
  };

  struct request req = {};
  size_t rta_len = 0;

  req.ifm.ifi_family = AF_UNSPEC;
  req.ifm.ifi_type = ARPHRD_ETHER;
  req.ifm.ifi_flags = IFF_BROADCAST;

  struct rtattr *rta_name = reinterpret_cast<struct rtattr*>(
    req.buf);

  rta_name->rta_type = IFLA_IFNAME;
  rta_name->rta_len = RTA_LENGTH(name.size() + 1);
  strcpy((char*)RTA_DATA(rta_name), name.c_str());
  rta_len += RTA_ALIGN(rta_name->rta_len);

  struct rtattr *rta_info = reinterpret_cast<struct rtattr*>(
    req.buf + rta_len);

  rta_info->rta_type = IFLA_LINKINFO;

  {
    struct rtattr *rta_info_kind = reinterpret_cast<struct rtattr*>(
      RTA_DATA(rta_info));
    rta_info_kind->rta_type = IFLA_INFO_KIND;
    rta_info_kind->rta_len = RTA_LENGTH(kind.size());
    char * rta_info_kind_d = reinterpret_cast<char *>(
      RTA_DATA(rta_info_kind));
    strcpy(rta_info_kind_d, kind.c_str());

    rta_info->rta_len = RTA_LENGTH(RTA_ALIGN(rta_info_kind->rta_len));
  }

  rta_len += rta_info->rta_len;

  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.hdr.nlmsg_seq = kSeq;
  req.hdr.nlmsg_len = NLMSG_LENGTH(RTA_ALIGN(sizeof(req.ifm)) + rta_len);

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

PosixError LinkDel(const std::string name) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor fd, NetlinkBoundSocket(NETLINK_ROUTE));

  struct request {
    struct nlmsghdr hdr;
    struct ifinfomsg ifm;
    struct rtattr rtattr;
    char ifname[IFNAMSIZ];
    char pad[NLMSG_ALIGNTO + RTA_ALIGNTO];
  };

  struct request req = {};
  req.hdr.nlmsg_type = RTM_DELLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = kSeq;
  req.ifm.ifi_family = AF_UNSPEC;
  req.rtattr.rta_type = IFLA_IFNAME;
  req.rtattr.rta_len = RTA_LENGTH(name.size() + 1);
  strncpy(req.ifname, name.c_str(), sizeof(req.ifname));
  req.hdr.nlmsg_len =
    NLMSG_LENGTH(sizeof(req.ifm)) + NLMSG_ALIGN(req.rtattr.rta_len);

  return NetlinkRequestAckOrError(fd, kSeq, &req, req.hdr.nlmsg_len);
}

PosixError NeighSet(int index, int family,
                   const void* addr, int addrlen,
                   const void* lladdr, int lladdrlen) {
  return NeighModify(index, family, addr, addrlen, lladdr, lladdrlen,
                     NeighModification::kSet);
}

PosixError NeighAddExclusive(int index, int family,
                             const void* addr, int addrlen,
                             const void* lladdr, int lladdrlen) {
  return NeighModify(index, family, addr, addrlen, lladdr, lladdrlen,
                     NeighModification::kAddExclusive);
}

PosixError NeighReplace(int index, int family,
                        const void* addr, int addrlen,
                        const void* lladdr, int lladdrlen) {
  return NeighModify(index, family, addr, addrlen, lladdr, lladdrlen,
                     NeighModification::kReplace);
}

PosixError NeighDel(int index, int family,
                    const void* addr, int addrlen) {
  return NeighModify(index, family, addr, addrlen, NULL, 0,
                     NeighModification::kDelete);
}

}  // namespace testing
}  // namespace gvisor
