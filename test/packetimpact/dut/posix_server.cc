// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <unordered_map>

#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "test/packetimpact/proto/posix_server.grpc.pb.h"
#include "test/packetimpact/proto/posix_server.pb.h"

// Converts a sockaddr_storage to a Sockaddr message.
::grpc::Status sockaddr_to_proto(const sockaddr_storage &addr,
                                 socklen_t addrlen,
                                 posix_server::Sockaddr *sockaddr_proto) {
  switch (addr.ss_family) {
    case AF_INET: {
      auto addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
      auto response_in = sockaddr_proto->mutable_in();
      response_in->set_family(addr_in->sin_family);
      response_in->set_port(ntohs(addr_in->sin_port));
      response_in->mutable_addr()->assign(
          reinterpret_cast<const char *>(&addr_in->sin_addr.s_addr), 4);
      return ::grpc::Status::OK;
    }
    case AF_INET6: {
      auto addr_in6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
      auto response_in6 = sockaddr_proto->mutable_in6();
      response_in6->set_family(addr_in6->sin6_family);
      response_in6->set_port(ntohs(addr_in6->sin6_port));
      response_in6->set_flowinfo(ntohl(addr_in6->sin6_flowinfo));
      response_in6->mutable_addr()->assign(
          reinterpret_cast<const char *>(&addr_in6->sin6_addr.s6_addr), 16);
      response_in6->set_scope_id(ntohl(addr_in6->sin6_scope_id));
      return ::grpc::Status::OK;
    }
  }
  return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Unknown Sockaddr");
}

::grpc::Status proto_to_sockaddr(const posix_server::Sockaddr &sockaddr_proto,
                                 sockaddr_storage *addr, socklen_t *addr_len) {
  switch (sockaddr_proto.sockaddr_case()) {
    case posix_server::Sockaddr::SockaddrCase::kIn: {
      auto proto_in = sockaddr_proto.in();
      if (proto_in.addr().size() != 4) {
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "IPv4 address must be 4 bytes");
      }
      auto addr_in = reinterpret_cast<sockaddr_in *>(addr);
      addr_in->sin_family = proto_in.family();
      addr_in->sin_port = htons(proto_in.port());
      proto_in.addr().copy(reinterpret_cast<char *>(&addr_in->sin_addr.s_addr),
                           4);
      *addr_len = sizeof(*addr_in);
      break;
    }
    case posix_server::Sockaddr::SockaddrCase::kIn6: {
      auto proto_in6 = sockaddr_proto.in6();
      if (proto_in6.addr().size() != 16) {
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "IPv6 address must be 16 bytes");
      }
      auto addr_in6 = reinterpret_cast<sockaddr_in6 *>(addr);
      addr_in6->sin6_family = proto_in6.family();
      addr_in6->sin6_port = htons(proto_in6.port());
      addr_in6->sin6_flowinfo = htonl(proto_in6.flowinfo());
      proto_in6.addr().copy(
          reinterpret_cast<char *>(&addr_in6->sin6_addr.s6_addr), 16);
      addr_in6->sin6_scope_id = htonl(proto_in6.scope_id());
      *addr_len = sizeof(*addr_in6);
      break;
    }
    case posix_server::Sockaddr::SockaddrCase::SOCKADDR_NOT_SET:
    default:
      return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Unknown Sockaddr");
  }
  return ::grpc::Status::OK;
}

void cmsg_to_proto(struct msghdr &msg, posix_server::MsgHdr *proto) {
  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    auto *cmsg_proto = proto->add_control();
    switch (cmsg->cmsg_level) {
      case IPPROTO_IP:
        switch (cmsg->cmsg_type) {
          case IP_ORIGDSTADDR: {
            struct sockaddr_in addr;
            memcpy(&addr, CMSG_DATA(cmsg), sizeof(addr));
            cmsg_proto->mutable_ip_origdstaddr()->set_family(addr.sin_family);
            cmsg_proto->mutable_ip_origdstaddr()->set_port(
                ntohs(addr.sin_port));
            cmsg_proto->mutable_ip_origdstaddr()->mutable_addr()->assign(
                reinterpret_cast<const char *>(&addr.sin_addr.s_addr), 4);
            break;
          }
          case IP_PKTINFO: {
            struct in_pktinfo pkt_info;
            memcpy(&pkt_info, CMSG_DATA(cmsg), sizeof(pkt_info));
            auto *pkt_info_proto = cmsg_proto->mutable_ip_pktinfo();
            pkt_info_proto->set_ifindex(pkt_info.ipi_ifindex);
            pkt_info_proto->mutable_spec_dst()->assign(
                reinterpret_cast<const char *>(&pkt_info.ipi_spec_dst.s_addr),
                4);
            pkt_info_proto->mutable_addr()->assign(
                reinterpret_cast<const char *>(&pkt_info.ipi_addr.s_addr), 4);
            break;
          }
          case IP_TOS: {
            unsigned char tos = 0;
            memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
            cmsg_proto->set_ip_tos(tos);
            break;
          }
          case IP_TTL: {
            int ttl = 0;
            memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
            cmsg_proto->set_ip_ttl(ttl);
            break;
          }
        }
        break;
      case IPPROTO_IPV6:
        switch (cmsg->cmsg_type) {
          case IPV6_PKTINFO:
            struct in6_pktinfo pkt_info;
            memcpy(&pkt_info, CMSG_DATA(cmsg), sizeof(pkt_info));
            auto *pkt_info_proto = cmsg_proto->mutable_ipv6_pktinfo();
            pkt_info_proto->set_ifindex(pkt_info.ipi6_ifindex);
            pkt_info_proto->mutable_addr()->assign(
                reinterpret_cast<const char *>(&pkt_info.ipi6_addr.s6_addr),
                16);
            break;
        }
        break;
    }
  }
}

::grpc::Status proto_to_cmsg(const posix_server::MsgHdr &proto,
                             struct msghdr *msg) {
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
  size_t control_len = 0;
  for (auto it = proto.control().begin(); it != proto.control().end(); ++it) {
    if (cmsg == NULL) {
      return ::grpc::Status(grpc::StatusCode::INTERNAL,
                            "not enough space in buffer to add cmsg");
    }
    switch (it->cmsg_case()) {
      case ::posix_server::CMsg::kIpOrigdstaddr:
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "sendmsg does not support IP_ORIGDSTADDR cmsg");
      case ::posix_server::CMsg::kIpPktinfo: {
        struct in_pktinfo pkt_info;
        pkt_info.ipi_ifindex = it->ip_pktinfo().ifindex();
        it->ip_pktinfo().spec_dst().copy(
            reinterpret_cast<char *>(&pkt_info.ipi_spec_dst), 4);
        it->ip_pktinfo().addr().copy(
            reinterpret_cast<char *>(&pkt_info.ipi_addr), 4);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(pkt_info));
        memcpy(CMSG_DATA(cmsg), &pkt_info, sizeof(pkt_info));
        control_len += CMSG_SPACE(sizeof(pkt_info));
        break;
      }
      case ::posix_server::CMsg::kIpTos: {
        char tos = it->ip_tos();
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
        memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));
        control_len += CMSG_SPACE(sizeof(tos));
        break;
      }
      case ::posix_server::CMsg::kIpTtl: {
        int ttl = it->ip_ttl();
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TTL;
        cmsg->cmsg_len = CMSG_LEN(sizeof(ttl));
        memcpy(CMSG_DATA(cmsg), &ttl, sizeof(ttl));
        control_len += CMSG_SPACE(sizeof(ttl));
        break;
      }
      case ::posix_server::CMsg::kIpv6Hoplimit: {
        int hopLimit = it->ipv6_hoplimit();
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_HOPLIMIT;
        cmsg->cmsg_len = CMSG_LEN(sizeof(hopLimit));
        memcpy(CMSG_DATA(cmsg), &hopLimit, sizeof(hopLimit));
        control_len += CMSG_SPACE(sizeof(hopLimit));
        break;
      }
      case ::posix_server::CMsg::kIpv6Pktinfo: {
        struct in6_pktinfo pkt_info;
        pkt_info.ipi6_ifindex = it->ipv6_pktinfo().ifindex();
        it->ip_pktinfo().addr().copy(
            reinterpret_cast<char *>(&pkt_info.ipi6_addr), 16);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(pkt_info));
        memcpy(CMSG_DATA(cmsg), &pkt_info, sizeof(pkt_info));
        control_len += CMSG_SPACE(sizeof(pkt_info));
        break;
      }
      default:
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "unknown or unset cmsg type");
    }
    cmsg = CMSG_NXTHDR(msg, cmsg);
  }
  msg->msg_controllen = control_len;
  return ::grpc::Status::OK;
}

class PosixImpl final : public posix_server::Posix::Service {
  ::grpc::Status Accept(grpc_impl::ServerContext *context,
                        const ::posix_server::AcceptRequest *request,
                        ::posix_server::AcceptResponse *response) override {
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    response->set_fd(accept(request->sockfd(),
                            reinterpret_cast<sockaddr *>(&addr), &addrlen));
    response->set_errno_(errno);
    return sockaddr_to_proto(addr, addrlen, response->mutable_addr());
  }

  ::grpc::Status Bind(grpc_impl::ServerContext *context,
                      const ::posix_server::BindRequest *request,
                      ::posix_server::BindResponse *response) override {
    if (!request->has_addr()) {
      return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Missing address");
    }

    sockaddr_storage addr;
    socklen_t addr_len;
    auto err = proto_to_sockaddr(request->addr(), &addr, &addr_len);
    if (!err.ok()) {
      return err;
    }

    response->set_ret(
        bind(request->sockfd(), reinterpret_cast<sockaddr *>(&addr), addr_len));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Close(grpc_impl::ServerContext *context,
                       const ::posix_server::CloseRequest *request,
                       ::posix_server::CloseResponse *response) override {
    response->set_ret(close(request->fd()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Connect(grpc_impl::ServerContext *context,
                         const ::posix_server::ConnectRequest *request,
                         ::posix_server::ConnectResponse *response) override {
    if (!request->has_addr()) {
      return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Missing address");
    }
    sockaddr_storage addr;
    socklen_t addr_len;
    auto err = proto_to_sockaddr(request->addr(), &addr, &addr_len);
    if (!err.ok()) {
      return err;
    }

    response->set_ret(connect(request->sockfd(),
                              reinterpret_cast<sockaddr *>(&addr), addr_len));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Fcntl(grpc_impl::ServerContext *context,
                       const ::posix_server::FcntlRequest *request,
                       ::posix_server::FcntlResponse *response) override {
    response->set_ret(::fcntl(request->fd(), request->cmd(), request->arg()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status GetSockName(
      grpc_impl::ServerContext *context,
      const ::posix_server::GetSockNameRequest *request,
      ::posix_server::GetSockNameResponse *response) override {
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    response->set_ret(getsockname(
        request->sockfd(), reinterpret_cast<sockaddr *>(&addr), &addrlen));
    response->set_errno_(errno);
    return sockaddr_to_proto(addr, addrlen, response->mutable_addr());
  }

  ::grpc::Status GetSockOpt(
      grpc_impl::ServerContext *context,
      const ::posix_server::GetSockOptRequest *request,
      ::posix_server::GetSockOptResponse *response) override {
    switch (request->type()) {
      case ::posix_server::GetSockOptRequest::BYTES: {
        socklen_t optlen = request->optlen();
        std::vector<char> buf(optlen);
        response->set_ret(::getsockopt(request->sockfd(), request->level(),
                                       request->optname(), buf.data(),
                                       &optlen));
        if (optlen >= 0) {
          response->mutable_optval()->set_bytesval(buf.data(), optlen);
        }
        break;
      }
      case ::posix_server::GetSockOptRequest::INT: {
        int intval = 0;
        socklen_t optlen = sizeof(intval);
        response->set_ret(::getsockopt(request->sockfd(), request->level(),
                                       request->optname(), &intval, &optlen));
        response->mutable_optval()->set_intval(intval);
        break;
      }
      case ::posix_server::GetSockOptRequest::TIME: {
        timeval tv;
        socklen_t optlen = sizeof(tv);
        response->set_ret(::getsockopt(request->sockfd(), request->level(),
                                       request->optname(), &tv, &optlen));
        response->mutable_optval()->mutable_timeval()->set_seconds(tv.tv_sec);
        response->mutable_optval()->mutable_timeval()->set_microseconds(
            tv.tv_usec);
        break;
      }
      default:
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "Unknown SockOpt Type");
    }
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Listen(grpc_impl::ServerContext *context,
                        const ::posix_server::ListenRequest *request,
                        ::posix_server::ListenResponse *response) override {
    response->set_ret(listen(request->sockfd(), request->backlog()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Send(::grpc::ServerContext *context,
                      const ::posix_server::SendRequest *request,
                      ::posix_server::SendResponse *response) override {
    response->set_ret(::send(request->sockfd(), request->buf().data(),
                             request->buf().size(), request->flags()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendTo(::grpc::ServerContext *context,
                        const ::posix_server::SendToRequest *request,
                        ::posix_server::SendToResponse *response) override {
    if (!request->has_dest_addr()) {
      return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Missing address");
    }
    sockaddr_storage addr;
    socklen_t addr_len;
    auto err = proto_to_sockaddr(request->dest_addr(), &addr, &addr_len);
    if (!err.ok()) {
      return err;
    }

    response->set_ret(::sendto(request->sockfd(), request->buf().data(),
                               request->buf().size(), request->flags(),
                               reinterpret_cast<sockaddr *>(&addr), addr_len));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SendMsg(::grpc::ServerContext *context,
                         const ::posix_server::SendMsgRequest *request,
                         ::posix_server::SendMsgResponse *response) override {
    struct msghdr msg = {0};
    sockaddr_storage addr;
    if (request->msg().has_name()) {
      auto status =
          proto_to_sockaddr(request->msg().name(), &addr, &msg.msg_namelen);
      if (!status.ok()) {
        return status;
      }
      msg.msg_name = &addr;
    }

    std::vector<struct iovec> iov(request->msg().iov_size());
    auto it_proto = request->msg().iov().begin();
    for (auto it = iov.begin(); it != iov.end(); ++it, ++it_proto) {
      it->iov_base = (char *)it_proto->data();
      it->iov_len = it_proto->size();
    }
    msg.msg_iov = iov.data();
    msg.msg_iovlen = iov.size();

    union {
      // 4kB is large enough to store one of every cmsg that exists.
      char buf[4096];
      struct cmsghdr align;
    } u;
    memset(u.buf, 0, sizeof(u.buf));
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof(u.buf);
    auto status = proto_to_cmsg(request->msg(), &msg);
    if (!status.ok()) {
      return status;
    }

    response->set_ret(::sendmsg(request->sockfd(), &msg, request->flags()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetSockOpt(
      grpc_impl::ServerContext *context,
      const ::posix_server::SetSockOptRequest *request,
      ::posix_server::SetSockOptResponse *response) override {
    switch (request->optval().val_case()) {
      case ::posix_server::SockOptVal::kBytesval:
        response->set_ret(setsockopt(request->sockfd(), request->level(),
                                     request->optname(),
                                     request->optval().bytesval().c_str(),
                                     request->optval().bytesval().size()));
        break;
      case ::posix_server::SockOptVal::kIntval: {
        int opt = request->optval().intval();
        response->set_ret(::setsockopt(request->sockfd(), request->level(),
                                       request->optname(), &opt, sizeof(opt)));
        break;
      }
      case ::posix_server::SockOptVal::kTimeval: {
        timeval tv = {.tv_sec = static_cast<__time_t>(
                          request->optval().timeval().seconds()),
                      .tv_usec = static_cast<__suseconds_t>(
                          request->optval().timeval().microseconds())};
        response->set_ret(setsockopt(request->sockfd(), request->level(),
                                     request->optname(), &tv, sizeof(tv)));
        break;
      }
      default:
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "Unknown SockOpt Type");
    }
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Socket(grpc_impl::ServerContext *context,
                        const ::posix_server::SocketRequest *request,
                        ::posix_server::SocketResponse *response) override {
    response->set_fd(
        socket(request->domain(), request->type(), request->protocol()));
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status Recv(::grpc::ServerContext *context,
                      const ::posix_server::RecvRequest *request,
                      ::posix_server::RecvResponse *response) override {
    std::vector<char> buf(request->len());
    response->set_ret(
        recv(request->sockfd(), buf.data(), buf.size(), request->flags()));
    if (response->ret() >= 0) {
      response->set_buf(buf.data(), response->ret());
    }
    response->set_errno_(errno);
    return ::grpc::Status::OK;
  }

  ::grpc::Status RecvMsg(::grpc::ServerContext *context,
                         const ::posix_server::RecvMsgRequest *request,
                         ::posix_server::RecvMsgResponse *response) override {
    sockaddr_storage addr;
    std::vector<struct iovec> iov(request->iovlen_size());
    std::vector<std::vector<char>> buffers(request->iovlen_size());
    for (int i = 0; i < request->iovlen_size(); i++) {
      buffers[i].resize(request->iovlen(i));
      iov[i].iov_base = buffers[i].data();
      iov[i].iov_len = buffers[i].size();
    }
    std::vector<char> control(request->controllen());
    struct msghdr msg;
    msg.msg_name = reinterpret_cast<sockaddr *>(&addr);
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = iov.data();
    msg.msg_iovlen = iov.size();
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();
    msg.msg_flags = 0;

    response->set_ret(::recvmsg(request->sockfd(), &msg, request->flags()));
    response->set_errno_(errno);
    int ret = response->ret();
    if (ret >= 0) {
      for (auto it = buffers.begin(); it != buffers.end(); ++it) {
        response->mutable_msg()->add_iov(it->data(),
                                         std::min((size_t)ret, it->size()));
        if (ret > it->size()) {
          ret -= it->size();
        } else {
          break;
        }
      }
    }
    cmsg_to_proto(msg, response->mutable_msg());
    response->mutable_msg()->set_flags(msg.msg_flags);
    return sockaddr_to_proto(addr, msg.msg_namelen,
                             response->mutable_msg()->mutable_name());
  }
};

// Parse command line options. Returns a pointer to the first argument beyond
// the options.
void parse_command_line_options(int argc, char *argv[], std::string *ip,
                                int *port) {
  static struct option options[] = {{"ip", required_argument, NULL, 1},
                                    {"port", required_argument, NULL, 2},
                                    {0, 0, 0, 0}};

  // Parse the arguments.
  int c;
  while ((c = getopt_long(argc, argv, "", options, NULL)) > 0) {
    if (c == 1) {
      *ip = optarg;
    } else if (c == 2) {
      *port = std::stoi(std::string(optarg));
    }
  }
}

void run_server(const std::string &ip, int port) {
  PosixImpl posix_service;
  grpc::ServerBuilder builder;
  std::string server_address = ip + ":" + std::to_string(port);
  // Set the authentication mechanism.
  std::shared_ptr<grpc::ServerCredentials> creds =
      grpc::InsecureServerCredentials();
  builder.AddListeningPort(server_address, creds);
  builder.RegisterService(&posix_service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  std::cerr << "Server listening on " << server_address << std::endl;
  server->Wait();
  std::cerr << "posix_server is finished." << std::endl;
}

int main(int argc, char *argv[]) {
  std::cerr << "posix_server is starting." << std::endl;
  std::string ip;
  int port;
  parse_command_line_options(argc, argv, &ip, &port);

  std::cerr << "Got IP " << ip << " and port " << port << "." << std::endl;
  run_server(ip, port);
}
