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
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <unordered_map>

#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "absl/strings/str_format.h"
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
      // sin6_scope_id is stored in host byte order.
      //
      // https://www.gnu.org/software/libc/manual/html_node/Internet-Address-Formats.html
      response_in6->set_scope_id(addr_in6->sin6_scope_id);
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
      // sin6_scope_id is stored in host byte order.
      //
      // https://www.gnu.org/software/libc/manual/html_node/Internet-Address-Formats.html
      addr_in6->sin6_scope_id = proto_in6.scope_id();
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

class PosixImpl final : public posix_server::Posix::Service {
  ::grpc::Status Accept(grpc::ServerContext *context,
                        const ::posix_server::AcceptRequest *request,
                        ::posix_server::AcceptResponse *response) override {
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    response->set_fd(accept(request->sockfd(),
                            reinterpret_cast<sockaddr *>(&addr), &addrlen));
    if (response->fd() < 0) {
      response->set_errno_(errno);
    }
    return sockaddr_to_proto(addr, addrlen, response->mutable_addr());
  }

  ::grpc::Status Bind(grpc::ServerContext *context,
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
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Close(grpc::ServerContext *context,
                       const ::posix_server::CloseRequest *request,
                       ::posix_server::CloseResponse *response) override {
    response->set_ret(close(request->fd()));
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Connect(grpc::ServerContext *context,
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
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status GetSockName(
      grpc::ServerContext *context,
      const ::posix_server::GetSockNameRequest *request,
      ::posix_server::GetSockNameResponse *response) override {
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    response->set_ret(getsockname(
        request->sockfd(), reinterpret_cast<sockaddr *>(&addr), &addrlen));
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return sockaddr_to_proto(addr, addrlen, response->mutable_addr());
  }

  ::grpc::Status GetSockOpt(
      grpc::ServerContext *context,
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
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Listen(grpc::ServerContext *context,
                        const ::posix_server::ListenRequest *request,
                        ::posix_server::ListenResponse *response) override {
    response->set_ret(listen(request->sockfd(), request->backlog()));
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Poll(::grpc::ServerContext *context,
                      const ::posix_server::PollRequest *request,
                      ::posix_server::PollResponse *response) override {
    std::vector<struct pollfd> pfds;
    pfds.reserve(request->pfds_size());
    for (const auto &pfd : request->pfds()) {
      pfds.push_back({
          .fd = pfd.fd(),
          .events = static_cast<short>(pfd.events()),
      });
    }
    int ret = ::poll(pfds.data(), pfds.size(), request->timeout_millis());

    response->set_ret(ret);
    if (ret < 0) {
      response->set_errno_(errno);
    } else {
      // Only pollfds that have non-empty revents are returned, the client can't
      // rely on indexes of the request array.
      for (const auto &pfd : pfds) {
        if (pfd.revents) {
          auto *proto_pfd = response->add_pfds();
          proto_pfd->set_fd(pfd.fd);
          proto_pfd->set_events(pfd.revents);
        }
      }
      if (int ready = response->pfds_size(); ret != ready) {
        return ::grpc::Status(
            ::grpc::StatusCode::INTERNAL,
            absl::StrFormat(
                "poll's return value(%d) doesn't match the number of "
                "file descriptors that are actually ready(%d)",
                ret, ready));
      }
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Send(::grpc::ServerContext *context,
                      const ::posix_server::SendRequest *request,
                      ::posix_server::SendResponse *response) override {
    response->set_ret(::send(request->sockfd(), request->buf().data(),
                             request->buf().size(), request->flags()));
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
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
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetNonblocking(
      grpc::ServerContext *context,
      const ::posix_server::SetNonblockingRequest *request,
      ::posix_server::SetNonblockingResponse *response) override {
    int flags = fcntl(request->fd(), F_GETFL);
    if (flags == -1) {
      response->set_ret(-1);
      response->set_errno_(errno);
      response->set_cmd("F_GETFL");
      return ::grpc::Status::OK;
    }
    if (request->nonblocking()) {
      flags |= O_NONBLOCK;
    } else {
      flags &= ~O_NONBLOCK;
    }
    int ret = fcntl(request->fd(), F_SETFL, flags);
    response->set_ret(ret);
    if (ret == -1) {
      response->set_errno_(errno);
      response->set_cmd("F_SETFL");
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetSockOpt(
      grpc::ServerContext *context,
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
        timeval tv = {.tv_sec = static_cast<time_t>(
                          request->optval().timeval().seconds()),
                      .tv_usec = static_cast<suseconds_t>(
                          request->optval().timeval().microseconds())};
        response->set_ret(setsockopt(request->sockfd(), request->level(),
                                     request->optname(), &tv, sizeof(tv)));
        break;
      }
      default:
        return ::grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                              "Unknown SockOpt Type");
    }
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Socket(grpc::ServerContext *context,
                        const ::posix_server::SocketRequest *request,
                        ::posix_server::SocketResponse *response) override {
    response->set_fd(
        socket(request->domain(), request->type(), request->protocol()));
    if (response->fd() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status Shutdown(grpc::ServerContext *context,
                          const ::posix_server::ShutdownRequest *request,
                          ::posix_server::ShutdownResponse *response) override {
    if (shutdown(request->fd(), request->how()) < 0) {
      response->set_errno_(errno);
    }
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
    if (response->ret() < 0) {
      response->set_errno_(errno);
    }
    return ::grpc::Status::OK;
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
