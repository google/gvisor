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

#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <unordered_map>

#include "arpa/inet.h"
#include "jsoncpp/json/reader.h"
#include "jsoncpp/json/value.h"

// Bind to the ip and port and return the socket address.  Return -1 on failure.
int bind_server(const std::string &ip, int port) {
  const char *hostname = nullptr;
  if (!ip.empty()) {
    hostname = ip.c_str();
  }
  const char *portname = std::to_string(port).c_str();
  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;
  addrinfo *result;
  int err = getaddrinfo(hostname, portname, &hints, &result);
  if (err != 0) {
    perror("getaddrinfo");
    return -1;
  }

  for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
    int sfd = socket(rp->ai_family, rp->ai_socktype, 0);
    if (sfd == -1) {
      continue;
    }

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
      freeaddrinfo(result);
      return sfd;
    }
    close(sfd);
  }
  perror("Couldn't bind");
  freeaddrinfo(result);
  return -1;
}

Json::Value to_exception(const std::string &what, int err, int errno1) {
  Json::Value exc;
  exc["exception"] = what;
  exc["err"] = err;
  exc["errno"] = errno1;
  return exc;
}

Json::Value process_bind(const Json::Value &command) {
  auto args = command["args"];
  const char *hostname = nullptr;
  if (!args[1][0].asString().empty()) {
    hostname = args[1][0].asString().c_str();
  }
  const char *port = nullptr;
  if (args[1][1].isInt()) {
    port = std::to_string(args[1][1].asInt()).c_str();
  } else if (args[1][1].isString()) {
    port = args[1][1].asString().c_str();
  }
  addrinfo *result;
  int err = getaddrinfo(hostname, port, nullptr, &result);
  if (err != 0) {
    return to_exception("getaddrinfo", err, errno);
  }

  int s = args[0].asInt();
  for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
    if ((err = bind(s, rp->ai_addr, rp->ai_addrlen)) == 0) {
      freeaddrinfo(result);
      return Json::Value();
    }
  }
  freeaddrinfo(result);
  return to_exception("bind", err, errno);
}

Json::Value process_socket(const Json::Value &command) {
  auto args = command["args"];
  int s = socket(args[0].asInt(), args[1].asInt(), args[2].asInt());
  if (s < 0) {
    return to_exception("socket", s, errno);
  }
  Json::Value result;
  result["return"] = s;
  return result;
}

// Returns an array with two elements: [ip_string, port].
Json::Value sockaddr_to_ip_port(const sockaddr_storage &addr,
                                socklen_t addrlen) {
  Json::Value response;
  if (addr.ss_family == AF_INET) {
    char buf[100];
    const char *result =
        inet_ntop(addr.ss_family,
                  &((reinterpret_cast<const sockaddr_in *>(&addr))->sin_addr),
                  buf, sizeof(buf));
    if (result == nullptr) {
      return to_exception("inet_ntop", 0, errno);
    }
    response[0] = std::string(result);
    auto addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
    response[1] = ntohs(addr_in->sin_port);
  }
  if (addr.ss_family == AF_INET6) {
    char buf[100];
    const char *result =
        inet_ntop(addr.ss_family,
                  &((reinterpret_cast<const sockaddr_in6 *>(&addr))->sin6_addr),
                  buf, sizeof(buf));
    if (result == nullptr) {
      return to_exception("inet_ntop", 0, errno);
    }
    response[0] = std::string(result);
    auto addr_in6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
    response[1] = ntohs(addr_in6->sin6_port);
  }
  return response;
}

Json::Value process_getsockname(const Json::Value &command) {
  auto args = command["args"];
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  int err = getsockname(args[0].asInt(), reinterpret_cast<sockaddr *>(&addr),
                        &addrlen);
  if (err != 0) {
    return to_exception("getsockname", err, errno);
  }
  Json::Value response;
  response["return"] = sockaddr_to_ip_port(addr, addrlen);
  return response;
}

Json::Value process_listen(const Json::Value &command) {
  auto args = command["args"];
  auto err = listen(args[0].asInt(), args[1].asInt());
  if (err != 0) {
    return to_exception("listen", err, errno);
  }
  return Json::Value();
}

Json::Value process_accept(const Json::Value &command) {
  auto args = command["args"];
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  auto err =
      accept(args[0].asInt(), reinterpret_cast<sockaddr *>(&addr), &addrlen);
  if (err < 0) {
    return to_exception("accept", err, errno);
  }
  Json::Value response;
  response["return"][0] = err;
  response["return"][1] = sockaddr_to_ip_port(addr, addrlen);
  return response;
}

Json::Value process_setsockopt(const Json::Value &command) {
  auto args = command["args"];
  int err;
  if (args[3].isInt()) {
    int opt_val = args[3].asInt();
    err = setsockopt(args[0].asInt(), args[1].asInt(), args[2].asInt(),
                     &opt_val, 4);
  } else {
    // We must not use strlen on the string because it may have nulls embedded.
    err = setsockopt(args[0].asInt(), args[1].asInt(), args[2].asInt(),
                     args[3].asString().c_str(), args[3].asString().size());
  }
  if (err == 0) {
    return Json::Value();
  }
  return to_exception("setsockopt", err, errno);
}

Json::Value process_close(const Json::Value &command) {
  auto args = command["args"];
  int err = close(args[0].asInt());
  if (err != 0) {
    return to_exception("close", err, errno);
  }
  return Json::Value();
}

using Command = Json::Value (*)(const Json::Value &);

static std::unordered_map<std::string, Command> *commands =
    new std::unordered_map<std::string, Command>({
        {"socket", &process_socket},
        {"bind", &process_bind},
        {"getsockname", &process_getsockname},
        {"listen", &process_listen},
        {"accept", &process_accept},
        {"setsockopt", &process_setsockopt},
        {"close", &process_close},
    });

std::string process_command(const std::string &json_command_text) {
  Json::Reader reader;
  Json::Value json_command;
  if (reader.parse(json_command_text, json_command, false)) {
    auto command = commands->at(json_command["command"].asString());
    if (command == nullptr) {
      return to_exception(
                 "Command not found: " + json_command["command"].asString(), 0,
                 0)
          .toStyledString();
    }
    auto json_response = (command)(json_command);
    return json_response.toStyledString();
  }
  return to_exception("Can't parse command " + json_command_text, 0, 0)
      .toStyledString();
}

/* Parse command line options. Returns a pointer to the first argument
 * beyond the options.
 */
void parse_command_line_options(int argc, char *argv[], std::string *ip,
                                int *port) {
  static struct option options[] = {{"ip", required_argument, NULL, 1},
                                    {"port", required_argument, NULL, 2},
                                    {0, 0, 0, 0}};

  /* Parse the arguments. */
  int c;
  while ((c = getopt_long(argc, argv, "vD:", options, NULL)) > 0) {
    if (c == 1) {
      *ip = optarg;
    } else if (c == 2) {
      *port = std::stoi(std::string(optarg));
    }
  }
  return;
}
int main(int argc, char *argv[]) {
  printf("Stub is starting.\n");
  std::string ip;
  int port;
  parse_command_line_options(argc, argv, &ip, &port);

  printf("got ip %s and port %d\n", ip.c_str(), port);
  int sfd = bind_server(ip, port);
  for (;;) {
    const size_t buf_size = 1024;
    char buf[buf_size];
    sockaddr_storage peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    int nread = recvfrom(sfd, buf, buf_size, 0,
                         reinterpret_cast<struct sockaddr *>(&peer_addr),
                         &peer_addr_len);
    if (nread == -1) {
      /* Ignore failed request */
      continue;
    }

    std::string result = process_command(std::string(buf, nread));

    if (sendto(sfd, result.c_str(), result.size(), 0,
               reinterpret_cast<struct sockaddr *>(&peer_addr),
               peer_addr_len) != nread) {
      fprintf(stderr, "Error sending response\n");
    }
  }
}
