// Copyright 2022 The gVisor Authors.
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

#include <err.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "test/util/file_descriptor.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

void runForkExecve() {
  auto root_or_error = Open("/", O_RDONLY, 0);
  auto& root = root_or_error.ValueOrDie();

  pid_t child;
  int execve_errno;
  ExecveArray argv = {"/bin/true"};
  ExecveArray envv = {"TEST=123"};
  auto kill_or_error = ForkAndExecveat(root.get(), "/bin/true", argv, envv, 0,
                                       nullptr, &child, &execve_errno);
  ASSERT_EQ(0, execve_errno);

  // Don't kill child, just wait for gracefully exit.
  kill_or_error.ValueOrDie().Release();
  RetryEINTR(waitpid)(child, nullptr, 0);
}

// Creates a simple UDS in the abstract namespace and send one byte from the
// client to the server.
void runSocket() {
  auto path = absl::StrCat(std::string("\0", 1), "trace_test.", getpid(),
                           absl::GetCurrentTimeNanos());

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path.c_str(), path.size() + 1);

  int parent_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (parent_sock < 0) {
    err(1, "socket");
  }
  auto sock_closer = absl::MakeCleanup([parent_sock] { close(parent_sock); });

  if (bind(parent_sock, reinterpret_cast<struct sockaddr*>(&addr),
           sizeof(addr))) {
    err(1, "bind");
  }
  if (listen(parent_sock, 5) < 0) {
    err(1, "listen");
  }

  pid_t pid = fork();
  if (pid < 0) {
    // Fork error.
    err(1, "fork");

  } else if (pid == 0) {
    // Child.
    close(parent_sock);  // ensure it's not mistakely used in child.

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
      err(1, "socket");
    }
    auto server_closer = absl::MakeCleanup([server] { close(server); });

    if (connect(server, reinterpret_cast<struct sockaddr*>(&addr),
                sizeof(addr)) < 0) {
      err(1, "connect");
    }

    char buf = 'A';
    int bytes = write(server, &buf, sizeof(buf));
    if (bytes != 1) {
      err(1, "write: %d", bytes);
    }
    exit(0);

  } else {
    // Parent.
    int client = RetryEINTR(accept)(parent_sock, nullptr, nullptr);
    if (client < 0) {
      err(1, "accept");
    }
    auto client_closer = absl::MakeCleanup([client] { close(client); });

    char buf;
    int bytes = read(client, &buf, sizeof(buf));
    if (bytes != 1) {
      err(1, "read: %d", bytes);
    }

    // Wait to reap the child.
    RetryEINTR(waitpid)(pid, nullptr, 0);
  }
}

}  // namespace testing
}  // namespace gvisor

int main(int argc, char** argv) {
  ::gvisor::testing::runForkExecve();
  ::gvisor::testing::runSocket();

  return 0;
}
