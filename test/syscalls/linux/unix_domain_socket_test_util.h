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

#ifndef GVISOR_TEST_SYSCALLS_UNIX_DOMAIN_SOCKET_TEST_UTIL_H_
#define GVISOR_TEST_SYSCALLS_UNIX_DOMAIN_SOCKET_TEST_UTIL_H_

#include <string>

#include "test/util/socket_util.h"

namespace gvisor {
namespace testing {

// DescribeUnixDomainSocketType returns a human-readable string explaining the
// given Unix domain socket type.
std::string DescribeUnixDomainSocketType(int type);

// UnixDomainSocketPair returns a SocketPairKind that represents SocketPairs
// created by invoking the socketpair() syscall with AF_UNIX and the given type.
SocketPairKind UnixDomainSocketPair(int type);

// FilesystemBoundUnixDomainSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and accept() syscalls with a temp file path,
// AF_UNIX and the given type.
SocketPairKind FilesystemBoundUnixDomainSocketPair(int type);

// AbstractBoundUnixDomainSocketPair returns a SocketPairKind that represents
// SocketPairs created with bind() and accept() syscalls with a temp abstract
// path, AF_UNIX and the given type.
SocketPairKind AbstractBoundUnixDomainSocketPair(int type);

// SocketpairGoferUnixDomainSocketPair returns a SocketPairKind that was created
// with two sockets connected to the socketpair gofer.
SocketPairKind SocketpairGoferUnixDomainSocketPair(int type);

// SocketpairGoferFileSocketPair returns a SocketPairKind that was created with
// two open() calls on paths backed by the socketpair gofer.
SocketPairKind SocketpairGoferFileSocketPair(int type);

// FilesystemUnboundUnixDomainSocketPair returns a SocketPairKind that
// represents two unbound sockets and a filesystem path for binding.
SocketPairKind FilesystemUnboundUnixDomainSocketPair(int type);

// AbstractUnboundUnixDomainSocketPair returns a SocketPairKind that represents
// two unbound sockets and an abstract namespace path for binding.
SocketPairKind AbstractUnboundUnixDomainSocketPair(int type);

// SendSingleFD sends both a single FD and some data over a unix domain socket
// specified by an FD. Note that calls to this function must be wrapped in
// ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void SendSingleFD(int sock, int fd, char buf[], int buf_size);

// SendFDs sends an arbitrary number of FDs and some data over a unix domain
// socket specified by an FD. Note that calls to this function must be wrapped
// in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void SendFDs(int sock, int fds[], int fds_size, char buf[], int buf_size);

// RecvSingleFD receives both a single FD and some data over a unix domain
// socket specified by an FD. Note that calls to this function must be wrapped
// in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void RecvSingleFD(int sock, int* fd, char buf[], int buf_size);

// RecvSingleFD receives both a single FD and some data over a unix domain
// socket specified by an FD. This version allows the expected amount of data
// received to be different than the buffer size. Note that calls to this
// function must be wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions
// to halt the test.
void RecvSingleFD(int sock, int* fd, char buf[], int buf_size,
                  int expected_size);

// PeekSingleFD peeks at both a single FD and some data over a unix domain
// socket specified by an FD. Note that calls to this function must be wrapped
// in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void PeekSingleFD(int sock, int* fd, char buf[], int buf_size);

// RecvFDs receives both an arbitrary number of FDs and some data over a unix
// domain socket specified by an FD. Note that calls to this function must be
// wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void RecvFDs(int sock, int fds[], int fds_size, char buf[], int buf_size);

// RecvFDs receives both an arbitrary number of FDs and some data over a unix
// domain socket specified by an FD. This version allows the expected amount of
// data received to be different than the buffer size. Note that calls to this
// function must be wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions
// to halt the test.
void RecvFDs(int sock, int fds[], int fds_size, char buf[], int buf_size,
             int expected_size);

// RecvNoCmsg receives some data over a unix domain socket specified by an FD
// and asserts that no control messages are available for receiving. Note that
// calls to this function must be wrapped in ASSERT_NO_FATAL_FAILURE for
// internal assertions to halt the test.
void RecvNoCmsg(int sock, char buf[], int buf_size, int expected_size);

inline void RecvNoCmsg(int sock, char buf[], int buf_size) {
  RecvNoCmsg(sock, buf, buf_size, buf_size);
}

// SendCreds sends the credentials of the current process and some data over a
// unix domain socket specified by an FD. Note that calls to this function must
// be wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the
// test.
void SendCreds(int sock, ucred creds, char buf[], int buf_size);

// SendCredsAndFD sends the credentials of the current process, a single FD, and
// some data over a unix domain socket specified by an FD. Note that calls to
// this function must be wrapped in ASSERT_NO_FATAL_FAILURE for internal
// assertions to halt the test.
void SendCredsAndFD(int sock, ucred creds, int fd, char buf[], int buf_size);

// RecvCreds receives some credentials and some data over a unix domain socket
// specified by an FD. Note that calls to this function must be wrapped in
// ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void RecvCreds(int sock, ucred* creds, char buf[], int buf_size);

// RecvCreds receives some credentials and some data over a unix domain socket
// specified by an FD. This version allows the expected amount of data received
// to be different than the buffer size. Note that calls to this function must
// be wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the
// test.
void RecvCreds(int sock, ucred* creds, char buf[], int buf_size,
               int expected_size);

// RecvCredsAndFD receives some credentials, a single FD, and some data over a
// unix domain socket specified by an FD. Note that calls to this function must
// be wrapped in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the
// test.
void RecvCredsAndFD(int sock, ucred* creds, int* fd, char buf[], int buf_size);

// SendNullCmsg sends a null control message and some data over a unix domain
// socket specified by an FD. Note that calls to this function must be wrapped
// in ASSERT_NO_FATAL_FAILURE for internal assertions to halt the test.
void SendNullCmsg(int sock, char buf[], int buf_size);

// RecvSingleFDUnaligned sends both a single FD and some data over a unix domain
// socket specified by an FD. This function does not obey the spec, but Linux
// allows it and the apphosting code depends on this quirk. Note that calls to
// this function must be wrapped in ASSERT_NO_FATAL_FAILURE for internal
// assertions to halt the test.
void RecvSingleFDUnaligned(int sock, int* fd, char buf[], int buf_size);

// SetSoPassCred sets the SO_PASSCRED option on the specified socket.
void SetSoPassCred(int sock);

// UnsetSoPassCred clears the SO_PASSCRED option on the specified socket.
void UnsetSoPassCred(int sock);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_UNIX_DOMAIN_SOCKET_TEST_UTIL_H_
