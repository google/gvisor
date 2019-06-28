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

#ifndef GVISOR_TEST_SYSCALLS_READV_COMMON_H_
#define GVISOR_TEST_SYSCALLS_READV_COMMON_H_

#include <stddef.h>

namespace gvisor {
namespace testing {

// A NUL-terminated string containing the data used by tests using the following
// test helpers.
extern const char kReadvTestData[];

// The size of kReadvTestData, including the terminating NUL.
extern const size_t kReadvTestDataSize;

// ReadAllOneBuffer asserts that it can read kReadvTestData from an fd using
// exactly one iovec.
void ReadAllOneBuffer(int fd);

// ReadAllOneLargeBuffer asserts that it can read kReadvTestData from an fd
// using exactly one iovec containing an overly large buffer.
void ReadAllOneLargeBuffer(int fd);

// ReadOneHalfAtATime asserts that it can read test_data_from an fd using
// exactly two iovecs that are roughly equivalent in size.
void ReadOneHalfAtATime(int fd);

// ReadOneBufferPerByte asserts that it can read kReadvTestData from an fd
// using one iovec per byte.
void ReadOneBufferPerByte(int fd);

// ReadBuffersOverlapping asserts that it can read kReadvTestData from an fd
// where two iovecs are overlapping.
void ReadBuffersOverlapping(int fd);

// ReadBuffersDiscontinuous asserts that it can read kReadvTestData from an fd
// where each iovec is discontinuous from the next by 1 byte.
void ReadBuffersDiscontinuous(int fd);

// ReadIovecsCompletelyFilled asserts that the previous iovec is completely
// filled before moving onto the next.
void ReadIovecsCompletelyFilled(int fd);

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_SYSCALLS_READV_COMMON_H_
