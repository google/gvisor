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

#ifndef GVISOR_TEST_UTIL_IOURING_UTIL_H_
#define GVISOR_TEST_UTIL_IOURING_UTIL_H_

#include <cerrno>
#include <cstdint>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

#define __NR_io_uring_setup 425

// io_uring_setup(2) flags.
#define IORING_SETUP_SQPOLL (1U << 1)

#define IORING_FEAT_SINGLE_MMAP (1U << 0)

#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL

struct io_sqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t flags;
  uint32_t dropped;
  uint32_t array;
  uint32_t resv1;
  uint64_t resv2;
};

struct io_cqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t overflow;
  uint32_t cqes;
  uint32_t flags;
  uint32_t resv1;
  uint64_t resv2;
};

struct io_uring_params {
  uint32_t sq_entries;
  uint32_t cq_entries;
  uint32_t flags;
  uint32_t sq_thread_cpu;
  uint32_t sq_thread_idle;
  uint32_t features;
  uint32_t wq_fd;
  uint32_t resv[3];
  struct io_sqring_offsets sq_off;
  struct io_cqring_offsets cq_off;
};

// This is a wrapper for the io_uring_setup(2) system call.
inline int IOUringSetup(uint32_t entries, struct io_uring_params* params) {
  return syscall(__NR_io_uring_setup, entries, params);
}

// Returns a new iouringfd with the given number of entries.
inline PosixErrorOr<FileDescriptor> NewIOUringFD(
    uint32_t entries, struct io_uring_params& params) {
  memset(&params, 0, sizeof(params));
  int fd = IOUringSetup(entries, &params);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "io_uring_setup");
  }
  return FileDescriptor(fd);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_IOURING_UTIL_H_
