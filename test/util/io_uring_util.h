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

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <atomic>
#include <cerrno>
#include <cstdint>

#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"

namespace gvisor {
namespace testing {

#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426

// io_uring_setup(2) flags.
#define IORING_SETUP_SQPOLL (1U << 1)
#define IORING_SETUP_CQSIZE (1U << 3)

// io_uring_enter(2) flags
#define IORING_ENTER_GETEVENTS (1U << 0)

#define IORING_FEAT_SINGLE_MMAP (1U << 0)

#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL

// IO_URING operation codes.
#define IORING_OP_NOP 0
#define IORING_OP_READV 1

#define BLOCK_SZ kPageSize

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

struct io_uring_cqe {
  uint64_t user_data;
  int32_t res;
  uint32_t flags;
};

struct io_uring_sqe {
  uint8_t opcode;
  uint8_t flags;
  uint16_t ioprio;
  int32_t fd;
  union {
    uint64_t off;
    uint64_t addr2;
    struct {
      uint32_t cmd_op;
      uint32_t __pad1;
    };
  };
  union {
    uint64_t addr;
    uint64_t splice_off_in;
  };
  uint32_t len;
  union {
    __kernel_rwf_t rw_flags;
    uint32_t fsync_flags;
    uint16_t poll_events;
    uint32_t poll32_events;
    uint32_t sync_range_flags;
    uint32_t msg_flags;
    uint32_t timeout_flags;
    uint32_t accept_flags;
    uint32_t cancel_flags;
    uint32_t open_flags;
    uint32_t statx_flags;
    uint32_t fadvise_advice;
    uint32_t splice_flags;
    uint32_t rename_flags;
    uint32_t unlink_flags;
    uint32_t hardlink_flags;
    uint32_t xattr_flags;
  };
  uint64_t user_data;
  union {
    uint16_t buf_index;
    uint16_t buf_group;
  } __attribute__((packed));
  uint16_t personality;
  union {
    int32_t splice_fd_in;
    uint32_t file_index;
  };
  union {
    struct {
      uint64_t addr3;
      uint64_t __pad2[1];
    };
    uint8_t cmd[0];
  };
};

using IOSqringOffsets = struct io_sqring_offsets;
using ICqringOffsets = struct io_cqring_offsets;
using IOUringCqe = struct io_uring_cqe;
using IOUringParams = struct io_uring_params;
using IOUringSqe = struct io_uring_sqe;

// Helper class for IO_URING
class IOUring {
 public:
  IOUring() = delete;
  IOUring(FileDescriptor &&fd, unsigned int entries, IOUringParams &params);
  ~IOUring();

  static PosixErrorOr<std::unique_ptr<IOUring>> InitIOUring(
      unsigned int entries, IOUringParams &params);

  uint32_t load_cq_head();
  uint32_t load_cq_tail();
  uint32_t load_sq_head();
  uint32_t load_sq_tail();
  uint32_t load_cq_overflow();
  uint32_t load_sq_dropped();
  void store_cq_head(uint32_t cq_head_val);
  void store_sq_tail(uint32_t sq_tail_val);
  int Enter(unsigned int to_submit, unsigned int min_complete,
            unsigned int flags, sigset_t *sig);

  IOUringCqe *get_cqes();
  IOUringSqe *get_sqes();
  uint32_t get_sq_mask();
  unsigned *get_sq_array();

  int Fd() { return iouringfd_.get(); }

 private:
  IOUringCqe *cqes_ = nullptr;
  FileDescriptor iouringfd_;
  size_t cring_sz_;
  size_t sring_sz_;
  size_t sqes_sz_;
  uint32_t sq_mask_;
  unsigned *sq_array_ = nullptr;
  uint32_t *cq_head_ptr_ = nullptr;
  uint32_t *cq_tail_ptr_ = nullptr;
  uint32_t *sq_head_ptr_ = nullptr;
  uint32_t *sq_tail_ptr_ = nullptr;
  uint32_t *cq_overflow_ptr_ = nullptr;
  uint32_t *sq_dropped_ptr_ = nullptr;
  void *sq_ptr_ = nullptr;
  void *cq_ptr_ = nullptr;
  void *sqe_ptr_ = nullptr;
};

// This is a wrapper for the io_uring_setup(2) system call.
inline int IOUringSetup(uint32_t entries, IOUringParams *params) {
  return syscall(__NR_io_uring_setup, entries, params);
}

// This is a wrapper for the io_uring_enter(2) system call.
inline int IOUringEnter(unsigned int fd, unsigned int to_submit,
                        unsigned int min_complete, unsigned int flags,
                        sigset_t *sig) {
  return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig);
}

// Returns a new iouringfd with the given number of entries.
inline PosixErrorOr<FileDescriptor> NewIOUringFD(uint32_t entries,
                                                 IOUringParams &params) {
  memset(&params, 0, sizeof(params));
  int fd = IOUringSetup(entries, &params);
  MaybeSave();
  if (fd < 0) {
    return PosixError(errno, "io_uring_setup");
  }
  return FileDescriptor(fd);
}

template <typename T>
static inline void io_uring_atomic_write(T *p, T v) {
  std::atomic_store_explicit(reinterpret_cast<std::atomic<T> *>(p), v,
                             std::memory_order_release);
}

template <typename T>
static inline T io_uring_atomic_read(const T *p) {
  return std::atomic_load_explicit(reinterpret_cast<const std::atomic<T> *>(p),
                                   std::memory_order_acquire);
}

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_UTIL_IOURING_UTIL_H_
