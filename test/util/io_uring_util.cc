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

#include "test/util/io_uring_util.h"

#include <memory>

namespace gvisor {
namespace testing {

PosixErrorOr<std::unique_ptr<IOUring>> IOUring::InitIOUring(
    unsigned int entries, IOUringParams &params) {
  PosixErrorOr<FileDescriptor> fd = NewIOUringFD(entries, params);
  if (!fd.ok()) {
    return fd.error();
  }

  return std::make_unique<IOUring>(std::move(fd.ValueOrDie()), entries, params);
}

IOUring::IOUring(FileDescriptor &&fd, unsigned int entries,
                 IOUringParams &params)
    : iouringfd_(std::move(fd)) {
  cring_sz_ = params.cq_off.cqes + params.cq_entries * sizeof(IOUringCqe);
  sring_sz_ = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  sqes_sz_ = params.sq_entries * sizeof(IOUringSqe);

  cq_ptr_ =
      mmap(0, cring_sz_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd_.get(), IORING_OFF_SQ_RING);
  sq_ptr_ =
      mmap(0, sring_sz_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd_.get(), IORING_OFF_SQ_RING);
  sqe_ptr_ = mmap(0, sqes_sz_, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, iouringfd_.get(), IORING_OFF_SQES);

  cqes_ = reinterpret_cast<IOUringCqe *>(reinterpret_cast<char *>(cq_ptr_) +
                                         params.cq_off.cqes);

  cq_head_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(cq_ptr_) + params.cq_off.head);
  cq_tail_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(cq_ptr_) + params.cq_off.tail);
  sq_head_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(sq_ptr_) + params.sq_off.head);
  sq_tail_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(sq_ptr_) + params.sq_off.tail);
  cq_overflow_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(cq_ptr_) + params.cq_off.overflow);
  sq_dropped_ptr_ = reinterpret_cast<uint32_t *>(
      reinterpret_cast<char *>(sq_ptr_) + params.sq_off.dropped);

  sq_mask_ = *(reinterpret_cast<uint32_t *>(reinterpret_cast<char *>(sq_ptr_) +
                                            params.sq_off.ring_mask));
  sq_array_ = reinterpret_cast<unsigned *>(reinterpret_cast<char *>(sq_ptr_) +
                                           params.sq_off.array);
}

IOUring::~IOUring() {
  munmap(cq_ptr_, cring_sz_);
  munmap(sq_ptr_, sring_sz_);
  munmap(sqe_ptr_, sqes_sz_);
}

uint32_t IOUring::load_cq_head() { return io_uring_atomic_read(cq_head_ptr_); }

uint32_t IOUring::load_cq_tail() { return io_uring_atomic_read(cq_tail_ptr_); }

uint32_t IOUring::load_sq_head() { return io_uring_atomic_read(sq_head_ptr_); }

uint32_t IOUring::load_sq_tail() { return io_uring_atomic_read(sq_tail_ptr_); }

uint32_t IOUring::load_cq_overflow() {
  return io_uring_atomic_read(cq_overflow_ptr_);
}

uint32_t IOUring::load_sq_dropped() {
  return io_uring_atomic_read(sq_dropped_ptr_);
}

void IOUring::store_cq_head(uint32_t cq_head_val) {
  io_uring_atomic_write(cq_head_ptr_, cq_head_val);
}

void IOUring::store_sq_tail(uint32_t sq_tail_val) {
  io_uring_atomic_write(sq_tail_ptr_, sq_tail_val);
}

int IOUring::Enter(unsigned int to_submit, unsigned int min_complete,
                   unsigned int flags, sigset_t *sig) {
  return IOUringEnter(iouringfd_.get(), to_submit, min_complete, flags, sig);
}

IOUringCqe *IOUring::get_cqes() { return cqes_; }

IOUringSqe *IOUring::get_sqes() {
  return reinterpret_cast<IOUringSqe *>(sqe_ptr_);
}

uint32_t IOUring::get_sq_mask() { return sq_mask_; }

unsigned *IOUring::get_sq_array() { return sq_array_; }

}  // namespace testing
}  // namespace gvisor
