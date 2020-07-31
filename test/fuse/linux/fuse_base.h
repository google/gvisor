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

#ifndef GVISOR_TEST_FUSE_FUSE_BASE_H_
#define GVISOR_TEST_FUSE_FUSE_BASE_H_

#include <linux/fuse.h>
#include <sys/uio.h>

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

constexpr char kMountPoint[] = "/mnt";
constexpr char kMountOpts[] = "rootmode=755,user_id=0,group_id=0";

// Internal commands used to communicate between testing thread and the FUSE
// server. See test/fuse/README.md for further detail.
enum FuseTestCmd {
  kSetResponse = 0,
  kGetSuccess,
  kGetRequest,
  kGetTotalReceivedBytes,
  kGetTotalSentBytes,
};

// Holds the information of a memory block in a serial buffer.
struct FuseMemBlock {
  uint32_t opcode;
  size_t offset;
  size_t len;
};

// A wrapper of a simple serial buffer that can be used with read(2) and
// write(2). Contains a cursor to indicate accessing.
class FuseMemBlocks {
 public:
  FuseMemBlocks() : cursor(0) {
    // To read from /dev/fuse, a buffer needs at least FUSE_MIN_READ_BUFFER
    // bytes to avoid EINVAL. FuseMemBlocks holds memory that can accommodate
    // a sequence of FUSE request/response, so it is initiated with double
    // minimal requirement.
    mem.resize(FUSE_MIN_READ_BUFFER * 2);
  }

  // Returns whether there is no memory block.
  bool Empty() { return blocks.empty(); }

  // Returns if there is no more remaining memory blocks.
  bool End() { return cursor == blocks.size(); }

  // Returns how many bytes that have been received.
  size_t UsedBytes() {
    return Empty() ? 0 : blocks.back().offset + blocks.back().len;
  }

  // Returns the available bytes remains in the serial buffer.
  size_t AvailBytes() { return mem.size() - UsedBytes(); }

  // Appends a memory block information that starts at the tail of the serial
  // buffer.
  void AddMemBlock(uint32_t opcode, size_t len) {
    blocks.push_back(FuseMemBlock{opcode, UsedBytes(), len});
  }

  // Returns the memory address at a specific offset. Used with read(2) or
  // write(2).
  char* DataAtOffset(size_t offset) { return mem.data() + offset; }

  // Returns the memory address at the tail of the serial buffer. Especially
  // used with write(2).
  char* DataAtTail() { return mem.data() + UsedBytes(); }

  // Returns current memory block pointed by the cursor and increase by 1.
  FuseMemBlock Next() { return blocks[cursor++]; }

 private:
  std::vector<FuseMemBlock> blocks;
  std::vector<char> mem;
  size_t cursor;
};

class FuseTest : public ::testing::Test {
 public:
  void SetUp() override;
  void TearDown() override;

  // Called by the testing thread to set up a fake response for an expected
  // opcode via socket. This can be used multiple times to define a sequence of
  // expected FUSE reactions.
  void SetServerResponse(uint32_t opcode, struct iovec* iov_out,
                         int iov_out_cnt);

  // Called by the testing thread to ensure every server EXPECTs or ASSERTs are
  // successful.
  void EnsureServerSuccess();

  // Called by the testing thread to ask the FUSE server for its next received
  // FUSE request. Be sure to use the corresponding struct of iovec to receive
  // data from server.
  void GetServerActualRequest(struct iovec* iov_in, int iov_in_cnt);

  // Called by the testing thread to ask the FUSE server for its total received
  // bytes from /dev/fuse.
  uint32_t GetServerTotalReceivedBytes();

 private:
  // Opens /dev/fuse and inherit the file descriptor for the FUSE server.
  void MountFuse();

  // Unmounts the mountpoint of the FUSE server.
  void UnmountFuse();

  // Creates a socketpair for communication and forks FUSE server.
  void SetUpFuseServer();

  // The FUSE server stays here and waits next command or FUSE request until it
  // is terminated.
  void ServerFuseLoop();

  // Used by the FUSE server to tell testing thread if it is OK to proceed next
  // command. Will be issued after processing each FuseTestCmd.
  void ServerCompleteWith(bool success);

  // Consumes the first FUSE request when mounting FUSE. Replies with a
  // response with empty payload.
  PosixError ServerConsumeFuseInit();

  // A command switch that dispatch different FuseTestCmd to its handler.
  void ServerHandleCommand();

  // The FUSE server side's corresponding code of `SetServerResponse()`.
  // Handles `kSetResponse` command. Saves the fake response into its output
  // memory queue.
  void ServerReceiveResponse();

  // The FUSE server side's corresponding code of `GetServerActualRequest()`.
  // Handles `kGetRequest` command. Sends the next received request pointed by
  // the cursor.
  void ServerSendReceivedRequest();

  // The FUSE server side's corresponding code of `EnsureServerSuccess()`.
  // Handles `kGetSuccess` command. Sends the overall success status counted by
  // gTest library.
  void ServerSendSuccess();

  // The FUSE server side's corresponding code of
  // `GetServerTotalReceivedBytes()`. Handles `kGetTotalReceivedBytes` command.
  // Sends the total bytes received from /dev/fuse by the FUSE server.
  void ServerSendTotalReceivedBytes();

  // Handles FUSE request sent to /dev/fuse by its saved responses.
  void ServerProcessFUSERequest();

  // Sends an error response when bad thing happens.
  void ServerSendErrorResponse(uint64_t unique);

  // Waits for FUSE server to complete its processing. Complains if the FUSE
  // server responds any failure during tests.
  void WaitServerComplete();

  int dev_fd_;
  int sock_[2];

  FuseMemBlocks requests_;
  FuseMemBlocks responses_;
};

}  // namespace testing
}  // namespace gvisor

#define SET_IOVEC_WITH_HEADER_PAYLOAD(iov, header, payload) \
  do {                                                      \
    iov[0].iov_len = sizeof(header);                        \
    iov[0].iov_base = &header;                              \
    iov[1].iov_len = sizeof(payload);                       \
    iov[1].iov_base = &payload;                             \
  } while (0)

#define SET_IOVEC_WITH_HEADER(iov, header) \
  do {                                     \
    iov[0].iov_len = sizeof(header);       \
    iov[0].iov_base = &header;             \
  } while (0)

#endif  // GVISOR_TEST_FUSE_FUSE_BASE_H_
