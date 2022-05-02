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
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <iostream>
#include <unordered_map>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

constexpr char kMountOpts[] = "rootmode=755,user_id=0,group_id=0";

constexpr struct fuse_init_out kDefaultFUSEInitOutPayload = {.major = 7};

// Internal commands used to communicate between testing thread and the FUSE
// server. See test/fuse/README.md for further detail.
enum class FuseTestCmd {
  kSetResponse = 0,
  kSetInodeLookup,
  kGetRequest,
  kGetNumUnconsumedRequests,
  kGetNumUnsentResponses,
  kGetTotalReceivedBytes,
  kSkipRequest,
};

// Holds the information of a memory block in a serial buffer.
struct FuseMemBlock {
  uint32_t opcode;
  size_t offset;
  size_t len;
};

// A wrapper of a simple serial buffer that can be used with read(2) and
// write(2). Contains a cursor to indicate accessing. This class is not thread-
// safe and can only be used in single-thread version.
class FuseMemBuffer {
 public:
  FuseMemBuffer() : cursor_(0) {
    // To read from /dev/fuse, a buffer needs at least FUSE_MIN_READ_BUFFER
    // bytes to avoid EINVAL. FuseMemBuffer holds memory that can accommodate
    // a sequence of FUSE request/response, so it is initiated with double
    // minimal requirement.
    mem_.resize(FUSE_MIN_READ_BUFFER * 2);
  }

  // Returns whether there is no memory block.
  bool Empty() { return blocks_.empty(); }

  // Returns if there is no more remaining memory blocks.
  bool End() { return cursor_ == blocks_.size(); }

  // Returns how many bytes that have been received.
  size_t UsedBytes() {
    return Empty() ? 0 : blocks_.back().offset + blocks_.back().len;
  }

  // Returns the available bytes remains in the serial buffer.
  size_t AvailBytes() { return mem_.size() - UsedBytes(); }

  // Appends a memory block information that starts at the tail of the serial
  // buffer. /dev/fuse requires at least FUSE_MIN_READ_BUFFER bytes to read, or
  // it will issue EINVAL. If it is not enough, just double the buffer length.
  void AddMemBlock(uint32_t opcode, void* data, size_t len) {
    if (AvailBytes() < FUSE_MIN_READ_BUFFER) {
      mem_.resize(mem_.size() << 1);
    }
    size_t offset = UsedBytes();
    memcpy(mem_.data() + offset, data, len);
    blocks_.push_back(FuseMemBlock{opcode, offset, len});
  }

  // Returns the memory address at a specific offset. Used with read(2) or
  // write(2).
  char* DataAtOffset(size_t offset) { return mem_.data() + offset; }

  // Returns current memory block pointed by the cursor and increase by 1.
  FuseMemBlock Next() {
    if (End()) {
      std::cerr << "Buffer is already exhausted." << std::endl;
      return FuseMemBlock{};
    }
    return blocks_[cursor_++];
  }

  // Returns the number of the blocks that has not been requested.
  size_t RemainingBlocks() { return blocks_.size() - cursor_; }

 private:
  size_t cursor_;
  std::vector<FuseMemBlock> blocks_;
  std::vector<char> mem_;
};

// FuseTest base class is useful in FUSE integration test. Inherit this class
// to automatically set up a fake FUSE server and use the member functions
// to manipulate with it. Refer to test/fuse/README.md for detailed explanation.
class FuseTest : public ::testing::Test {
 public:
  // nodeid_ is the ID of a fake inode. We starts from 2 since 1 is occupied by
  // the mount point.
  FuseTest() : nodeid_(2) {}
  void SetUp() override;
  void TearDown() override;

  // Called by the testing thread to set up a fake response for an expected
  // opcode via socket. This can be used multiple times to define a sequence of
  // expected FUSE reactions.
  void SetServerResponse(uint32_t opcode, std::vector<struct iovec>& iovecs);

  // Called by the testing thread to install a fake path under the mount point.
  // e.g. a file under /mnt/dir/file and moint point is /mnt, then it will look
  // up "dir/file" in this case.
  //
  // It sets a fixed response to the FUSE_LOOKUP requests issued with this
  // path, pretending there is an inode and avoid ENOENT when testing. If mode
  // is not given, it creates a regular file with mode 0600.
  void SetServerInodeLookup(const std::string& path,
                            mode_t mode = S_IFREG | S_IRUSR | S_IWUSR,
                            uint64_t size = 512);

  // Called by the testing thread to ask the FUSE server for its next received
  // FUSE request. Be sure to use the corresponding struct of iovec to receive
  // data from server.
  void GetServerActualRequest(std::vector<struct iovec>& iovecs);

  // Called by the testing thread to query the number of unconsumed requests in
  // the requests_ serial buffer of the FUSE server. TearDown() ensures all
  // FUSE requests received by the FUSE server were consumed by the testing
  // thread.
  uint32_t GetServerNumUnconsumedRequests();

  // Called by the testing thread to query the number of unsent responses in
  // the responses_ serial buffer of the FUSE server. TearDown() ensures all
  // preset FUSE responses were sent out by the FUSE server.
  uint32_t GetServerNumUnsentResponses();

  // Called by the testing thread to ask the FUSE server for its total received
  // bytes from /dev/fuse.
  uint32_t GetServerTotalReceivedBytes();

  // Called by the testing thread to ask the FUSE server to skip stored
  // request data.
  void SkipServerActualRequest();

 protected:
  TempPath mount_point_;
  int dev_fd_;

  // Opens /dev/fuse and inherit the file descriptor for the FUSE server.
  void MountFuse(const char* mount_opts = kMountOpts);

  // Mounts a fuse fs with a fuse fd connection at the specified point.
  void MountFuse(int fd, TempPath& mount_point,
                 const char* mount_opts = kMountOpts);

  // Creates a socketpair for communication and forks FUSE server.
  void SetUpFuseServer(
      const struct fuse_init_out* payload = &kDefaultFUSEInitOutPayload);

  // Unmounts the mountpoint of the FUSE server.
  void UnmountFuse();

 private:
  // Sends a FuseTestCmd and gets a uint32_t data from the FUSE server.
  inline uint32_t GetServerData(uint32_t cmd);

  // Waits for FUSE server to complete its processing. Complains if the FUSE
  // server responds any failure during tests.
  void WaitServerComplete();

  // The FUSE server stays here and waits next command or FUSE request until it
  // is terminated.
  void ServerFuseLoop();

  // Used by the FUSE server to tell testing thread if it is OK to proceed next
  // command. Will be issued after processing each FuseTestCmd.
  void ServerCompleteWith(bool success);

  // Consumes the first FUSE request when mounting FUSE. Replies with a
  // response with empty payload.
  PosixError ServerConsumeFuseInit(const struct fuse_init_out* payload);

  // A command switch that dispatch different FuseTestCmd to its handler.
  void ServerHandleCommand();

  // The FUSE server side's corresponding code of `SetServerResponse()`.
  // Handles `kSetResponse` command. Saves the fake response into its output
  // memory queue.
  void ServerReceiveResponse();

  // The FUSE server side's corresponding code of `SetServerInodeLookup()`.
  // Handles `kSetInodeLookup` command. Receives an expected file mode and
  // file path under the mount point.
  void ServerReceiveInodeLookup();

  // The FUSE server side's corresponding code of `GetServerActualRequest()`.
  // Handles `kGetRequest` command. Sends the next received request pointed by
  // the cursor.
  void ServerSendReceivedRequest();

  // Sends a uint32_t data via socket.
  inline void ServerSendData(uint32_t data);

  // The FUSE server side's corresponding code of `SkipServerActualRequest()`.
  // Handles `kSkipRequest` command. Skip the request pointed by current cursor.
  void ServerSkipReceivedRequest();

  // Handles FUSE request sent to /dev/fuse by its saved responses.
  void ServerProcessFuseRequest();

  // Responds to FUSE request with a saved data.
  void ServerRespondFuseSuccess(FuseMemBuffer& mem_buf,
                                const FuseMemBlock& block, uint64_t unique);

  // Responds an error header to /dev/fuse when bad thing happens.
  void ServerRespondFuseError(uint64_t unique);

  int sock_[2];
  std::unique_ptr<ScopedThread> fuse_server_;

  uint64_t nodeid_;
  std::unordered_map<std::string, FuseMemBlock> lookup_map_;

  FuseMemBuffer requests_;
  FuseMemBuffer responses_;
  FuseMemBuffer lookups_;
};

}  // namespace testing
}  // namespace gvisor

#endif  // GVISOR_TEST_FUSE_FUSE_BASE_H_
