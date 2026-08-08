// Copyright 2026 The gVisor Authors.
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

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/cgroup_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr uint32_t kBpfCgroupMaxProgs = 64;
constexpr uint32_t kBpfComplexityLimitInsns = 1000000;

struct BpfAttrProgLoad {
  uint32_t prog_type;
  uint32_t insn_cnt;
  uint64_t insns;
  uint64_t license;
  uint32_t log_level;
  uint32_t log_size;
  uint64_t log_buf;
  uint32_t kern_version;
  uint32_t prog_flags;
  char prog_name[BPF_OBJ_NAME_LEN];
  uint32_t prog_ifindex;
  uint32_t expected_attach_type;
  uint32_t prog_btf_fd;
  uint32_t func_info_rec_size;
  uint64_t func_info;
  uint32_t func_info_cnt;
  uint32_t line_info_rec_size;
  uint64_t line_info;
  uint32_t line_info_cnt;
  uint32_t attach_btf_id;
  uint32_t core_relo_cnt;
  uint64_t fd_array;
  uint64_t core_relos;
  uint32_t core_relo_rec_size;
  uint32_t log_true_size;
  int32_t prog_token_fd;
  uint32_t fd_array_cnt;
  uint64_t signature;
  uint32_t signature_size;
  int32_t keyring_id;
};
static_assert(sizeof(BpfAttrProgLoad) == 168, "bad BPF_PROG_LOAD attr layout");

struct BpfAttrProgAttach {
  uint32_t target_fd;
  uint32_t attach_bpf_fd;
  uint32_t attach_type;
  uint32_t attach_flags;
  uint32_t replace_bpf_fd;
  uint32_t relative_fd;
  uint64_t expected_revision;
};
static_assert(sizeof(BpfAttrProgAttach) == 32,
              "bad BPF_PROG_ATTACH attr layout");

struct BpfAttrProgQuery {
  uint32_t target_fd;
  uint32_t attach_type;
  uint32_t query_flags;
  uint32_t attach_flags;
  uint64_t prog_ids;
  uint32_t prog_cnt;
  uint32_t pad;
  uint64_t prog_attach_flags;
  uint64_t link_ids;
  uint64_t link_attach_flags;
  uint64_t revision;
};
static_assert(sizeof(BpfAttrProgQuery) == 64, "bad BPF_PROG_QUERY attr layout");

// The largest member of union bpf_attr is the size of the union itself.
constexpr size_t kBpfAttrSize =
    std::max({sizeof(BpfAttrProgLoad), sizeof(BpfAttrProgAttach),
              sizeof(BpfAttrProgQuery)});

// A trivial BPF_PROG_TYPE_CGROUP_DEVICE program that allows every device
// access.
constexpr struct bpf_insn kAllowAllDevices[] = {
    {BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1},
    {BPF_JMP | BPF_EXIT, 0, 0, 0, 0},
};
constexpr uint32_t kAllowAllDevicesInsnCnt =
    sizeof(kAllowAllDevices) / sizeof(kAllowAllDevices[0]);

int bpf(int cmd, void* attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

// Fills in attr for BPF_ATTR_LOAD with program kAllowAllDevices.
static void InitProgLoadAttr(BpfAttrProgLoad* attr) {
  *attr = {};
  attr->prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
  attr->insn_cnt = kAllowAllDevicesInsnCnt;
  attr->insns = reinterpret_cast<uint64_t>(&kAllowAllDevices[0]);
  attr->license = reinterpret_cast<uint64_t>("Apache-2.0");
}

static PosixErrorOr<FileDescriptor> LoadProgram() {
  BpfAttrProgLoad attr;
  InitProgLoadAttr(&attr);
  int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  if (fd < 0) {
    return PosixError(errno, "bpf(BPF_PROG_LOAD)");
  }
  return FileDescriptor(fd);
}

static int AttachProgram(int prog_fd, int cgroup_fd, uint32_t flags,
                         uint32_t attach_type = BPF_CGROUP_DEVICE) {
  BpfAttrProgAttach attr = {};
  attr.target_fd = cgroup_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = attach_type;
  attr.attach_flags = flags;
  return bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

static BpfAttrProgQuery MakeQueryAttr(int cgroup_fd, uint32_t count,
                                      uint32_t* ids) {
  BpfAttrProgQuery attr = {};
  attr.target_fd = cgroup_fd;
  attr.attach_type = BPF_CGROUP_DEVICE;
  attr.prog_cnt = count;
  attr.prog_ids = reinterpret_cast<uint64_t>(ids);
  return attr;
}

class EbpfTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Need CAP_SYS_ADMIN to mount a cgroup
    // (also implies permission to manage cgroup eBPF filters)
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

    // The above capabilities aren't necessarily enough, since we need them
    // in the *initial* root user ns.
    //
    // So, we'll make a test bpf() call and and skip if it's blocked.
    BpfAttrProgLoad probe = {
        .insn_cnt = kAllowAllDevicesInsnCnt,
        .insns = reinterpret_cast<uint64_t>(&kAllowAllDevices[0]),
        .license = reinterpret_cast<uint64_t>("Apache-2.0"),
    };
    SKIP_IF(bpf(BPF_PROG_LOAD, &probe, sizeof(probe)) < 0 &&
            (errno == ENOSYS || errno == EPERM));

    mounter_.emplace(ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir()));
    root_.emplace(ASSERT_NO_ERRNO_AND_VALUE(mounter_->MountCgroup2fs()));
    cgroup_.emplace(ASSERT_NO_ERRNO_AND_VALUE(root_->CreateChild("bpf")));
    cgroup_fd_ = ASSERT_NO_ERRNO_AND_VALUE(OpenCgroup(*cgroup_));
  }

  void TearDown() override {
    cgroup_fd_.reset();
    if (cgroup_.has_value()) {
      RemoveCgroupTree(cgroup_->Path());
      cgroup_.reset();
    }
    root_.reset();
    mounter_.reset();
  }

  static PosixErrorOr<FileDescriptor> OpenCgroup(const Cgroup& cgroup) {
    return Open(cgroup.Path(), O_RDONLY | O_DIRECTORY);
  }

  // Recursively removes the cgroup at path and all cgroups below it.
  static void RemoveCgroupTree(const std::string& path) {
    auto children = ListDir(path, /*skipdots=*/true);
    if (children.ok()) {
      for (const auto& child : children.ValueOrDie()) {
        const std::string full_path = JoinPath(path, child);
        auto is_dir = IsDirectory(full_path);
        if (is_dir.ok() && is_dir.ValueOrDie()) {
          RemoveCgroupTree(full_path);
        }
      }
    }
    Rmdir(path).IgnoreError();
  }

  int cgroup_fd() const { return cgroup_fd_.get(); }

  std::optional<Mounter> mounter_;
  std::optional<Cgroup> root_;
  std::optional<Cgroup> cgroup_;
  FileDescriptor cgroup_fd_;
};  // namespace

// BPF_PROG_LOAD

TEST_F(EbpfTest, LoadSucceeds) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_GE(prog.get(), 0);

  // Program fds are always close-on-exec.
  int flags = fcntl(prog.get(), F_GETFD);
  ASSERT_THAT(flags, SyscallSucceeds());
  EXPECT_TRUE(flags & FD_CLOEXEC);
}

TEST_F(EbpfTest, LoadInvalidProgramTypeFails) {
  BpfAttrProgLoad attr;

  InitProgLoadAttr(&attr);
  attr.prog_type = BPF_PROG_TYPE_UNSPEC;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));

  InitProgLoadAttr(&attr);
  attr.prog_type = 10000;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, LoadBadInstructionCountFails) {
  BpfAttrProgLoad attr;

  // 0 instructions
  InitProgLoadAttr(&attr);
  attr.insn_cnt = 0;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(E2BIG));

  // BPF_COMPLEXITY_LIMIT_INSTRUCTIONS + 1 instructions
  InitProgLoadAttr(&attr);
  attr.insn_cnt = kBpfComplexityLimitInsns + 1;
  std::vector<char> buf(attr.insn_cnt);
  attr.insns = reinterpret_cast<uint64_t>(buf.data());
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(E2BIG));
}

TEST_F(EbpfTest, LoadInvalidProgFlagsFails) {
  BpfAttrProgLoad attr;
  InitProgLoadAttr(&attr);
  attr.prog_flags = 0xffffffff;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, LoadWithAttachBtfIDFails) {
  BpfAttrProgLoad attr;
  InitProgLoadAttr(&attr);
  attr.attach_btf_id = 1;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, LoadBadInstructionPointerFails) {
  BpfAttrProgLoad attr;
  InitProgLoadAttr(&attr);
  attr.insns = 0;
  EXPECT_THAT(bpf(BPF_PROG_LOAD, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EFAULT));
}

TEST_F(EbpfTest, LoadRequiresBpfCapability) {
  ScopedThread([] {
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_NO_ERRNO(SetCapability(CAP_BPF, false));
    EXPECT_THAT(LoadProgram(), PosixErrorIs(EPERM));
  });
}

TEST_F(EbpfTest, LoadCgroupDeviceRequiresNetOrSysAdmin) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_BPF)));

  ScopedThread([] {
    EXPECT_NO_ERRNO(SetCapability(CAP_NET_ADMIN, false));
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_THAT(LoadProgram(), PosixErrorIs(EPERM));
  });
}

// BPF_PROG_ATTACH

TEST_F(EbpfTest, AttachSucceeds) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), 0), SyscallSucceeds());
}

TEST_F(EbpfTest, AttachAllowMulti) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
}

TEST_F(EbpfTest, AttachWithOverrideSucceeds) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_OVERRIDE),
              SyscallSucceeds());
}

TEST_F(EbpfTest, AttachInvalidFlagsFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  // BPF_F_ALLOW_MULTI and BPF_F_ALLOW_OVERRIDE are mutually exclusive.
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(),
                            BPF_F_ALLOW_MULTI | BPF_F_ALLOW_OVERRIDE),
              SyscallFailsWithErrno(EINVAL));

  // Undefined flags are rejected.
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), 1 << 20),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttachInvalidAttachTypeFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI,
                            __MAX_BPF_ATTACH_TYPE),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttachMismatchedProgramTypeFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI,
                            BPF_CGROUP_INET_INGRESS),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttachBadProgramFdFails) {
  FileDescriptor not_a_prog =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  EXPECT_THAT(AttachProgram(not_a_prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttachBadCgroupFdFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  FileDescriptor not_a_cgroup =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  EXPECT_THAT(AttachProgram(prog.get(), not_a_cgroup.get(), BPF_F_ALLOW_MULTI),
              SyscallFailsWithErrno(EBADF));

  // A cgroup control file is on cgroup2fs, but is not a cgroup node.
  FileDescriptor control_file = ASSERT_NO_ERRNO_AND_VALUE(
      Open(cgroup_->Relpath("cgroup.procs"), O_RDONLY));
  EXPECT_THAT(AttachProgram(prog.get(), control_file.get(), BPF_F_ALLOW_MULTI),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(EbpfTest, AttachSameProgramTwiceFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  ASSERT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
  EXPECT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttachWithMismatchedFlagsFails) {
  FileDescriptor prog1 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor prog2 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  ASSERT_THAT(AttachProgram(prog1.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
  // All programs in a slot must agree on the slot-wide flags.
  EXPECT_THAT(AttachProgram(prog2.get(), cgroup_fd(), 0),
              SyscallFailsWithErrno(EPERM));
}

TEST_F(EbpfTest, AttachTooManyProgramsFails) {
  std::vector<FileDescriptor> progs;
  for (uint32_t i = 0; i < kBpfCgroupMaxProgs; i++) {
    progs.push_back(ASSERT_NO_ERRNO_AND_VALUE(LoadProgram()));
    ASSERT_THAT(
        AttachProgram(progs.back().get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
        SyscallSucceeds());
  }

  FileDescriptor extra = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  EXPECT_THAT(AttachProgram(extra.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallFailsWithErrno(E2BIG));

  uint32_t ids[kBpfCgroupMaxProgs] = {};
  BpfAttrProgQuery query = MakeQueryAttr(cgroup_fd(), kBpfCgroupMaxProgs, ids);
  ASSERT_THAT(bpf(BPF_PROG_QUERY, &query, sizeof(query)), SyscallSucceeds());
  EXPECT_EQ(query.prog_cnt, kBpfCgroupMaxProgs);
}

TEST_F(EbpfTest, AttachBelowNonOverridableProgramFails) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(cgroup_->CreateChild("child"));
  FileDescriptor child_fd = ASSERT_NO_ERRNO_AND_VALUE(OpenCgroup(child));

  FileDescriptor parent_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor child_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  // The parent's program allows neither multi-attach nor override, so nothing
  // may attach below it.
  ASSERT_THAT(AttachProgram(parent_prog.get(), cgroup_fd(), 0),
              SyscallSucceeds());
  EXPECT_THAT(AttachProgram(child_prog.get(), child_fd.get(), 0),
              SyscallFailsWithErrno(EPERM));
}

TEST_F(EbpfTest, AttachBelowOverridableProgramSucceeds) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(cgroup_->CreateChild("child"));
  FileDescriptor child_fd = ASSERT_NO_ERRNO_AND_VALUE(OpenCgroup(child));

  FileDescriptor parent_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor child_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  ASSERT_THAT(
      AttachProgram(parent_prog.get(), cgroup_fd(), BPF_F_ALLOW_OVERRIDE),
      SyscallSucceeds());
  EXPECT_THAT(AttachProgram(child_prog.get(), child_fd.get(), 0),
              SyscallSucceeds());
}

TEST_F(EbpfTest, AttachBelowMultiProgramSucceeds) {
  Cgroup child = ASSERT_NO_ERRNO_AND_VALUE(cgroup_->CreateChild("child"));
  FileDescriptor child_fd = ASSERT_NO_ERRNO_AND_VALUE(OpenCgroup(child));

  FileDescriptor parent_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor child_prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  ASSERT_THAT(AttachProgram(parent_prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
  EXPECT_THAT(
      AttachProgram(child_prog.get(), child_fd.get(), BPF_F_ALLOW_MULTI),
      SyscallSucceeds());
}

TEST_F(EbpfTest, AttachIsPermittedByProgramFd) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  // Privilege is required to obtain a program fd, but not to attach one, so an
  // unprivileged process that inherits the fd can still attach it.
  EXPECT_THAT(
      InForkedProcess([prog_fd = prog.get(), cgroup_fd = cgroup_fd()] {
        TEST_CHECK_NO_ERRNO(SetCapability(CAP_BPF, false));
        TEST_CHECK_NO_ERRNO(SetCapability(CAP_NET_ADMIN, false));
        TEST_CHECK_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));

        TEST_CHECK(::testing::Value(LoadProgram(), PosixErrorIs(EPERM)));
        TEST_CHECK_SUCCESS(
            AttachProgram(prog_fd, cgroup_fd, BPF_F_ALLOW_MULTI));
      }),
      IsPosixErrorOkAndHolds(0));

  uint32_t ids[4] = {};
  BpfAttrProgQuery query = MakeQueryAttr(cgroup_fd(), 4, ids);
  ASSERT_THAT(bpf(BPF_PROG_QUERY, &query, sizeof(query)), SyscallSucceeds());
  EXPECT_EQ(query.prog_cnt, 1);
}

// BPF_PROG_QUERY

TEST_F(EbpfTest, QueryEmptyCgroup) {
  uint32_t ids[4] = {};
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 4, ids);
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)), SyscallSucceeds());
  EXPECT_EQ(attr.prog_cnt, 0);
  EXPECT_EQ(attr.attach_flags, 0);
}

TEST_F(EbpfTest, QueryRevisionStartsAtOne) {
  if (!IsRunningOnGvisor()) {
    // Cgroup eBPF program revisions were added in kernel 6.17, so skip them on
    // the native test on older kernels.
    const auto kernelVersion = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(!((kernelVersion.major > 6) ||
              (kernelVersion.major == 6 && kernelVersion.minor >= 17)));
  }

  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 0, nullptr);
  ASSERT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)), SyscallSucceeds());

  // Check that the revision starts at one.
  EXPECT_EQ(attr.revision, 1);
}

TEST_F(EbpfTest, QueryReportsAttachedPrograms) {
  BpfAttrProgQuery before = MakeQueryAttr(cgroup_fd(), 0, nullptr);
  ASSERT_THAT(bpf(BPF_PROG_QUERY, &before, sizeof(before)), SyscallSucceeds());

  FileDescriptor prog1 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor prog2 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  ASSERT_THAT(AttachProgram(prog1.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
  ASSERT_THAT(AttachProgram(prog2.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());

  uint32_t ids[4] = {};
  BpfAttrProgQuery after = MakeQueryAttr(cgroup_fd(), 4, ids);
  ASSERT_THAT(bpf(BPF_PROG_QUERY, &after, sizeof(after)), SyscallSucceeds());
  EXPECT_EQ(after.prog_cnt, 2);
  EXPECT_EQ(after.attach_flags, BPF_F_ALLOW_MULTI);
  if (!IsRunningOnGvisor()) {
    const auto kernelVersion = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    if ((kernelVersion.major > 6) ||
        (kernelVersion.major == 6 && kernelVersion.minor >= 17)) {
      // Check that each attach bumps the slot's revision.
      // Again, skip this on kernels older than 6.17, which lack cgroup eBPF
      // program revisions.
      EXPECT_GT(after.revision, before.revision);
    }
  }
}

TEST_F(EbpfTest, QueryOtherAttachTypeIsEmpty) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  ASSERT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());

  // Programs are tracked per attach type.
  uint32_t ids[4] = {};
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 4, ids);
  attr.attach_type = BPF_CGROUP_INET_INGRESS;
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)), SyscallSucceeds());
  EXPECT_EQ(attr.prog_cnt, 0);
}

TEST_F(EbpfTest, QueryBufferTooSmall) {
  FileDescriptor prog1 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  FileDescriptor prog2 = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  ASSERT_THAT(AttachProgram(prog1.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());
  ASSERT_THAT(AttachProgram(prog2.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());

  uint32_t ids[4] = {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF};
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 1, ids);
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)),
              SyscallFailsWithErrno(ENOSPC));

  // The real count is still reported, and only the one slot the caller asked
  // for is written.
  EXPECT_EQ(attr.prog_cnt, 2);
  EXPECT_EQ(ids[1], 0xDEADBEEF);
  EXPECT_EQ(ids[2], 0xDEADBEEF);
  EXPECT_EQ(ids[3], 0xDEADBEEF);
}

TEST_F(EbpfTest, QueryCountOnly) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());
  ASSERT_THAT(AttachProgram(prog.get(), cgroup_fd(), BPF_F_ALLOW_MULTI),
              SyscallSucceeds());

  // A call with an empty buffer returns only the count.
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 0, nullptr);
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)), SyscallSucceeds());
  EXPECT_EQ(attr.prog_cnt, 1);
}

TEST_F(EbpfTest, QueryBadCgroupFdFails) {
  uint32_t ids[1] = {};

  FileDescriptor not_a_cgroup =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/null", O_RDONLY));
  BpfAttrProgQuery attr = MakeQueryAttr(not_a_cgroup.get(), 1, ids);
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EBADF));
}

TEST_F(EbpfTest, QueryInvalidAttachTypeFails) {
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 0, nullptr);
  attr.attach_type = __MAX_BPF_ATTACH_TYPE;
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, QueryInvalidFlagsFails) {
  BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 0, nullptr);
  attr.query_flags = 1u << 31;
  EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, QueryRequiresCapability) {
  // Unlike attach, query requires CAP_NET_ADMIN or CAP_SYS_ADMIN.
  ScopedThread([this] {
    EXPECT_NO_ERRNO(SetCapability(CAP_NET_ADMIN, false));
    EXPECT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));
    EXPECT_NO_ERRNO(SetCapability(CAP_BPF, false));

    BpfAttrProgQuery attr = MakeQueryAttr(cgroup_fd(), 0, nullptr);
    EXPECT_THAT(bpf(BPF_PROG_QUERY, &attr, sizeof(attr)),
                SyscallFailsWithErrno(EPERM));
  });
}

// bpf(2) argument handling

TEST_F(EbpfTest, UnimplementedCommandWithCapFails) {
  SKIP_IF(!IsRunningOnGvisor());

  // Unimplemented cmd with capabilities should give EINVAL.
  BpfAttrProgAttach attr = {};
  EXPECT_THAT(bpf(BPF_MAP_CREATE, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, UnimplementedCommandWithoutCapFails) {
  SKIP_IF(!IsRunningOnGvisor());

  AutoCapability cap_sys_admin(CAP_SYS_ADMIN, false);
  AutoCapability cap_bpf(CAP_BPF, false);

  // Unimplemented cmd without capabilities should give EPERM.
  BpfAttrProgAttach attr = {};
  EXPECT_THAT(bpf(BPF_MAP_CREATE, &attr, sizeof(attr)),
              SyscallFailsWithErrno(EPERM));
}

TEST_F(EbpfTest, AttrSizeTooLargeFails) {
  BpfAttrProgAttach attr = {};
  EXPECT_THAT(bpf(BPF_PROG_ATTACH, &attr, 1 << 20),
              SyscallFailsWithErrno(E2BIG));
}

TEST_F(EbpfTest, LargerAttrWithZeroedTailSucceeds) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  // A caller built against a newer kernel may pass more than BPF_PROG_ATTACH
  // reads. That is accepted as long as the extra bytes are zeroed.
  alignas(8) char buf[sizeof(BpfAttrProgAttach) + 100] = {};
  auto* attr = reinterpret_cast<BpfAttrProgAttach*>(buf);
  attr->target_fd = cgroup_fd();
  attr->attach_bpf_fd = prog.get();
  attr->attach_type = BPF_CGROUP_DEVICE;
  attr->attach_flags = BPF_F_ALLOW_MULTI;
  EXPECT_THAT(bpf(BPF_PROG_ATTACH, buf, sizeof(buf)), SyscallSucceeds());
}

TEST_F(EbpfTest, AttrWithNonZeroTailFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  alignas(8) char buf[sizeof(BpfAttrProgAttach) + 8] = {};
  auto* attr = reinterpret_cast<BpfAttrProgAttach*>(buf);
  attr->target_fd = cgroup_fd();
  attr->attach_bpf_fd = prog.get();
  attr->attach_type = BPF_CGROUP_DEVICE;
  attr->attach_flags = BPF_F_ALLOW_MULTI;

  // Set a byte in the part of union bpf_attr that BPF_PROG_ATTACH doesn't read.
  // Linux rejects this in CHECK_ATTR().
  buf[sizeof(BpfAttrProgAttach)] = 1;
  EXPECT_THAT(bpf(BPF_PROG_ATTACH, buf, sizeof(buf)),
              SyscallFailsWithErrno(EINVAL));
}

TEST_F(EbpfTest, AttrPastUnionWithNonZeroTailFails) {
  FileDescriptor prog = ASSERT_NO_ERRNO_AND_VALUE(LoadProgram());

  alignas(8) char buf[kBpfAttrSize + 8] = {};
  auto* attr = reinterpret_cast<BpfAttrProgAttach*>(buf);
  attr->target_fd = cgroup_fd();
  attr->attach_bpf_fd = prog.get();
  attr->attach_type = BPF_CGROUP_DEVICE;
  attr->attach_flags = BPF_F_ALLOW_MULTI;
  buf[kBpfAttrSize] = 1;

  EXPECT_THAT(bpf(BPF_PROG_ATTACH, buf, sizeof(buf)),
              SyscallFailsWithErrno(E2BIG));
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
