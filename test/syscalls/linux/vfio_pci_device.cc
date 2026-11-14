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

#include <fcntl.h>
#include <linux/vfio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {
namespace {

TEST(VfioPCIDeviceTest, Open) {
  const char* group_path = getenv("TEST_VFIO_GROUP");
  const char* device_name = getenv("TEST_VFIO_DEVICE");
  ASSERT_NE(group_path, nullptr);
  ASSERT_NE(device_name, nullptr);
  auto container = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/vfio/vfio", O_RDWR));
  auto group = ASSERT_NO_ERRNO_AND_VALUE(Open(group_path, O_RDWR));
  int container_fd = container.get();
  ASSERT_THAT(ioctl(group.get(), VFIO_GROUP_SET_CONTAINER, &container_fd),
              SyscallSucceeds());
  ASSERT_THAT(ioctl(container.get(), VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU),
              SyscallSucceeds());
  const FileDescriptor device(
      ioctl(group.get(), VFIO_GROUP_GET_DEVICE_FD, device_name));
  ASSERT_THAT(device.get(), SyscallSucceeds());

  struct vfio_device_info info = {};
  info.argsz = sizeof(info);
  ASSERT_THAT(ioctl(device.get(), VFIO_DEVICE_GET_INFO, &info),
              SyscallSucceeds());
  ASSERT_NE(info.flags & VFIO_DEVICE_FLAGS_PCI, 0);
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
