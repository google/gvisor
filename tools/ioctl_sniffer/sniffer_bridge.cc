// Copyright 2024 The gVisor Authors.
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

#include "tools/ioctl_sniffer/sniffer_bridge.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "tools/ioctl_sniffer/ioctl.pb.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"

void WriteIoctlProto(gvisor::Ioctl &ioctl) {
  // Write size of the proto message.
  uint64_t size = ioctl.ByteSizeLong();
  write(LOG_OUTPUT_FD, &size, sizeof(size));

  // Write the proto message.
  google::protobuf::io::FileOutputStream os(LOG_OUTPUT_FD);
  ioctl.SerializeToZeroCopyStream(&os);
  os.Flush();
}
