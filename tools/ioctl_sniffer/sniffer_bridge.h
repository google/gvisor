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

#ifndef TOOLS_IOCTL_SNIFFER_SNIFFER_BRIDGE_H_
#define TOOLS_IOCTL_SNIFFER_SNIFFER_BRIDGE_H_

#include "tools/ioctl_sniffer/ioctl.pb.h"

// The file descriptor to write the ioctl data to. Go's os.exec will
// always make this available.
constexpr int LOG_OUTPUT_FD = 3;

// Write the ioctl proto to the log output file descriptor. Our format is:
//   - 8 byte little endian uint64 containing the size of the proto.
//   - The proto bytes.
// This should match the format in sniffer_bridge.go.
void WriteIoctlProto(gvisor::Ioctl &ioctl);

#endif  // TOOLS_IOCTL_SNIFFER_SNIFFER_BRIDGE_H_
