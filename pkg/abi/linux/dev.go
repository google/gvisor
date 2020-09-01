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

package linux

// MakeDeviceID encodes a major and minor device number into a single device ID.
//
// Format (see linux/kdev_t.h:new_encode_dev):
//
// Bits 7:0   - minor bits 7:0
// Bits 19:8  - major bits 11:0
// Bits 31:20 - minor bits 19:8
func MakeDeviceID(major uint16, minor uint32) uint32 {
	return (minor & 0xff) | ((uint32(major) & 0xfff) << 8) | ((minor >> 8) << 20)
}

// DecodeDeviceID decodes a device ID into major and minor device numbers.
func DecodeDeviceID(rdev uint32) (uint16, uint32) {
	major := uint16((rdev >> 8) & 0xfff)
	minor := (rdev & 0xff) | ((rdev >> 20) << 8)
	return major, minor
}

// Character device IDs.
//
// See Documentations/devices.txt and uapi/linux/major.h.
const (
	// UNNAMED_MAJOR is the major device number for "unnamed" devices, whose
	// minor numbers are dynamically allocated by the kernel.
	UNNAMED_MAJOR = 0

	// MEM_MAJOR is the major device number for "memory" character devices.
	MEM_MAJOR = 1

	// TTYAUX_MAJOR is the major device number for alternate TTY devices.
	TTYAUX_MAJOR = 5

	// MISC_MAJOR is the major device number for non-serial mice, misc feature
	// devices.
	MISC_MAJOR = 10

	// UNIX98_PTY_MASTER_MAJOR is the initial major device number for
	// Unix98 PTY masters.
	UNIX98_PTY_MASTER_MAJOR = 128

	// UNIX98_PTY_REPLICA_MAJOR is the initial major device number for
	// Unix98 PTY replicas.
	UNIX98_PTY_REPLICA_MAJOR = 136
)

// Minor device numbers for TTYAUX_MAJOR.
const (
	// PTMX_MINOR is the minor device number for /dev/ptmx.
	PTMX_MINOR = 2
)
