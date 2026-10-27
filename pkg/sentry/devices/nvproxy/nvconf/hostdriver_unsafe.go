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

package nvconf

import (
	"bytes"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

// HostDriverVersion returns the version of the host Nvidia driver. devRoot is
// the host directory under which the Nvidia device files are found.
func HostDriverVersion(devRoot string) (string, error) {
	ctlPath := filepath.Join(devRoot, "/dev/nvidiactl")
	ctlFD, err := unix.Openat(-1, ctlPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", ctlPath, err)
	}
	defer unix.Close(ctlFD)

	// The path was checked when the dev root was chosen, but it is opened by
	// name here, so check what was opened.
	var st unix.Stat_t
	if err := unix.Fstat(ctlFD, &st); err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", ctlPath, err)
	}
	if err := checkNVControlDeviceStat(ctlPath, &st); err != nil {
		return "", err
	}

	// From src/nvidia/arch/nvalloc/unix/include/nv-ioctl.h:
	const NV_RM_API_VERSION_REPLY_RECOGNIZED = 1

	// 530.30.02 and later versions of the host driver `#define
	// NV_RM_API_VERSION_CMD_QUERY '2'`, which causes this ioctl to return the
	// driver version without performing a check. Earlier versions of the
	// driver `#define NV_RM_API_VERSION_CMD_OVERRIDE '2'`, which causes the
	// ioctl to no-op. Try with Cmd '2' first, hoping that the driver
	// interprets it as _QUERY; if the returned string is empty, then it was
	// interpreted as _OVERRIDE and we need to perform an actual check (Cmd 0),
	// which has the downside of logging an error message.
	ioctlParams := nvgpu.RMAPIVersion{
		Cmd: '2',
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(ctlFD), uintptr(linux.IOWR(nvgpu.NV_IOCTL_MAGIC, nvgpu.NV_ESC_CHECK_VERSION_STR, uint32(unsafe.Sizeof(ioctlParams)))), uintptr(unsafe.Pointer(&ioctlParams))); errno != 0 {
		return "", fmt.Errorf("NV_ESC_CHECK_VERSION_STR ioctl error: %w", errno)
	}
	if ioctlParams.Reply != NV_RM_API_VERSION_REPLY_RECOGNIZED {
		return "", fmt.Errorf("unknown NV_ESC_CHECK_VERSION_STR reply: %d", ioctlParams.Reply)
	}
	if ioctlParams.VersionString[0] == '\x00' {
		ioctlParams.Cmd = 0
		ioctlParams.Reply = 0
		// We expect the check to fail on our empty version string, so tolerate
		// EINVAL.
		if _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(ctlFD), uintptr(linux.IOWR(nvgpu.NV_IOCTL_MAGIC, nvgpu.NV_ESC_CHECK_VERSION_STR, uint32(unsafe.Sizeof(ioctlParams)))), uintptr(unsafe.Pointer(&ioctlParams))); errno != 0 && errno != unix.EINVAL {
			return "", fmt.Errorf("fallback NV_ESC_CHECK_VERSION_STR ioctl error: %w", errno)
		}
		if ioctlParams.Reply != NV_RM_API_VERSION_REPLY_RECOGNIZED {
			return "", fmt.Errorf("unknown fallback NV_ESC_CHECK_VERSION_STR reply: %d", ioctlParams.Reply)
		}
	}

	if i := bytes.IndexByte(ioctlParams.VersionString[:], '\x00'); i >= 0 {
		return string(ioctlParams.VersionString[:i]), nil
	}
	return string(ioctlParams.VersionString[:]), nil
}
