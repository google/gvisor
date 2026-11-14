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

package nvproxy

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// drmIoctlInvoke issues cmd on the host render node with buf as its argument.
func drmIoctlInvoke(hostFD int32, cmd uint32, buf []byte) (uintptr, error) {
	var arg uintptr
	if len(buf) != 0 {
		arg = uintptr(unsafe.Pointer(&buf[0]))
	}
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(hostFD), uintptr(cmd), arg)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// drmHostDriverName returns the first maxLen bytes of the name of the DRM
// driver behind hostFD and the full length of the name, as DRM_IOCTL_VERSION
// reports them.
func drmHostDriverName(hostFD int32, maxLen int) ([]byte, uint64, error) {
	name := make([]byte, maxLen)
	buf := make([]byte, 64)
	hostarch.ByteOrder.PutUint64(buf[16:], uint64(maxLen))
	hostarch.ByteOrder.PutUint64(buf[24:], uint64(uintptr(unsafe.Pointer(&name[0]))))
	_, err := drmIoctlInvoke(hostFD, drmIoctlVersion, buf)
	runtime.KeepAlive(name)
	if err != nil {
		return nil, 0, err
	}
	nameLen := hostarch.ByteOrder.Uint64(buf[16:])
	return name[:min(nameLen, uint64(maxLen))], nameLen, nil
}

// drmVersionInvoke issues DRM_IOCTL_VERSION on hostFD with buf, a struct
// drm_version, with each of its string pointers replaced by the matching
// sentry buffer in strs and its length set to that buffer's length, or with a
// null pointer for a nil one. It puts the application's pointers back in buf
// before it returns, whether the host call fails or not.
func drmVersionInvoke(hostFD int32, buf []byte, strs *[len(drmVersionStrings)][]byte) (uintptr, error) {
	var appPtrs [len(drmVersionStrings)]uint64
	for i, s := range drmVersionStrings {
		appPtrs[i] = hostarch.ByteOrder.Uint64(buf[s.ptrOff:])
		var sentryPtr uint64
		if len(strs[i]) != 0 {
			sentryPtr = uint64(uintptr(unsafe.Pointer(&strs[i][0])))
			hostarch.ByteOrder.PutUint64(buf[s.lenOff:], uint64(len(strs[i])))
		}
		hostarch.ByteOrder.PutUint64(buf[s.ptrOff:], sentryPtr)
	}
	n, err := drmIoctlInvoke(hostFD, drmIoctlVersion, buf)
	runtime.KeepAlive(strs)
	for i, s := range drmVersionStrings {
		hostarch.ByteOrder.PutUint64(buf[s.ptrOff:], appPtrs[i])
	}
	return n, err
}
