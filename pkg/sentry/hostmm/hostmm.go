// Copyright 2019 The gVisor Authors.
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

// Package hostmm provides tools for interacting with the host Linux kernel's
// virtual memory management subsystem.
package hostmm

import (
	"fmt"
	"os"
	"path"
	"regexp"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
)

// ReadTransparentHugepageEnum returns the currently selected option for
// whichever of
// /sys/kernel/mm/transparent_hugepage/{enabled,shmem_enabled,defrag} is
// specified by filename. (Only the basename is required, not the full path.)
func ReadTransparentHugepageEnum(filename string) (string, error) {
	pathname := path.Join("/sys/kernel/mm/transparent_hugepage/", filename)
	data, err := os.ReadFile(pathname)
	if err != nil {
		return "", err
	}
	return GetTransparentHugepageEnum(string(data))
}

// GetTransparentHugepageEnum returns the currently selected option given the
// contents of any of
// /sys/kernel/mm/transparent_hugepage/{enabled,shmem_enabled,defrag}.
func GetTransparentHugepageEnum(data string) (string, error) {
	// In these files, the selected option is highlighted by square brackets.
	m := regexp.MustCompile(`\[.*\]`).FindString(data)
	if m == "" {
		return "", fmt.Errorf("failed to find selected option in %q", data)
	}
	// Remove the square brackets.
	return m[1 : len(m)-1], nil
}

// NotifyCurrentMemcgPressureCallback requests that f is called whenever the
// calling process' memory cgroup indicates memory pressure of the given level,
// as specified by Linux's Documentation/cgroup-v1/memory.txt.
//
// If NotifyCurrentMemcgPressureCallback succeeds, it returns a function that
// terminates the requested memory pressure notifications. This function may be
// called at most once.
func NotifyCurrentMemcgPressureCallback(f func(), level string) (func(), error) {
	cgdir, err := currentCgroupDirectory("memory")
	if err != nil {
		return nil, err
	}

	pressurePath := path.Join(cgdir, "memory.pressure_level")
	pressureFile, err := os.Open(pressurePath)
	if err != nil {
		return nil, err
	}
	defer pressureFile.Close()

	eventControlPath := path.Join(cgdir, "cgroup.event_control")
	eventControlFile, err := os.OpenFile(eventControlPath, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	defer eventControlFile.Close()

	eventFD, err := eventfd.Create()
	if err != nil {
		return nil, err
	}

	// Don't use fmt.Fprintf since the whole string needs to be written in a
	// single unix.
	eventControlStr := fmt.Sprintf("%d %d %s", eventFD.FD(), pressureFile.Fd(), level)
	if n, err := eventControlFile.Write([]byte(eventControlStr)); n != len(eventControlStr) || err != nil {
		eventFD.Close()
		return nil, fmt.Errorf("error writing %q to %s: got (%d, %v), wanted (%d, nil)", eventControlStr, eventControlPath, n, err, len(eventControlStr))
	}

	log.Debugf("Receiving memory pressure level notifications from %s at level %q", pressurePath, level)
	const sizeofUint64 = 8
	// The most significant bit of the eventfd value is set by the stop
	// function, which is practically unambiguous since it's not plausible for
	// 2**63 pressure events to occur between eventfd reads.
	const stopVal = 1 << 63
	stopCh := make(chan struct{})
	go func() { // S/R-SAFE: f provides synchronization if necessary
		for {
			val, err := eventFD.Read()
			if err != nil {
				panic(fmt.Sprintf("failed to read from memory pressure level eventfd: %v", err))
			}
			if val >= stopVal {
				// Assume this was due to the notifier's "destructor" (the
				// function returned by NotifyCurrentMemcgPressureCallback
				// below) being called.
				eventFD.Close()
				close(stopCh)
				return
			}
			f()
		}
	}()
	return func() {
		eventFD.Write(stopVal)
		<-stopCh
	}, nil
}

// IMAWorkAroundForMemFile works around IMA by immediately creating a temporary
// PROT_EXEC mapping, while the backing file is still small. IMA will ignore
// any future mappings.
//
// The Linux kernel contains an optional feature called "Integrity
// Measurement Architecture" (IMA). If IMA is enabled, it will checksum
// binaries the first time they are mapped PROT_EXEC. This is bad news for
// executable pages mapped from our backing file, which can grow to
// terabytes in (sparse) size. If IMA attempts to checksum a file that
// large, it will allocate all of the sparse pages and quickly exhaust all
// memory.
func IMAWorkAroundForMemFile(fd uintptr) {
	m, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		hostarch.PageSize,
		unix.PROT_EXEC,
		unix.MAP_SHARED,
		fd,
		0)
	if errno != 0 {
		// This isn't fatal (IMA may not even be in use). Log the error, but
		// don't return it.
		log.Warningf("Failed to pre-map MemoryFile PROT_EXEC: %v", errno)
	} else {
		if _, _, errno := unix.Syscall(
			unix.SYS_MUNMAP,
			m,
			hostarch.PageSize,
			0); errno != 0 {
			panic(fmt.Sprintf("failed to unmap PROT_EXEC MemoryFile mapping: %v", errno))
		}
	}
}
