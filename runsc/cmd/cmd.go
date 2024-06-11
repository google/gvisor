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

// Package cmd holds implementations of the runsc commands.
package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
)

// intFlags can be used with int flags that appear multiple times. It supports
// comma-separated lists too.
type intFlags []int

// String implements flag.Value.
func (i *intFlags) String() string {
	sInts := make([]string, 0, len(*i))
	for _, fd := range *i {
		sInts = append(sInts, strconv.Itoa(fd))
	}
	return strings.Join(sInts, ",")
}

// Get implements flag.Value.
func (i *intFlags) Get() any {
	return i
}

// GetArray returns an array of ints representing FDs.
func (i *intFlags) GetArray() []int {
	return *i
}

// GetFDs returns an array of *fd.FD.
func (i *intFlags) GetFDs() []*fd.FD {
	rv := make([]*fd.FD, 0, len(*i))
	for _, val := range *i {
		rv = append(rv, fd.New(val))
	}
	return rv
}

// Set implements flag.Value. Set(String()) should be idempotent.
func (i *intFlags) Set(s string) error {
	for _, sFD := range strings.Split(s, ",") {
		fd, err := strconv.Atoi(sFD)
		if err != nil {
			return fmt.Errorf("invalid flag value: %v", err)
		}
		if fd < -1 {
			return fmt.Errorf("flag value must be >= -1: %d", fd)
		}
		*i = append(*i, fd)
	}
	return nil
}

// setCapsAndCallSelf sets capabilities to the current thread and then execve's
// itself again with the arguments specified in 'args' to restart the process
// with the desired capabilities.
func setCapsAndCallSelf(args []string, caps *specs.LinuxCapabilities) error {
	// Keep thread locked while capabilities are changed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := applyCaps(caps); err != nil {
		return fmt.Errorf("applyCaps() failed: %v", err)
	}
	binPath := specutils.ExePath

	log.Infof("Execve %q again, bye!", binPath)
	err := unix.Exec(binPath, args, os.Environ())
	return fmt.Errorf("error executing %s: %v", binPath, err)
}

// callSelfAsNobody sets UID and GID to nobody and then execve's itself again.
func callSelfAsNobody(args []string) error {
	// Keep thread locked while user/group are changed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const nobody = 65534

	if _, _, err := unix.RawSyscall(unix.SYS_SETGID, uintptr(nobody), 0, 0); err != 0 {
		return fmt.Errorf("error setting uid: %v", err)
	}
	if _, _, err := unix.RawSyscall(unix.SYS_SETUID, uintptr(nobody), 0, 0); err != 0 {
		return fmt.Errorf("error setting gid: %v", err)
	}
	// Drop all capabilities.
	if err := applyCaps(&specs.LinuxCapabilities{}); err != nil {
		return fmt.Errorf("error dropping capabilities: %w", err)
	}

	binPath := specutils.ExePath

	log.Infof("Execve %q again, bye!", binPath)
	err := unix.Exec(binPath, args, os.Environ())
	return fmt.Errorf("error executing %s: %v", binPath, err)
}
