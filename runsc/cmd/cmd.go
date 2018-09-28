// Copyright 2018 Google Inc.
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
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Fatalf logs to stderr and exits with a failure status code.
func Fatalf(s string, args ...interface{}) {
	// If runsc is being invoked by docker or cri-o, then we might not have
	// access to stderr, so we log a serious-looking warning in addition to
	// writing to stderr.
	log.Warningf("FATAL ERROR: "+s, args...)
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	// Return an error that is unlikely to be used by the application.
	os.Exit(128)
}

// intFlags can be used with int flags that appear multiple times.
type intFlags []int

// String implements flag.Value.
func (i *intFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

// Get implements flag.Value.
func (i *intFlags) Get() interface{} {
	return i
}

// GetArray returns array of FDs.
func (i *intFlags) GetArray() []int {
	return *i
}

// Set implements flag.Value.
func (i *intFlags) Set(s string) error {
	fd, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid flag value: %v", err)
	}
	if fd < 0 {
		return fmt.Errorf("flag value must be greater than 0: %d", fd)
	}
	*i = append(*i, fd)
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
	binPath, err := specutils.BinPath()
	if err != nil {
		return err
	}

	log.Infof("Execve %q again, bye!", binPath)
	syscall.Exec(binPath, args, []string{})
	panic("unreachable")
}
