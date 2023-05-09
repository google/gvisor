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

	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/log"
)

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
