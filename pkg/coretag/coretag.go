// Copyright 2022 The gVisor Authors.
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

// Package coretag implements core tagging.
package coretag

import (
	"fmt"
	"io/ioutil"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Enable core tagging. If this returns with no error, all threads in the
// current thread group will be run in a core tagged thread. Only available on
// linux kernel >= 5.14.
func Enable() error {
	// Set core tag on current thread group.
	// prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, pid=0,
	//       PR_SCHED_CORE_SCOPE_THREAD_GROUP, cookie=nullptr)
	// pid=0 means current pid.
	// cookie=nullptr is required for PR_SCHED_CORE_CREATE.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SCHED_CORE,
		unix.PR_SCHED_CORE_CREATE, 0 /*pid*/, linux.PR_SCHED_CORE_SCOPE_THREAD_GROUP, 0, 0); errno != 0 {
		return fmt.Errorf("failed to core tag sentry: %w", errno)
	}
	return nil
}

// GetAllCoreTags returns the core tag of all the threads in the thread group.
func GetAllCoreTags(pid int) ([]uint64, error) {
	// prctl(PR_SCHED_CORE_GET, PR_SCHED_CORE_SCOPE_THREAD_GROUP, ...) is not supported
	// in linux. So instead we get all threads from /proc/<pid>/task and get all the
	// core tags individually.
	tagSet := make(map[uint64]struct{})
	// Get current pid core tag.
	tag, err := getCoreTag(pid)
	if err != nil {
		return nil, err
	}
	tagSet[tag] = struct{}{}

	// Get core tags of tids.
	tids, err := getTids(pid)
	if err != nil {
		return nil, err
	}
	for tid := range tids {
		tag, err := getCoreTag(tid)
		if err != nil {
			return nil, err
		}
		tagSet[tag] = struct{}{}
	}

	// Return set of tags as a slice.
	tags := make([]uint64, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags, nil
}

// getTids returns set of tids as reported by /proc/<pid>/task.
func getTids(pid int) (map[int]struct{}, error) {
	tids := make(map[int]struct{})
	files, err := ioutil.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		tid, err := strconv.Atoi(file.Name())
		if err != nil {
			return nil, err
		}
		tids[tid] = struct{}{}
	}

	return tids, nil
}
