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

package coretag

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// getAllCoreTags returns the core tag of all the threads in the thread group.
// PID 0 means the current pid.
func getAllCoreTags(pid int) ([]uint64, error) {
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
// PID 0 means the current PID.
func getTids(pid int) (map[int]struct{}, error) {
	tids := make(map[int]struct{})
	path := "/proc/self/task"
	if pid != 0 {
		path = fmt.Sprintf("/proc/%d/task", pid)
	}
	files, err := os.ReadDir(path)
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

func TestEnable(t *testing.T) {
	// Query the current thread with valid arguments before testing CREATE.
	// PR_SCHED_CORE requires CONFIG_SCHED_CORE and active SMT.
	// https://github.com/torvalds/linux/blob/fd73f4a66/kernel/sys.c#L2806-L2810
	// https://github.com/torvalds/linux/blob/fd73f4a66/kernel/sched/core_sched.c#L139-L140
	_, err := getCoreTag(0)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENODEV) {
		t.Skipf("Core tagging is unavailable: %v", err)
	}
	if err != nil {
		t.Fatalf("getCoreTag(0) got error %v, wanted nil", err)
	}
	tag, err := Enable()
	if err != nil {
		t.Fatalf("Enable() got error %v, wanted nil", err)
	}
	if tag == 0 {
		t.Fatalf("Enable() got tag 0, wanted != 0")
	}

	pid := os.Getpid()
	coreTags, err := getAllCoreTags(pid)
	if err != nil {
		t.Fatalf("getAllCoreTags() got error %v, wanted nil", err)
	}
	if len(coreTags) != 1 || coreTags[0] != tag {
		t.Fatalf("Got coreTags %v, wanted [%d]", coreTags, tag)
	}
	coreTagsSelf, err := getAllCoreTags(0)
	if err != nil {
		t.Fatalf("getAllCoreTags(0) got error %v, wanted nil", err)
	}
	if !reflect.DeepEqual(coreTags, coreTagsSelf) {
		t.Fatalf("Got different coreTags for PID %d vs self: %v vs %v", pid, coreTags, coreTagsSelf)
	}
}
