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

package fsgofer

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/lisafs"
)

const nGroupsMax = 65536

func init() {
	runtime.LockOSThread()
}

func TestGroupsAlreadySet(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested []int
		current   []int
		want      bool
	}{
		{name: "both empty", requested: nil, current: []int{}, want: true},
		{name: "same order", requested: []int{1, 2}, current: []int{1, 2}, want: true},
		{name: "other order", requested: []int{2, 1}, current: []int{1, 2}, want: true},
		{name: "repeated group", requested: []int{1, 1, 2}, current: []int{1, 2}, want: true},
		{name: "extra group", requested: []int{1}, current: []int{1, 2}, want: false},
		{name: "other group", requested: []int{1}, current: []int{2}, want: false},
		{name: "empty against one", requested: nil, current: []int{1}, want: false},
		{name: "unmapped group", requested: []int{overflowGID}, current: []int{overflowGID}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := groupsAlreadySet(tc.requested, tc.current); got != tc.want {
				t.Errorf("groupsAlreadySet(%v, %v) = %t, want %t", tc.requested, tc.current, got, tc.want)
			}
		})
	}
}

func TestSupportedMessagesNeedSetgroups(t *testing.T) {
	for _, tc := range []struct {
		name         string
		canSetGroups bool
		want         bool
	}{
		{name: "setgroups allowed", canSetGroups: true, want: true},
		{name: "setgroups denied", canSetGroups: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			impl := &connectionImpl{config: &Config{CanSetGroups: tc.canSetGroups}}
			if got := slices.Contains(impl.SupportedMessages(), lisafs.ConnectWithGroups); got != tc.want {
				t.Errorf("ConnectWithGroups offered = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestConnectWithGroupsKeepsOurGroups(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	before, err := unix.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups failed: %v", err)
	}
	want := []int{4242, 4243}
	var got []int
	sock, err := connectWithGroups(want, func() (int, error) {
		groups, err := unix.Getgroups()
		got = groups
		return 42, err
	})
	if errors.Is(err, unix.EPERM) {
		t.Skipf("setting supplementary groups needs CAP_SETGID: %v", err)
	}
	if err != nil {
		t.Fatalf("connectWithGroups failed: %v", err)
	}
	if sock != 42 {
		t.Errorf("connect returned %d, want 42", sock)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("connect ran with groups %v, want %v", got, want)
	}
	after, err := unix.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups failed: %v", err)
	}
	slices.Sort(after)
	slices.Sort(before)
	if !slices.Equal(after, before) {
		t.Errorf("our groups are %v after the connect, were %v", after, before)
	}
}

func TestConnectWithGroupsEndsItsThread(t *testing.T) {
	tid := 0
	_, err := connectWithGroups([]int{4242}, func() (int, error) {
		tid = unix.Gettid()
		return 42, nil
	})
	if errors.Is(err, unix.EPERM) {
		t.Skipf("setting supplementary groups needs CAP_SETGID: %v", err)
	}
	if err != nil {
		t.Fatalf("connectWithGroups failed: %v", err)
	}
	if tid == unix.Gettid() {
		t.Fatalf("connect ran on the calling thread %d", tid)
	}
	task := fmt.Sprintf("/proc/self/task/%d", tid)
	for range 200 {
		if _, err := os.Stat(task); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("thread %d is still running two seconds after the connect", tid)
}

func TestConnectWithGroupsPassesPanicOn(t *testing.T) {
	if _, err := connectWithGroups([]int{4242}, func() (int, error) { return 42, nil }); errors.Is(err, unix.EPERM) {
		t.Skipf("setting supplementary groups needs CAP_SETGID: %v", err)
	}
	defer func() {
		if p := recover(); p == nil {
			t.Errorf("connectWithGroups returned, want the connect's panic")
		}
	}()
	connectWithGroups([]int{4242}, func() (int, error) { panic("connect panic") })
}

func TestConnectWithGroupsFailureSkipsConnect(t *testing.T) {
	connected := false
	sock, err := connectWithGroups(make([]int, nGroupsMax+1), func() (int, error) {
		connected = true
		return 42, nil
	})
	if err == nil {
		t.Errorf("connectWithGroups succeeded, want an error")
	}
	if connected {
		t.Errorf("connect ran after the groups could not be set")
	}
	if sock != -1 {
		t.Errorf("connectWithGroups returned %d, want -1", sock)
	}
}
