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

//go:build linux
// +build linux

package fdnotifier

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestNotifierStartup(t *testing.T) {
	// Both RLIMIT_NOFILE and the shared notifier belong to the process.
	// Each case needs to run before the first successful registration.
	const probe = "GVISOR_TEST_FDNOTIFIER_STARTUP"
	mode, child := os.LookupEnv(probe)
	if !child {
		for _, mode := range []string{"Pause", "Register"} {
			t.Run(mode, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestNotifierStartup$")
				cmd.Env = append(os.Environ(), probe+"="+mode)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
			})
		}
		return
	}

	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var q waiter.Queue
	entry, _ := waiter.NewChannelEntry(waiter.EventIn)
	q.EventRegister(&entry)
	defer q.EventUnregister(&entry)

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Max: limit.Max}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
				t.Fatal(err)
			}
		}()
		switch mode {
		case "Pause":
			Pause()
			Resume()
		case "Register":
			if err := AddFD(int32(fd), &q); !errors.Is(err, unix.EMFILE) {
				t.Fatalf("AddFD at the descriptor limit = %v, want EMFILE", err)
			}
		default:
			t.Fatalf("unknown probe %q", mode)
		}
	}()
	if err := AddFD(int32(fd), &q); err != nil {
		t.Fatalf("AddFD after restoring the descriptor limit: %v", err)
	}
	RemoveFD(int32(fd))
}
