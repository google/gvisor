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

package main

import (
	"context"
	"os"
	"runtime"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

// execFromThread re-execs itself in a loop, always from a thread that is not
// the thread group leader. Each execve enters the window in which the old
// leader has exited but the execing thread has not yet been promoted in its
// place, which is the window in which container state must not be misreported
// as stopped.
type execFromThread struct{}

// Name implements subcommands.Command.Name.
func (*execFromThread) Name() string {
	return "exec-from-thread"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*execFromThread) Synopsis() string {
	return "re-execs itself in a loop from a non-thread-group-leader thread"
}

// Usage implements subcommands.Command.Usage.
func (*execFromThread) Usage() string {
	return "exec-from-thread"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*execFromThread) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*execFromThread) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	errCh := make(chan error, 1)
	go execWhenNotLeader(errCh)
	// On success this process is replaced and we never get here.
	fatalf("exec-from-thread: %v", <-errCh)
	return subcommands.ExitFailure
}

// execWhenNotLeader re-execs the current binary from the calling goroutine's
// thread if it is not the thread group leader. Otherwise it parks itself,
// keeping the leader thread pinned, and hands off to a new goroutine, which
// the runtime must schedule on a different thread.
func execWhenNotLeader(errCh chan error) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		go execWhenNotLeader(errCh)
		select {} // Hold the leader thread parked until the exec.
	}
	errCh <- unix.Exec("/proc/self/exe", []string{os.Args[0], "exec-from-thread"}, os.Environ())
}
