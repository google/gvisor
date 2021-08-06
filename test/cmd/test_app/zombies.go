// Copyright 2021 The gVisor Authors.
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
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	sys "syscall"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

func fatalf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	os.Exit(1)
}

// zombieTest creates an orphaned process that will be reparented to PID 1
// (or the nearest subreaper) and expect that it is reaped.
//
// The setup involves three different processes:
//
// 1. The zombiemonitor process starts the zombieparent process and reads the
// zombiechild process pid from zombieparent's stdout. It waits on
// zombieparent, and after that dies, zombiechild will be reparented to PID 1
// (or nearest subreaper).  The zombiemonitor kills zombiechild and expects
// that it will be reaped.
//
// 2. The zombieparent process starts the zombiechild process, writes the
// zombiechild process pid to stdout, and exits, causing zombiechild to be
// reparented to PID 1 (or nearest subreaper).
//
// 3. zombiechild just waits until it is killed.
type zombieTest struct{}

// Name implements subcommands.Command.Name.
func (*zombieTest) Name() string {
	return "zombie_test"
}

// Synopsis implements subcommands.Command.Synopsys.
func (*zombieTest) Synopsis() string {
	return "creates an orphaned grandchild and expects to be reparented and reaped."
}

// Usage implements subcommands.Command.Usage.
func (*zombieTest) Usage() string {
	return "Usage: zombie_test [zombieparent|zombiechild]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*zombieTest) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (zt *zombieTest) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	n := f.NArg()
	if n > 1 {
		log.Fatal(zt.Usage())
	}
	if n == 0 {
		// Run the monitor, which is the main entrypoint of this program.
		runOrphanMonitor()
		return subcommands.ExitSuccess
	}
	// One argument passed
	switch f.Arg(0) {
	case "zombieparent":
		runZombieParent()
	case "zombiechild":
		runZombieChild()
	default:
		log.Fatal(zt.Usage())
	}

	return subcommands.ExitSuccess
}

func runOrphanMonitor() {
	// Start the zombieparent and read its output. The call to
	// CombinedOutput() will wait() on zombieparent, so when it returns we
	// know that zombiechild has been orphaned and reparented to PID 1.
	cmd := exec.Command("/proc/self/exe", "zombie_test", "zombieparent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("failed to exec zombieparent: %v\noutput: %s\n", err, string(out))
	}

	// Parse zombiechild pid from zombieparent output.
	zombieChildPid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		log.Fatalf("failed to parse zombieparent output: %q", string(out))
	}
	fmt.Printf("started zombiechild with pid %d\n", zombieChildPid)

	// Kill the zombiechild.
	fmt.Printf("killing zombiechild\n")
	if err := unix.Kill(zombieChildPid, unix.SIGTERM); err != nil {
		log.Fatalf("error killing for zombiechild: %v", err)
	}

	// Wait for zombiechild to be reaped by PID 1.
	if err := waitForZombieReaped(zombieChildPid, 10*time.Second); err != nil {
		log.Fatalf("error waiting for zombiechild to be reaped: %v", err)
	}
	fmt.Printf("zombiechild has been reaped\n")

	// Success.
}

func runZombieParent() {
	// Start the zombiechild, and write the pid to stdout.
	cmd := exec.Command("/proc/self/exe", "zombie_test", "zombiechild")
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to exec zombiechild: %v", err)
	}
	fmt.Fprint(os.Stdout, strconv.Itoa(cmd.Process.Pid))

	// Die. This will cause zombiechild to be reparented.
}

func runZombieChild() {
	// Sleep for a long time. We will be killed before this exits.
	time.Sleep(1 * time.Minute)
}

// waitForZombieReaped sends a harmless signal to the given pid until it gets
// ESRCH, indicating that the process has been reaped, or until the timeout is
// reached.
func waitForZombieReaped(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("pid %d was not reaped after %v", pid, timeout)
		}

		err := unix.Kill(pid, 0)
		if err == nil {
			fmt.Printf("pid %d still exists\n", pid)
			time.Sleep(1 * time.Second)
			continue
		}
		if errno := err.(sys.Errno); errno != unix.ESRCH {
			return fmt.Errorf("unexpected error signalling pid %d: %v", pid, err)
		}
		fmt.Printf("pid %d has been reaped\n", pid)
		return nil
	}
}
