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

package sandboxsetup

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/starttime"
)

// SetCapsAndCallSelf sets capabilities to the current thread and then
// execve's itself again with the arguments specified in 'args' to restart
// the process with the desired capabilities.
func SetCapsAndCallSelf(args []string, caps *specs.LinuxCapabilities) error {
	// Keep thread locked while capabilities are changed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ApplyCaps(caps); err != nil {
		return fmt.Errorf("ApplyCaps() failed: %v", err)
	}
	binPath := specutils.ExePath

	log.Infof("Execve %q again, bye!", binPath)
	err := unix.Exec(binPath, args, starttime.AppendEnviron(os.Environ()))
	return fmt.Errorf("error executing %s: %v", binPath, err)
}

// CallSelfAsNobody sets UID and GID to nobody and then execve's itself
// again.
func CallSelfAsNobody(args []string) error {
	// Keep thread locked while user/group are changed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const nobody = 65534

	if _, _, err := unix.RawSyscall(unix.SYS_SETGID, uintptr(nobody), 0, 0); err != 0 {
		return fmt.Errorf("error setting gid: %v", err)
	}
	if _, _, err := unix.RawSyscall(unix.SYS_SETUID, uintptr(nobody), 0, 0); err != 0 {
		return fmt.Errorf("error setting uid: %v", err)
	}
	// Drop all capabilities.
	if err := ApplyCaps(&specs.LinuxCapabilities{}); err != nil {
		return fmt.Errorf("error dropping capabilities: %w", err)
	}

	binPath := specutils.ExePath

	log.Infof("Execve %q again, bye!", binPath)
	err := unix.Exec(binPath, args, starttime.AppendEnviron(os.Environ()))
	return fmt.Errorf("error executing %s: %v", binPath, err)
}

// PrepareArgs returns the args that can be used to re-execute the current
// program. It manipulates the flags of the subcommand identified by
// subCmdName and fSet is the flag.FlagSet of this subcommand. It applies
// the flags specified by override map. In case of conflict, flag is
// overridden.
//
// Postcondition: PrepareArgs() takes ownership of override map.
func PrepareArgs(subCmdName string, fSet *flag.FlagSet, override map[string]string) []string {
	var args []string
	// Add all args up until (and including) the sub command.
	for _, arg := range os.Args {
		args = append(args, arg)
		if arg == subCmdName {
			break
		}
	}
	// Set sub command flags. Iterate through all the explicitly set flags.
	fSet.Visit(func(gf *flag.Flag) {
		// If a conflict is found with override, then prefer override
		// flag.
		if ov, ok := override[gf.Name]; ok {
			args = append(args, fmt.Sprintf("--%s=%s", gf.Name, ov))
			delete(override, gf.Name)
			return
		}
		// Otherwise pass through the original flag.
		args = append(args, fmt.Sprintf("--%s=%s", gf.Name, gf.Value))
	})
	// Apply remaining override flags (that didn't conflict above).
	for of, ov := range override {
		args = append(args, fmt.Sprintf("--%s=%s", of, ov))
	}
	// Add the non-flag arguments at the end.
	args = append(args, fSet.Args()...)
	return args
}

// ExecProcUmounter executes a child process that umounts /proc when the
// returned pipe is closed.
func ExecProcUmounter() (*exec.Cmd, *os.File) {
	r, w, err := os.Pipe()
	if err != nil {
		util.Fatalf("error creating a pipe: %v", err)
	}
	defer r.Close()

	cmd := exec.Command(specutils.ExePath)
	cmd.Args = append(cmd.Args, "umount", "--sync-fd=3", "/proc")
	cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		util.Fatalf("error executing umounter: %v", err)
	}
	return cmd, w
}

// UmountProc writes to syncFD signalling the process started by
// ExecProcUmounter() to umount /proc.
func UmountProc(syncFD int) {
	syncFile := os.NewFile(uintptr(syncFD), "procfs umount sync FD")
	buf := make([]byte, 1)
	if w, err := syncFile.Write(buf); err != nil || w != 1 {
		util.Fatalf("unable to write into the proc umounter descriptor: %v", err)
	}
	syncFile.Close()

	var waitStatus unix.WaitStatus
	if _, err := unix.Wait4(0, &waitStatus, 0, nil); err != nil {
		util.Fatalf("error waiting for the proc umounter process: %v", err)
	}
	if !waitStatus.Exited() || waitStatus.ExitStatus() != 0 {
		util.Fatalf("the proc umounter process failed: %v", waitStatus)
	}
	if err := unix.Access("/proc/self", unix.F_OK); err != unix.ENOENT {
		util.Fatalf("/proc is still accessible")
	}
}
