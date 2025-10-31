// Copyright 2024 The gVisor Authors.
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

// Package main sets up the ioctl sniffer and runs a given command.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/tools/ioctl_sniffer/sniffer"

	_ "embed" // Necessary to use go:embed.
)

var (
	enforceCompatibility = flag.String("enforce_compatibility", "", "May be set to 'INSTANT' or 'REPORT'. If set, the sniffer will return a non-zero error code if it detects an unsupported ioctl. 'INSTANT' causes the sniffer to exit immediately when this happens. 'REPORT' causes the sniffer to report all unsupported ioctls at the end of execution.")
	verbose              = flag.Bool("verbose", false, "If true, the sniffer will print all Nvidia ioctls it sees.")
	addLdPath            = flag.String("add_ld_path", "", "If set, reconfigure the ld cache to include the given directory")
	seccompMode          = flag.Bool("seccomp", true, "If true, seccomp is used to trace ioctl system calls.")
)

//go:embed libioctl_hook.so
var ioctlHookSharedObject []byte

// createSharedObject creates a temporary directory containing the ioctl hook
// shared object, and returns the path to it. This file will be automatically
// deleted when the program exits.
func createSharedObject() (*os.File, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "libioctl_hook.*.so")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	// Remove the file from the filesystem but keep a handle open to it
	// so that it lasts only as long as the program does.
	if err := os.Remove(tmpFile.Name()); err != nil {
		return nil, fmt.Errorf("failed to unlink temporary file: %w", err)
	}
	if _, err := tmpFile.Write(ioctlHookSharedObject); err != nil {
		return nil, fmt.Errorf("failed to write to temporary file: %w", err)
	}
	return tmpFile, nil
}

// Main is our main function.
func Main(ctx context.Context) error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("no command specified")
	}

	if *enforceCompatibility != "" && *enforceCompatibility != "INSTANT" && *enforceCompatibility != "REPORT" {
		return fmt.Errorf("invalid value for --enforce_compatibility: %q", *enforceCompatibility)
	}

	if *verbose {
		log.SetLevel(log.Debug)
	}

	if *addLdPath != "" {
		if err := addPathToLd(ctx, *addLdPath); err != nil {
			return fmt.Errorf("failed to add path %q to ld: %w", *addLdPath, err)
		}
	}

	// Init our sniffer
	if err := sniffer.Init(); err != nil {
		return fmt.Errorf("failed to init sniffer: %w", err)
	}

	hookFile, err := createSharedObject()
	if err != nil {
		return fmt.Errorf("failed to create shared object file: %w", err)
	}
	defer func() {
		if err := hookFile.Close(); err != nil {
			log.Warningf("failed to close shared object file: %w", err)
		}
	}()

	// Start the sniffer server.
	server := sniffer.NewServer()
	if err := server.Listen(); err != nil {
		return fmt.Errorf("failed to start sniffer server: %w", err)
	}

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() {
		if err := server.Serve(serveCtx); err != nil {
			log.Warningf("failed to serve sniffer server: %w", err)
		}
	}()

	seccompResults := sniffer.NewResults()
	if *seccompMode {
		// All ioctl-s to notifyFD are not traced, because it is used to
		// recv seccomp notification request via ioctl-s. That can be
		// fixed if seccomp rules will be installed just for a target
		// process.
		const notifyFD = 888

		options := seccomp.ProgramOptions{
			DefaultAction:    linux.SECCOMP_RET_ALLOW,
			LogNotifications: true,
			NotificationCallback: func(f *os.File, req linux.SeccompNotif, ret int) {
				sniffer.ServeSeccompRequest(seccompResults, req, ret)
			},
			NotifyFDNum: notifyFD,
		}
		instrs, _, err := seccomp.BuildProgram([]seccomp.RuleSet{
			{
				Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
					unix.SYS_IOCTL: seccomp.PerArg{
						seccomp.NotEqual(notifyFD),
					},
				}),
				Action: linux.SECCOMP_RET_USER_NOTIF,
			},
		},
			options,
		)
		if err != nil {
			return err
		}
		if err := seccomp.SetFilterAndLogNotifications(instrs, options); err != nil {
			return fmt.Errorf("failed to set filter: %v", err)
		}
	}

	// Set up command from flags
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if !*seccompMode {
		// Refer to the hook file by file descriptor here as its named file no
		// longer exists.
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("LD_PRELOAD=/proc/%d/fd/%d", os.Getpid(), hookFile.Fd()),
			fmt.Sprintf("GVISOR_IOCTL_SNIFFER_SOCKET_PATH=%v", server.Addr()),
			fmt.Sprintf("GVISOR_IOCTL_SNIFFER_ENFORCE_COMPATIBILITY=%s", *enforceCompatibility))
	}

	go func() {
		time.Sleep(600 * time.Second)
		panic("timeout")
	}()
	// Run the command and start reading the output.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to run command: %w", err)
	}

waitLoop:
	for {
		var info unix.Siginfo
		errno := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, syscall.WEXITED|syscall.WNOWAIT, nil)
		if errno == syscall.EINTR {
			continue
		} else if errno != nil {
			return fmt.Errorf("failed to wait for the child process: %v", errno)
		}
		switch info.Code {
		case linux.CLD_EXITED, linux.CLD_KILLED, linux.CLD_DUMPED:
			break waitLoop
		}
	}

	// Once our command is done, we can close the sniffer server and print the
	// results.
	cmdErr := cmd.Wait()
	serveCancel()

	// Merge results from each connection.
	finalResults := server.AllResults()
	finalResults.Merge(seccompResults)
	if finalResults.HasUnsupportedIoctl() {
		if *enforceCompatibility != "" {
			return fmt.Errorf("unsupported ioctls found: %v", finalResults)
		}
		log.Infof("============== Unsupported ioctls ==============")
		log.Infof("%v", finalResults)
	}

	if cmdErr != nil {
		return fmt.Errorf("command exited with error: %w", cmdErr)
	}

	return nil
}

func main() {
	ctx := context.Background()
	if err := Main(ctx); err != nil {
		log.Warningf("%v", err)
		os.Exit(1)
	}
}
