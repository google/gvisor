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
	"flag"
	"fmt"
	"os"
	"os/exec"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/tools/ioctl_sniffer/sniffer"

	_ "embed" // Necessary to use go:embed.
)

var enforceCompatability = flag.Bool("enforce_compatibility", false, "If true, the sniffer will fail if it detects an unsupported ioctl.")
var verbose = flag.Bool("verbose", false, "If true, the sniffer will print all Nvidia ioctls it sees.")

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
func Main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("no command specified")
	}

	if *verbose {
		log.SetLevel(log.Debug)
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

	// Create a pipe to read the output of the command.
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}

	// Set up command from flags
	cmd := exec.Command(flag.Arg(0), flag.Args()[1:]...)
	cmd.ExtraFiles = []*os.File{w}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Refer to the hook file by file descriptor here as its named file no
	// longer exists.
	cmd.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=/proc/%d/fd/%d", os.Getpid(), hookFile.Fd()))

	// Run the command and start reading the output.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to run command: %w", err)
	}

	w.Close()
	results := sniffer.ReadHookOutput(r)

	if *enforceCompatability && results.HasUnsupportedIoctl() {
		return fmt.Errorf("unsupported ioctls found: %v", results)
	}

	// Once we've read all the output, print the list of missing ioctls.
	log.Infof("============== Unsupported ioctls ==============")
	log.Infof("%s", results)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("command exited with error: %w", err)
	}

	return nil
}

func main() {
	if err := Main(); err != nil {
		log.Warningf("%v", err)
		os.Exit(1)
	}
}
