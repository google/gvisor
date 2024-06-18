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
)

var ldPreloadPath = flag.String("ld_preload", "./libioctl_hook.so", "The path to the LD_PRELOAD library.")

// Main is our main function.
func Main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Init our sniffer
	if err := sniffer.Init(); err != nil {
		return fmt.Errorf("failed to init sniffer: %w", err)
	}

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
	cmd.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=%s", *ldPreloadPath))

	// Run the command and start reading the output.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to run command: %w", err)
	}

	w.Close()
	results := sniffer.ReadHookOutput(r)

	// Once we've read all the output, print the list of missing ioctls.
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
