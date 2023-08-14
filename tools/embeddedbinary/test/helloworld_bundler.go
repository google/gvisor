// Copyright 2023 The gVisor Authors.
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

// helloworld_bundler bundles helloworld_bundlee and executes it.
package main

import (
	"fmt"
	"os"

	syscall "golang.org/x/sys/unix"
	"gvisor.dev/gvisor/tools/embeddedbinary/test/helloworld"
)

func doExec() {
	if err := helloworld.Exec(helloworld.Options{}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to exec embedded binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Unreachable\n")
	os.Exit(1)
}

func doForkExec() {
	childPID, err := helloworld.ForkExec(helloworld.Options{
		// Share stdin/stdout/stderr with child process.
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fork+exec embedded binary: %v\n", err)
		os.Exit(1)
	}
	var waitStatus syscall.WaitStatus
	if _, err := syscall.Wait4(childPID, &waitStatus, 0, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to wait for child embedded binary: %v\n", err)
		os.Exit(1)
	}
	if status := waitStatus.ExitStatus(); status != 0 {
		fmt.Fprintf(os.Stderr, "Child embedded binary returned code %d\n", status)
		os.Exit(status)
	}
	os.Exit(0)
}

func main() {
	for _, arg := range os.Args {
		switch arg {
		case "--mode=exec":
			doExec()
		case "--mode=fork":
			doForkExec()
		}
	}
	fmt.Fprintf(os.Stderr, "Must specify either --mode=exec or --mode=fork.\n")
	os.Exit(1)
}
