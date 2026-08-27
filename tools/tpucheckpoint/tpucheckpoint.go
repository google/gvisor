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

// tpucheckpoint drives the libtpu checkpoint/restore control protocol
// against an unsandboxed process. It discovers the libtpu control threads
// of a target PID by scanning /proc/<pid>/task/*/comm, opens the encoded
// pipe FDs via /proc/<pid>/fd/, and sends ControlRequest messages.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/tools/tpucheckpoint/tpucontrol"
)

func usage() {
	fmt.Fprintf(os.Stderr, `tpucheckpoint: checkpoint and restore the TPU state of a process.

Discovers libtpu control pipes by scanning thread names in /proc/<pid>/task/,
then sends control messages using the tpu_control protocol.

Operations:
  --action checkpoint | restore   --pid <pid> [--timeout <seconds>]
        Checkpoint or restore the TPU runtime state of <pid>.

  --get-state --pid <pid>
        Print the current TPU runtime state.

Options:
  --pid|-p <pid>           Target process PID.
  --timeout|-t <seconds>   Operation timeout in seconds (default: 180).
  --help|-h                Print this help message.

Discovery:
  Scans /proc/<pid>/task/*/comm for threads named "libtpu{XXXXYYYY}".
  The 8-character hex suffix encodes the request/response pipe FD numbers.
  Pipes are accessed via /proc/<pid>/fd/<N>, which requires ptrace-level
  access to the target (same user or CAP_SYS_PTRACE).
`)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tpucheckpoint: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	var (
		pid        = -1
		action     string
		getState   bool
		timeoutSec = 180
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--help", "-h":
			usage()
			os.Exit(0)
		case "--pid", "-p":
			i++
			if i >= len(args) {
				fatal("--pid requires a value")
			}
			var err error
			pid, err = strconv.Atoi(args[i])
			if err != nil || pid <= 0 {
				fatal("invalid PID: %s", args[i])
			}
		case "--action":
			i++
			if i >= len(args) {
				fatal("--action requires a value")
			}
			action = strings.ToLower(args[i])
		case "--get-state":
			getState = true
		case "--timeout", "-t":
			i++
			if i >= len(args) {
				fatal("--timeout requires a value")
			}
			var err error
			timeoutSec, err = strconv.Atoi(args[i])
			if err != nil || timeoutSec <= 0 {
				fatal("invalid timeout: %s", args[i])
			}
		default:
			fatal("unknown option: %s\nrun 'tpucheckpoint --help' for usage", args[i])
		}
	}

	if pid <= 0 {
		fatal("--pid is required")
	}

	switch {
	case getState:
		state, err := tpucontrol.GetState(pid, timeoutSec)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(state)

	case action == "checkpoint":
		start := time.Now()
		if err := tpucontrol.Checkpoint(pid, timeoutSec); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("checkpoint complete (%.3fs)\n", time.Since(start).Seconds())

	case action == "restore":
		start := time.Now()
		if err := tpucontrol.Restore(pid, timeoutSec); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("restore complete (%.3fs)\n", time.Since(start).Seconds())

	case action != "":
		fatal("unknown action: %s (supported: checkpoint, restore)", action)

	default:
		fatal("no operation specified (use --action checkpoint|restore or --get-state)\nrun 'tpucheckpoint --help' for usage")
	}
}
