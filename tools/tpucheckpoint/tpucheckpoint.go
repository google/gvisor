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
// against unsandboxed processes. It discovers the libtpu control threads
// of each target PID by scanning /proc/<pid>/task/*/comm, opens the
// encoded pipe FDs via /proc/<pid>/fd/, and sends ControlRequest messages.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/tools/tpucheckpoint/tpucontrol"
)

func usage() {
	fmt.Fprintf(os.Stderr, `tpucheckpoint: checkpoint and restore the TPU state of processes.

Discovers libtpu control pipes by scanning thread names in /proc/<pid>/task/,
then sends control messages using the tpu_control protocol.

Operations:
  --action checkpoint | restore   --pid <pid>[,<pid>...] [--timeout <seconds>]
        Checkpoint or restore the TPU runtime state of the given PIDs.
        Multiple PIDs are processed concurrently.

  --get-state --pid <pid>[,<pid>...]
        Print the current TPU runtime state of the given PIDs.

Options:
  --pid|-p <pid>[,<pid>...]   Target process PIDs, comma-separated.
  --timeout|-t <seconds>      Per-process operation timeout in seconds (default: 180).
  --help|-h                   Print this help message.

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

// report prints per-PID results and returns false if any operation failed.
// line renders the success output for one result; for a single PID the
// "pid N: " prefix is omitted, keeping the original single-PID output.
func report(results []tpucontrol.Result, line func(r tpucontrol.Result) string) bool {
	ok := true
	for _, r := range results {
		if r.Err != nil {
			ok = false
			fmt.Fprintf(os.Stderr, "tpucheckpoint: pid %d: %v\n", r.PID, r.Err)
			continue
		}
		if len(results) == 1 {
			fmt.Println(line(r))
		} else {
			fmt.Printf("pid %d: %s\n", r.PID, line(r))
		}
	}
	return ok
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	var (
		pids       []int
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
			if pids != nil {
				fatal("--pid may be specified only once; use a comma-separated list")
			}
			var err error
			pids, err = tpucontrol.ParsePIDs(args[i])
			if err != nil {
				fatal("%v", err)
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

	if len(pids) == 0 {
		fatal("--pid is required")
	}

	var ok bool
	switch {
	case getState:
		ok = report(tpucontrol.GetState(pids, timeoutSec), func(r tpucontrol.Result) string {
			return r.State.String()
		})

	case action == "checkpoint":
		ok = report(tpucontrol.Checkpoint(pids, timeoutSec), func(r tpucontrol.Result) string {
			return fmt.Sprintf("checkpoint complete (%.3fs)", r.Duration.Seconds())
		})

	case action == "restore":
		ok = report(tpucontrol.Restore(pids, timeoutSec), func(r tpucontrol.Result) string {
			return fmt.Sprintf("restore complete (%.3fs)", r.Duration.Seconds())
		})

	case action != "":
		fatal("unknown action: %s (supported: checkpoint, restore)", action)

	default:
		fatal("no operation specified (use --action checkpoint|restore or --get-state)\nrun 'tpucheckpoint --help' for usage")
	}

	if !ok {
		os.Exit(1)
	}
}
