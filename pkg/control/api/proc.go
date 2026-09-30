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

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/urpc"
)

// FilePayload aids to ensure that payload files and guest file descriptors are
// consistent when instantiated through the NewFilePayload helper method.
type FilePayload struct {
	// FilePayload is the file payload that is transferred via RPC.
	urpc.FilePayload

	// GuestFDs are the file descriptors in the file descriptor map of the
	// executed application. They correspond 1:1 to the files in the
	// urpc.FilePayload. If a program is executed from a host file descriptor,
	// the file payload may contain one additional file. In that case, the file
	// used for program execution is the last file in the Files array.
	GuestFDs []int
}

// NewFilePayload returns a FilePayload that maps file descriptors to files inside
// the executed process and provides a file for execution.
func NewFilePayload(fdMap map[int]*os.File, execFile *os.File) FilePayload {
	fileCount := len(fdMap)
	if execFile != nil {
		fileCount++
	}
	files := make([]*os.File, 0, fileCount)
	guestFDs := make([]int, 0, len(fdMap))

	// Make the map iteration order deterministic for the sake of testing.
	// Otherwise, the order is randomized and tests relying on the comparison
	// of equality will fail.
	for key := range fdMap {
		guestFDs = append(guestFDs, key)
	}
	sort.Ints(guestFDs)

	for _, guestFD := range guestFDs {
		files = append(files, fdMap[guestFD])
	}

	if execFile != nil {
		files = append(files, execFile)
	}

	return FilePayload{
		FilePayload: urpc.FilePayload{Files: files},
		GuestFDs:    guestFDs,
	}
}

// ExecArgs is the set of arguments to exec.
type ExecArgs struct {
	// Filename is the filename to load.
	//
	// If this is provided as "", then the file will be guessed via Argv[0].
	Filename string `json:"filename"`

	// Argv is a list of arguments.
	Argv []string `json:"argv"`

	// Envv is a list of environment variables.
	Envv []string `json:"envv"`

	// WorkingDirectory defines the working directory for the new process.
	WorkingDirectory string `json:"wd"`

	// KUID is the UID to run with in the root user namespace. Defaults to
	// root if not set explicitly.
	KUID auth.KUID

	// KGID is the GID to run with in the root user namespace. Defaults to
	// the root group if not set explicitly.
	KGID auth.KGID

	// ExtraKGIDs is the list of additional groups to which the user belongs.
	ExtraKGIDs []auth.KGID

	// NoNewPrivileges disallows the new process from acquiring new privileges.
	NoNewPrivileges bool

	// Capabilities is the list of capabilities to give to the process.
	Capabilities *auth.TaskCapabilities

	// StdioIsPty indicates that FDs 0, 1, and 2 are connected to a host pty FD.
	StdioIsPty bool

	// SupportTTYs indicates whether TTYs other than the console TTY should be
	// imported as TTYs.
	SupportTTYs bool

	// FilePayload determines the files to give to the new process.
	FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string
}

// String prints the arguments as a string.
func (args *ExecArgs) String() string {
	if len(args.Argv) == 0 {
		return args.Filename
	}
	a := make([]string, len(args.Argv))
	copy(a, args.Argv)
	if args.Filename != "" {
		a[0] = args.Filename
	}
	return strings.Join(a, " ")
}

// Process contains information about a single process in a Sandbox.
type Process struct {
	UID auth.KUID `json:"uid"`
	PID int32     `json:"pid"`
	// Parent PID
	PPID int32 `json:"ppid"`
	// Process Group ID
	PGID    int32   `json:"pgid"`
	Threads []int32 `json:"threads"`
	// Processor utilization
	C int32 `json:"c"`
	// TTY name of the process. Will be of the form "pts/N" if there is a
	// TTY, or "?" if there is not.
	TTY string `json:"tty"`
	// Start time
	STime string `json:"stime"`
	// CPU time
	Time string `json:"time"`
	// Executable shortname (e.g. "sh" for /bin/sh)
	Cmd string `json:"cmd"`
}

// ProcessListToTable prints a table with the following format:
// UID       PID       PPID      PGID      C         TTY       STIME     TIME       CMD
// 0         1         0         1         0         pty/4     14:04     505262ns   tail
func ProcessListToTable(pl []*Process) string {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 10, 1, 3, ' ', 0)
	fmt.Fprint(tw, "UID\tPID\tPPID\tPGID\tC\tTTY\tSTIME\tTIME\tCMD")
	for _, d := range pl {
		fmt.Fprintf(tw, "\n%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s",
			d.UID,
			d.PID,
			d.PPID,
			d.PGID,
			d.C,
			d.TTY,
			d.STime,
			d.Time,
			d.Cmd)
	}
	tw.Flush()
	return buf.String()
}

// ProcessListToJSON will return the JSON representation of ps.
func ProcessListToJSON(pl []*Process) (string, error) {
	b, err := json.MarshalIndent(pl, "", "  ")
	if err != nil {
		return "", fmt.Errorf("couldn't marshal process list %v: %v", pl, err)
	}
	return string(b), nil
}

// PrintPIDsJSON prints a JSON object containing only the PIDs in pl. This
// behavior is the same as runc's.
func PrintPIDsJSON(pl []*Process) (string, error) {
	pids := make([]int32, 0, len(pl))
	for _, d := range pl {
		pids = append(pids, d.PID)
	}
	b, err := json.Marshal(pids)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal PIDs %v: %v", pids, err)
	}
	return string(b), nil
}
