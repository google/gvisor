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

package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/fdimport"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	hostvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Proc includes task-related functions.
//
// At the moment, this is limited to exec support.
type Proc struct {
	Kernel *kernel.Kernel
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

	// MountNamespace is the mount namespace to execute the new process in.
	// A reference on MountNamespace must be held for the lifetime of the
	// ExecArgs. If MountNamespace is nil, it will default to the init
	// process's MountNamespace.
	MountNamespace *fs.MountNamespace

	// MountNamespaceVFS2 is the mount namespace to execute the new process in.
	// A reference on MountNamespace must be held for the lifetime of the
	// ExecArgs. If MountNamespace is nil, it will default to the init
	// process's MountNamespace.
	MountNamespaceVFS2 *vfs.MountNamespace

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

	// Capabilities is the list of capabilities to give to the process.
	Capabilities *auth.TaskCapabilities

	// StdioIsPty indicates that FDs 0, 1, and 2 are connected to a host pty FD.
	StdioIsPty bool

	// FilePayload determines the files to give to the new process.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string

	// PIDNamespace is the pid namespace for the process being executed.
	PIDNamespace *kernel.PIDNamespace
}

// String prints the arguments as a string.
func (args ExecArgs) String() string {
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

// Exec runs a new task.
func (proc *Proc) Exec(args *ExecArgs, waitStatus *uint32) error {
	newTG, _, _, _, err := proc.execAsync(args)
	if err != nil {
		return err
	}

	// Wait for completion.
	newTG.WaitExited()
	*waitStatus = newTG.ExitStatus().Status()
	return nil
}

// ExecAsync runs a new task, but doesn't wait for it to finish. It is defined
// as a function rather than a method to avoid exposing execAsync as an RPC.
func ExecAsync(proc *Proc, args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	return proc.execAsync(args)
}

// execAsync runs a new task, but doesn't wait for it to finish. It returns the
// newly created thread group and its PID. If the stdio FDs are TTYs, then a
// TTYFileOperations that wraps the TTY is also returned.
func (proc *Proc) execAsync(args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	// Import file descriptors.
	fdTable := proc.Kernel.NewFDTable()

	creds := auth.NewUserCredentials(
		args.KUID,
		args.KGID,
		args.ExtraKGIDs,
		args.Capabilities,
		proc.Kernel.RootUserNamespace())

	initArgs := kernel.CreateProcessArgs{
		Filename:                args.Filename,
		Argv:                    args.Argv,
		Envv:                    args.Envv,
		WorkingDirectory:        args.WorkingDirectory,
		MountNamespace:          args.MountNamespace,
		MountNamespaceVFS2:      args.MountNamespaceVFS2,
		Credentials:             creds,
		FDTable:                 fdTable,
		Umask:                   0022,
		Limits:                  limits.NewLimitSet(),
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            proc.Kernel.RootUTSNamespace(),
		IPCNamespace:            proc.Kernel.RootIPCNamespace(),
		AbstractSocketNamespace: proc.Kernel.RootAbstractSocketNamespace(),
		ContainerID:             args.ContainerID,
		PIDNamespace:            args.PIDNamespace,
	}
	if initArgs.MountNamespace != nil {
		// initArgs must hold a reference on MountNamespace, which will
		// be donated to the new process in CreateProcess.
		initArgs.MountNamespace.IncRef()
	}
	if initArgs.MountNamespaceVFS2 != nil {
		// initArgs must hold a reference on MountNamespaceVFS2, which will
		// be donated to the new process in CreateProcess.
		initArgs.MountNamespaceVFS2.IncRef()
	}
	ctx := initArgs.NewContext(proc.Kernel)
	defer fdTable.DecRef(ctx)

	if kernel.VFS2Enabled {
		// Get the full path to the filename from the PATH env variable.
		if initArgs.MountNamespaceVFS2 == nil {
			// Set initArgs so that 'ctx' returns the namespace.
			//
			// Add a reference to the namespace, which is transferred to the new process.
			initArgs.MountNamespaceVFS2 = proc.Kernel.GlobalInit().Leader().MountNamespaceVFS2()
			initArgs.MountNamespaceVFS2.IncRef()
		}
	} else {
		if initArgs.MountNamespace == nil {
			// Set initArgs so that 'ctx' returns the namespace.
			initArgs.MountNamespace = proc.Kernel.GlobalInit().Leader().MountNamespace()

			// initArgs must hold a reference on MountNamespace, which will
			// be donated to the new process in CreateProcess.
			initArgs.MountNamespace.IncRef()
		}
	}
	resolved, err := user.ResolveExecutablePath(ctx, &initArgs)
	if err != nil {
		return nil, 0, nil, nil, err
	}
	initArgs.Filename = resolved

	fds, err := fd.NewFromFiles(args.Files)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("duplicating payload files: %w", err)
	}
	defer func() {
		for _, fd := range fds {
			_ = fd.Close()
		}
	}()
	ttyFile, ttyFileVFS2, err := fdimport.Import(ctx, fdTable, args.StdioIsPty, fds)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	tg, tid, err := proc.Kernel.CreateProcess(initArgs)
	if err != nil {
		return nil, 0, nil, nil, err
	}

	// Set the foreground process group on the TTY before starting the process.
	switch {
	case ttyFile != nil:
		ttyFile.InitForegroundProcessGroup(tg.ProcessGroup())
	case ttyFileVFS2 != nil:
		ttyFileVFS2.InitForegroundProcessGroup(tg.ProcessGroup())
	}

	// Start the newly created process.
	proc.Kernel.StartProcess(tg, nil /* run */)

	return tg, tid, ttyFile, ttyFileVFS2, nil
}

// PsArgs is the set of arguments to ps.
type PsArgs struct {
	// JSON will force calls to Ps to return the result as a JSON payload.
	JSON bool
}

// Ps provides a process listing for the running kernel.
func (proc *Proc) Ps(args *PsArgs, out *string) error {
	var p []*Process
	if e := Processes(proc.Kernel, "", &p); e != nil {
		return e
	}
	if !args.JSON {
		*out = ProcessListToTable(p)
	} else {
		s, e := ProcessListToJSON(p)
		if e != nil {
			return e
		}
		*out = s
	}
	return nil
}

// Process contains information about a single process in a Sandbox.
type Process struct {
	UID auth.KUID       `json:"uid"`
	PID kernel.ThreadID `json:"pid"`
	// Parent PID
	PPID    kernel.ThreadID   `json:"ppid"`
	Threads []kernel.ThreadID `json:"threads"`
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
// UID       PID       PPID      C         TTY		STIME     TIME       CMD
// 0         1         0         0         pty/4	14:04     505262ns   tail
func ProcessListToTable(pl []*Process) string {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 10, 1, 3, ' ', 0)
	fmt.Fprint(tw, "UID\tPID\tPPID\tC\tTTY\tSTIME\tTIME\tCMD")
	for _, d := range pl {
		fmt.Fprintf(tw, "\n%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s",
			d.UID,
			d.PID,
			d.PPID,
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
	pids := make([]kernel.ThreadID, 0, len(pl))
	for _, d := range pl {
		pids = append(pids, d.PID)
	}
	b, err := json.Marshal(pids)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal PIDs %v: %v", pids, err)
	}
	return string(b), nil
}

// Processes retrieves information about processes running in the sandbox with
// the given container id. All processes are returned if 'containerID' is empty.
func Processes(k *kernel.Kernel, containerID string, out *[]*Process) error {
	ts := k.TaskSet()
	now := k.RealtimeClock().Now()
	for _, tg := range ts.Root.ThreadGroups() {
		pidns := tg.PIDNamespace()
		pid := pidns.IDOfThreadGroup(tg)

		// If tg has already been reaped ignore it.
		if pid == 0 {
			continue
		}
		if containerID != "" && containerID != tg.Leader().ContainerID() {
			continue
		}

		ppid := kernel.ThreadID(0)
		if p := tg.Leader().Parent(); p != nil {
			ppid = pidns.IDOfThreadGroup(p.ThreadGroup())
		}
		threads := tg.MemberIDs(pidns)
		*out = append(*out, &Process{
			UID:     tg.Leader().Credentials().EffectiveKUID,
			PID:     pid,
			PPID:    ppid,
			Threads: threads,
			STime:   formatStartTime(now, tg.Leader().StartTime()),
			C:       percentCPU(tg.CPUStats(), tg.Leader().StartTime(), now),
			Time:    tg.CPUStats().SysTime.String(),
			Cmd:     tg.Leader().Name(),
			TTY:     ttyName(tg.TTY()),
		})
	}
	sort.Slice(*out, func(i, j int) bool { return (*out)[i].PID < (*out)[j].PID })
	return nil
}

// formatStartTime formats startTime depending on the current time:
// - If startTime was today, HH:MM is used.
// - If startTime was not today but was this year, MonDD is used (e.g. Jan02)
// - If startTime was not this year, the year is used.
func formatStartTime(now, startTime ktime.Time) string {
	nowS, nowNs := now.Unix()
	n := time.Unix(nowS, nowNs)
	startTimeS, startTimeNs := startTime.Unix()
	st := time.Unix(startTimeS, startTimeNs)
	format := "15:04"
	if st.YearDay() != n.YearDay() {
		format = "Jan02"
	}
	if st.Year() != n.Year() {
		format = "2006"
	}
	return st.Format(format)
}

func percentCPU(stats usage.CPUStats, startTime, now ktime.Time) int32 {
	// Note: In procps, there is an option to include child CPU stats. As
	// it is disabled by default, we do not include them.
	total := stats.UserTime + stats.SysTime
	lifetime := now.Sub(startTime)
	if lifetime <= 0 {
		return 0
	}
	percentCPU := total * 100 / lifetime
	// Cap at 99% since procps does the same.
	if percentCPU > 99 {
		percentCPU = 99
	}
	return int32(percentCPU)
}

func ttyName(tty *kernel.TTY) string {
	if tty == nil {
		return "?"
	}
	return fmt.Sprintf("pts/%d", tty.Index)
}
