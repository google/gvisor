// Copyright 2018 Google Inc.
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
	"text/tabwriter"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/host"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
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

	// Root defines the root directory for the new process. A reference on
	// Root must be held for the lifetime of the ExecArgs. If Root is nil,
	// it will default to the VFS root.
	Root *fs.Dirent

	// WorkingDirectory defines the working directory for the new process.
	WorkingDirectory string `json:"wd"`

	// KUID is the UID to run with in the root user namespace. Defaults to
	// root if not set explicitly.
	KUID auth.KUID

	// KGID is the GID to run with in the root user namespace. Defaults to
	// the root group if not set explicitly.
	KGID auth.KGID

	// ExtraKGIDs is the list of additional groups to which the user
	// belongs.
	ExtraKGIDs []auth.KGID

	// Capabilities is the list of capabilities to give to the process.
	Capabilities *auth.TaskCapabilities

	// StdioIsPty indicates that FDs 0, 1, and 2 are connected to a host
	// pty FD.
	StdioIsPty bool

	// FilePayload determines the files to give to the new process.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string
}

// Exec runs a new task.
func (proc *Proc) Exec(args *ExecArgs, waitStatus *uint32) error {
	newTG, _, _, err := proc.execAsync(args)
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
func ExecAsync(proc *Proc, args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileOperations, error) {
	return proc.execAsync(args)
}

// execAsync runs a new task, but doesn't wait for it to finish. It returns the
// newly created thread group and its PID. If the stdio FDs are TTYs, then a
// TTYFileOperations that wraps the TTY is also returned.
func (proc *Proc) execAsync(args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileOperations, error) {
	// Import file descriptors.
	l := limits.NewLimitSet()
	fdm := proc.Kernel.NewFDMap()
	defer fdm.DecRef()

	// No matter what happens, we should close all files in the FilePayload
	// before returning. Any files that are imported will be duped.
	defer func() {
		for _, f := range args.FilePayload.Files {
			f.Close()
		}
	}()

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
		Root:                    args.Root,
		Credentials:             creds,
		FDMap:                   fdm,
		Umask:                   0022,
		Limits:                  l,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            proc.Kernel.RootUTSNamespace(),
		IPCNamespace:            proc.Kernel.RootIPCNamespace(),
		AbstractSocketNamespace: proc.Kernel.RootAbstractSocketNamespace(),
		ContainerID:             args.ContainerID,
	}
	if initArgs.Root != nil {
		// initArgs must hold a reference on Root. This ref is dropped
		// in CreateProcess.
		initArgs.Root.IncRef()
	}
	ctx := initArgs.NewContext(proc.Kernel)

	if initArgs.Filename == "" {
		// Get the full path to the filename from the PATH env variable.
		paths := fs.GetPath(initArgs.Envv)
		f, err := proc.Kernel.RootMountNamespace().ResolveExecutablePath(ctx, initArgs.WorkingDirectory, initArgs.Argv[0], paths)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("error finding executable %q in PATH %v: %v", initArgs.Argv[0], paths, err)
		}
		initArgs.Filename = f
	}

	mounter := fs.FileOwnerFromContext(ctx)

	var ttyFile *fs.File
	for appFD, hostFile := range args.FilePayload.Files {
		var appFile *fs.File

		if args.StdioIsPty && appFD < 3 {
			// Import the file as a host TTY file.
			if ttyFile == nil {
				var err error
				appFile, err = host.ImportFile(ctx, int(hostFile.Fd()), mounter, true /* isTTY */)
				if err != nil {
					return nil, 0, nil, err
				}
				defer appFile.DecRef()

				// Remember this in the TTY file, as we will
				// use it for the other stdio FDs.
				ttyFile = appFile
			} else {
				// Re-use the existing TTY file, as all three
				// stdio FDs must point to the same fs.File in
				// order to share TTY state, specifically the
				// foreground process group id.
				appFile = ttyFile
			}
		} else {
			// Import the file as a regular host file.
			var err error
			appFile, err = host.ImportFile(ctx, int(hostFile.Fd()), mounter, false /* isTTY */)
			if err != nil {
				return nil, 0, nil, err
			}
			defer appFile.DecRef()
		}

		// Add the file to the FD map.
		if err := fdm.NewFDAt(kdefs.FD(appFD), appFile, kernel.FDFlags{}, l); err != nil {
			return nil, 0, nil, err
		}
	}

	tg, tid, err := proc.Kernel.CreateProcess(initArgs)
	if err != nil {
		return nil, 0, nil, err
	}

	if ttyFile == nil {
		return tg, tid, nil, nil
	}
	return tg, tid, ttyFile.FileOperations.(*host.TTYFileOperations), nil
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
// TODO: Implement TTY field.
type Process struct {
	UID auth.KUID       `json:"uid"`
	PID kernel.ThreadID `json:"pid"`
	// Parent PID
	PPID kernel.ThreadID `json:"ppid"`
	// Processor utilization
	C int32 `json:"c"`
	// Start time
	STime string `json:"stime"`
	// CPU time
	Time string `json:"time"`
	// Executable shortname (e.g. "sh" for /bin/sh)
	Cmd string `json:"cmd"`
}

// ProcessListToTable prints a table with the following format:
// UID       PID       PPID      C         STIME     TIME       CMD
// 0         1         0         0         14:04     505262ns   tail
func ProcessListToTable(pl []*Process) string {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 10, 1, 3, ' ', 0)
	fmt.Fprint(tw, "UID\tPID\tPPID\tC\tSTIME\tTIME\tCMD")
	for _, d := range pl {
		fmt.Fprintf(tw, "\n%d\t%d\t%d\t%d\t%s\t%s\t%s",
			d.UID,
			d.PID,
			d.PPID,
			d.C,
			d.STime,
			d.Time,
			d.Cmd)
	}
	tw.Flush()
	return buf.String()
}

// ProcessListToJSON will return the JSON representation of ps.
func ProcessListToJSON(pl []*Process) (string, error) {
	b, err := json.Marshal(pl)
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
		pid := ts.Root.IDOfThreadGroup(tg)
		// If tg has already been reaped ignore it.
		if pid == 0 {
			continue
		}
		if containerID != "" && containerID != tg.Leader().ContainerID() {
			continue
		}

		ppid := kernel.ThreadID(0)
		if p := tg.Leader().Parent(); p != nil {
			ppid = ts.Root.IDOfThreadGroup(p.ThreadGroup())
		}
		*out = append(*out, &Process{
			UID:   tg.Leader().Credentials().EffectiveKUID,
			PID:   pid,
			PPID:  ppid,
			STime: formatStartTime(now, tg.Leader().StartTime()),
			C:     percentCPU(tg.CPUStats(), tg.Leader().StartTime(), now),
			Time:  tg.CPUStats().SysTime.String(),
			Cmd:   tg.Leader().Name(),
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
