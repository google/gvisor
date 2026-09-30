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
	"fmt"
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/control/api"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fdimport"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/user"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Proc includes task-related functions.
type Proc struct {
	Kernel *kernel.Kernel
}

// ExecArgs is the set of arguments to exec, extended with sentry-internal
// state that is never sent over the control socket.
type ExecArgs struct {
	api.ExecArgs

	// MountNamespace is the mount namespace to execute the new process in.
	// A reference on MountNamespace must be held for the lifetime of the
	// ExecArgs. If MountNamespace is nil, it will default to the init
	// process's MountNamespace.
	MountNamespace *vfs.MountNamespace

	// If FDTable is not nil, it is the process FD table. If Exec/ExecAsync
	// succeeds, it takes a reference on FDTable.
	FDTable *kernel.FDTable

	// PIDNamespace is the pid namespace for the process being executed.
	PIDNamespace *kernel.PIDNamespace

	// InitialCgroupV2 is the cgroup2 node the process being executed starts
	// in. If nil, it starts in the root cgroup.
	InitialCgroupV2 kernel.Cgroup2

	// CgroupNamespace is the cgroup namespace for the process being executed.
	// If nil, the root cgroup namespace is used. A reference on
	// CgroupNamespace must be held for the lifetime of the ExecArgs.
	CgroupNamespace *kernel.CgroupNamespace

	// Limits is the limit set for the process being executed.
	Limits *limits.LimitSet

	// SeccompProgram is an optional seccomp BPF program to install on the
	// new process.
	SeccompProgram *bpf.Program
}

// Exec runs a new task.
func (proc *Proc) Exec(args *api.ExecArgs, waitStatus *uint32) error {
	newTG, _, _, err := proc.execAsync(&ExecArgs{ExecArgs: *args})
	if err != nil {
		return err
	}

	// Wait for completion.
	newTG.WaitExited()
	*waitStatus = uint32(newTG.ExitStatus())
	return nil
}

// ExecAsync runs a new task, but doesn't wait for it to finish. It is defined
// as a function rather than a method to avoid exposing execAsync as an RPC.
func ExecAsync(proc *Proc, args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileDescription, error) {
	return proc.execAsync(args)
}

// execAsync runs a new task, but doesn't wait for it to finish. It returns the
// newly created thread group and its PID. If the stdio FDs are TTYs, then a
// TTYFileOperations that wraps the TTY is also returned.
func (proc *Proc) execAsync(args *ExecArgs) (*kernel.ThreadGroup, kernel.ThreadID, *host.TTYFileDescription, error) {
	creds := auth.NewUserCredentials(
		args.KUID,
		args.KGID,
		args.ExtraKGIDs,
		args.Capabilities,
		proc.Kernel.RootUserNamespace())

	pidns := args.PIDNamespace
	if pidns == nil {
		pidns = proc.Kernel.RootPIDNamespace()
	}
	limitSet := args.Limits
	if limitSet == nil {
		limitSet = limits.NewLimitSet()
	}
	initArgs := kernel.CreateProcessArgs{
		Filename:             args.Filename,
		Argv:                 args.Argv,
		Envv:                 args.Envv,
		WorkingDirectory:     args.WorkingDirectory,
		MountNamespace:       args.MountNamespace,
		Credentials:          creds,
		NoNewPrivs:           args.NoNewPrivileges,
		Umask:                0022,
		Limits:               limitSet,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         proc.Kernel.RootUTSNamespace(),
		IPCNamespace:         proc.Kernel.RootIPCNamespace(),
		ContainerID:          args.ContainerID,
		PIDNamespace:         pidns,
		InitialCgroupV2:      args.InitialCgroupV2,
		CgroupNamespace:      args.CgroupNamespace,
		Origin:               kernel.OriginExec,
	}
	ctx := initArgs.NewContext(proc.Kernel)

	if initArgs.MountNamespace == nil {
		// Set initArgs so that 'ctx' returns the namespace.
		initArgs.MountNamespace = proc.Kernel.GlobalInitMountNamespace()
		if initArgs.MountNamespace == nil {
			return nil, 0, nil, fmt.Errorf("cannot exec: sandbox has no root mount namespace")
		}
	}
	// initArgs must hold a reference on MountNamespace, which will
	// be donated to the new process in CreateProcess.
	initArgs.MountNamespace.IncRef()
	mntnsCu := cleanup.Make(func() { initArgs.MountNamespace.DecRef(ctx) })
	defer mntnsCu.Clean()

	// Import file descriptors.
	var fdTable *kernel.FDTable
	if args.FDTable != nil {
		fdTable = args.FDTable
		// reference borrowed from the caller
	} else {
		fdTable = proc.Kernel.NewFDTable()
		defer fdTable.DecRef(ctx)
	}
	initArgs.FDTable = fdTable

	fdMap, execFD, err := args.unpackFiles()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("creating fd map: %w", err)
	}
	defer func() {
		for _, hostFD := range fdMap {
			_ = hostFD.Close()
		}
	}()

	if execFD != nil {
		if initArgs.Filename != "" {
			return nil, 0, nil, fmt.Errorf("process must either be started from a file or a filename, not both")
		}
		file, err := host.NewFD(ctx, proc.Kernel.HostMount(), execFD.FD(), &host.NewFDOptions{
			Readonly:     true,
			Savable:      true,
			VirtualOwner: true,
			UID:          args.KUID,
			GID:          args.KGID,
		})
		if err != nil {
			return nil, 0, nil, err
		}
		defer file.DecRef(ctx)
		execFD.Release()
		initArgs.File = file
	} else {
		resolved, err := user.ResolveExecutablePath(ctx, &initArgs)
		if err != nil {
			return nil, 0, nil, err
		}
		initArgs.Filename = resolved
	}

	opts := fdimport.ImportOptions{
		Console: args.StdioIsPty,
		// Exec sessions are not restorable because the caller will not be present after the restore.
		// Exec'd processes are killed after the restore.
		Restorable:  false,
		UID:         args.KUID,
		GID:         args.KGID,
		SupportTTYs: args.SupportTTYs,
	}
	ttyFile, err := fdimport.Import(ctx, fdTable, fdMap, opts)
	if err != nil {
		return nil, 0, nil, err
	}

	if ttyFile != nil {
		initArgs.TTY = ttyFile.TTY()
	}

	// Set cgroups to the new exec task if cgroups are mounted.
	cgroupRegistry := proc.Kernel.CgroupRegistry()
	initialCgrps := map[kernel.Cgroup]struct{}{}
	for _, ctrl := range kernel.CgroupCtrls {
		cg, err := cgroupRegistry.FindCgroup(ctx, ctrl, "/"+args.ContainerID)
		if err != nil {
			log.Warningf("cgroup mount for controller %v not found", ctrl)
			continue
		}
		initialCgrps[cg] = struct{}{}
	}
	if len(initialCgrps) > 0 {
		initArgs.InitialCgroups = initialCgrps
	}

	mntnsCu.Release() // mntns ref is transferred to Kernel.CreateProcess()
	tg, tid, err := proc.Kernel.CreateProcess(initArgs)
	if err != nil {
		return nil, 0, nil, err
	}

	if args.SeccompProgram != nil {
		task := tg.Leader()
		if err := task.AppendSyscallFilter(*args.SeccompProgram, true); err != nil {
			return nil, 0, nil, fmt.Errorf("appending seccomp filters: %w", err)
		}
	}

	// Start the newly created process.
	proc.Kernel.StartProcess(tg)

	return tg, tid, ttyFile, nil
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
		*out = api.ProcessListToTable(p)
	} else {
		s, e := api.ProcessListToJSON(p)
		if e != nil {
			return e
		}
		*out = s
	}
	return nil
}

// Process contains information about a single process in a Sandbox.
type Process = api.Process

// Processes retrieves information about processes running in the sandbox with
// the given container id. All processes are returned if 'containerID' is empty.
func Processes(k *kernel.Kernel, containerID string, out *[]*Process) error {
	ts := k.TaskSet()
	now := k.RealtimeClock().Now()
	pidns := ts.Root
	for _, tg := range pidns.ThreadGroups() {
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
		pgid := kernel.ThreadID(0)
		if pg := tg.ProcessGroup(); pg != nil {
			pgid = kernel.ThreadID(pidns.IDOfProcessGroup(pg))
		}
		var threads []int32
		for _, tid := range tg.MemberIDs(pidns) {
			threads = append(threads, int32(tid))
		}
		*out = append(*out, &Process{
			UID:     tg.Leader().Credentials().EffectiveKUID,
			PID:     int32(pid),
			PPID:    int32(ppid),
			PGID:    int32(pgid),
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
//   - If startTime was today, HH:MM is used.
//   - If startTime was not today but was this year, MonDD is used (e.g. Jan02)
//   - If startTime was not this year, the year is used.
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
	return fmt.Sprintf("pts/%d", tty.Index())
}

// ContainerUsage retrieves per-container CPU usage.
func ContainerUsage(kr *kernel.Kernel) map[string]uint64 {
	cusage := make(map[string]uint64)
	for _, tg := range kr.TaskSet().Root.ThreadGroups() {
		// We want each tg's usage including reaped children.
		cid := tg.Leader().ContainerID()
		stats := tg.CPUStats()
		stats.Accumulate(tg.JoinedChildCPUStats())
		cusage[cid] += uint64(stats.UserTime.Nanoseconds()) + uint64(stats.SysTime.Nanoseconds())
	}
	return cusage
}

// unpackFiles unpacks the file descriptor map and, if applicable, the file
// descriptor to be used for execution from the unmarshalled ExecArgs.
func (args *ExecArgs) unpackFiles() (map[int]*fd.FD, *fd.FD, error) {
	var execFD *fd.FD
	var err error

	// If there is one additional file, the last file is used for program
	// execution.
	if len(args.Files) == len(args.GuestFDs)+1 {
		execFD, err = fd.NewFromFile(args.Files[len(args.Files)-1])
		if err != nil {
			return nil, nil, fmt.Errorf("duplicating exec file: %w", err)
		}
	} else if len(args.Files) != len(args.GuestFDs) {
		return nil, nil, fmt.Errorf("length of payload files does not match length of file descriptor array")
	}

	// GuestFDs are the indexes of our FD map.
	fdMap := make(map[int]*fd.FD, len(args.GuestFDs))
	for i, appFD := range args.GuestFDs {
		file := args.Files[i]
		if appFD < 0 {
			return nil, nil, fmt.Errorf("guest file descriptors must be 0 or greater")
		}
		hostFD, err := fd.NewFromFile(file)
		if err != nil {
			return nil, nil, fmt.Errorf("duplicating payload files: %w", err)
		}
		fdMap[appFD] = hostFD
	}
	return fdMap, execFD, nil
}

// SignalProcessArgs is the arguments to SignalProcess.
type SignalProcessArgs struct {
	// Signal number to send.
	Signo int `json:"signo"`

	// Process ID (in the root PID namespace) to signal.
	PID int `json:"pid"`
}

// SignalProcess sends a signal to the process with the given PID.
func (proc *Proc) SignalProcess(args *SignalProcessArgs, _ *struct{}) error {
	tg := proc.Kernel.RootPIDNamespace().ThreadGroupWithID(kernel.ThreadID(args.PID))
	if tg == nil {
		return fmt.Errorf("no such process with PID %d", args.PID)
	}
	return proc.Kernel.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(args.Signo)})
}
