// Copyright 2025 The gVisor Authors.
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
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/fdcollector"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/pipefs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/timing"
)

const (
	cudaProcsKey = "cuda-procs"

	// cudaCheckpointPathKey is the checkpoint state key for the path to the
	// cuda-checkpoint binary.
	cudaCheckpointPathKey = "cuda-checkpoint-path"

	// cudaCheckpointSequentialKey is the checkpoint state key for whether to run
	// cuda-checkpoint sequentially.
	cudaCheckpointSequentialKey = "cuda-checkpoint-sequential"
)

func preSaveCuda(k *kernel.Kernel, o *state.SaveOpts) error {
	if o.CudaCheckpointPath == "" {
		return nil
	}

	wasPaused := k.IsPaused()
	if wasPaused {
		// It is possible that the kernel is paused when we are trying to save it.
		// Unpause it temporarily so that we can execute cuda-checkpoint. We can
		// expect such a state when using Docker. Docker's checkpoint command
		// calls pause first and then calls the checkpoint command.
		log.Infof("Unpausing kernel to execute cuda-checkpoint")
		k.Unpause()
		if k.IsPaused() {
			// If the kernel is still paused, we don't understand/expect this state.
			k.Pause() // Revert the unpause from above.
			return fmt.Errorf("kernel is double paused before checkpoint")
		}
	}
	sctx := k.SupervisorContext()
	cudaProcs := cudaProcs(sctx, k, o.CudaCheckpointPath, k.NvidiaDriverVersion.Major())
	// FIXME: b/456299722
	for _, tg := range cudaProcs {
		tg.SigsegvLock()
	}
	// Undo the --toggle on success procs if any fail, so the application can
	// continue running after the failed checkpoint is reported.
	err := runCudaCheckpointOp(sctx, k, o.CudaCheckpointPath, cudaProcs, nil, o.CudaCheckpointSequential, cudaCheckpointToggle, &cudaCheckpointToggle)
	if wasPaused {
		k.Pause()
	}
	if err != nil {
		// FIXME: b/456299722
		for _, tg := range cudaProcs {
			tg.SigsegvUnlock()
		}
		return err
	}
	k.AddStateToCheckpoint(cudaCheckpointPathKey, o.CudaCheckpointPath)
	k.AddStateToCheckpoint(cudaCheckpointSequentialKey, o.CudaCheckpointSequential)
	k.AddStateToCheckpoint(cudaProcsKey, cudaProcs)
	return nil
}

// cudaProcs returns a list of all CUDA processes in the sandbox. It selects
// them by collecting processes whose FD table has an open file descriptor to
// any CUDA device.
//
// Callers must not hold any thread-group leader's Task.mu in k.
// checklocks cannot name the leader mutexes selected by ForEachThreadGroup.
func cudaProcs(sctx context.Context, k *kernel.Kernel, cudaCheckpointPath string, nvidiaDriverVersionMajor int) []*kernel.ThreadGroup {
	var procs []*kernel.ThreadGroup
	k.TaskSet().ForEachThreadGroup(func(tg *kernel.ThreadGroup, tgLeader *kernel.Task) {
		found := false
		// Note that it is possible for tasks in a thread group to have various FD
		// tables (via clone(2) with CLONE_THREAD set and CLONE_FILES *not* set).
		// However, we don't expect this to happen in practice for CUDA processes.
		// So for efficiency, we just check the tgLeader's FD table, instead of
		// iterating over all tasks' FD tables in all thread groups.
		tgLeader.WithMuLocked(func(t *kernel.Task) {
			t.FDTable().ForEach(sctx, func(_ int32, file *vfs.FileDescription, _ kernel.FDFlags) bool {
				if _, ok := file.Impl().(nvproxy.NvidiaDeviceFD); ok {
					found = true
					return false
				}
				return true
			})
		})
		if found {
			procs = append(procs, tg)
		}
	})

	// procs may contain NVML-only processes, which don't use CUDA. As of
	// writing, calling cuda-checkpoint on them will fail for all tested drivers.
	// This includes R570, which supposedly has "NVML support". We suspect this
	// means that R570 supports CUDA+NVML processes, but not NVML-only processes.
	//
	// To filter out NVML-only processes, there are two approaches:
	// 1. Call cuda-checkpoint --get-state on all candidates. The checkpoint-able
	//    ones will return "running" and the others will fail. This is the
	//    recommendation in https://github.com/NVIDIA/cuda-checkpoint/issues/10.
	// 2. CUDA processes will have a thread named 'cudaXXXXXXXXXXX', where X is a
	//    hex digit. cuda-checkpoint interacts with these threads. Filter out
	//    processes that don't have such a thread.
	//
	// Option 1 is more robust, however, support for --get-state was only added
	// in R555. Prefer option 1 if possible, otherwise fall back to option 2.
	if nvidiaDriverVersionMajor < 550 {
		log.Warningf("cuda-checkpoint requires driver >=R550, driver major = %d, expect failures with message \"Insufficient driver\"", nvidiaDriverVersionMajor)
	} else if nvidiaDriverVersionMajor < 555 {
		procs = filterCudaProcsUsingThreadName(sctx, procs)
	} else {
		procs = filterCudaProcsUsingGetState(sctx, k, cudaCheckpointPath, procs)
	}
	return procs
}

// postRestoreCuda restores CUDA processes that were checkpointed by
// preSaveCuda. nvproxyRemapping is non-nil only when called after a restore
// that remapped GPUs.
func postRestoreCuda(k *kernel.Kernel, timeline *timing.Timeline, nvproxyRemapping *nvproxy.DeviceRemapping) error {
	cudaCheckpointPathVal := k.PopCheckpointState(cudaCheckpointPathKey)
	if cudaCheckpointPathVal == nil {
		return nil
	}
	cudaCheckpointPath := cudaCheckpointPathVal.(string)
	cudaCheckpointSequential := k.PopCheckpointState(cudaCheckpointSequentialKey).(bool)
	cudaProcs := k.PopCheckpointState(cudaProcsKey).([]*kernel.ThreadGroup)
	timeline.Reached("starting cuda-ckpt")
	err := restoreCudaProcs(k.SupervisorContext(), k, cudaCheckpointPath, cudaProcs, timeline, cudaCheckpointSequential, nvproxyRemapping)
	// FIXME: b/456299722
	for _, tg := range cudaProcs {
		tg.SigsegvUnlock()
	}
	return err
}

// cudaCheckpointDeviceMap returns the value to pass to cuda-checkpoint's
// --device-map flag to restore CUDA state checkpointed on dr's old devices
// onto its new devices, in the format "oldUuid1=newUuid1,oldUuid2=newUuid2".
// cuda-checkpoint requires the map to list all checkpointed devices, so all
// saved devices are included even if only some are remapped. It returns ""
// if dr is nil or an identity, in which case no device map is needed.
func cudaCheckpointDeviceMap(dr *nvproxy.DeviceRemapping) (string, error) {
	if dr == nil {
		return "", nil
	}
	identity := true
	pairs := make([]string, 0, len(dr.OldDeviceByMinor))
	for _, oldMinor := range slices.Sorted(maps.Keys(dr.OldDeviceByMinor)) {
		oldID := dr.OldDeviceByMinor[oldMinor]
		newID := dr.NewDeviceByOld[oldID]
		if oldID.UUID == "" || newID.UUID == "" {
			return "", fmt.Errorf("nvproxy device has no UUID: %v => %v", oldID, newID)
		}
		if oldID.UUID != newID.UUID {
			identity = false
		}
		pairs = append(pairs, oldID.UUID+"="+newID.UUID)
	}
	if identity {
		return "", nil
	}
	return strings.Join(pairs, ","), nil
}

// restoreCudaProcs restores CUDA state in all of the given (currently
// checkpointed) CUDA processes. If nvproxyRemapping maps any device to a
// different one, CUDA state is restored onto the new devices via
// cuda-checkpoint's --device-map flag.
//
// Failures are not undone: if CUDA can't be restored, the sandbox can't make
// progress regardless, so the error is simply returned to the caller.
func restoreCudaProcs(sctx context.Context, k *kernel.Kernel, cudaCheckpointPath string, cudaProcs []*kernel.ThreadGroup, timeline *timing.Timeline, sequential bool, nvproxyRemapping *nvproxy.DeviceRemapping) error {
	deviceMap, err := cudaCheckpointDeviceMap(nvproxyRemapping)
	if err != nil {
		return err
	}
	if deviceMap == "" {
		// --toggle transitions checkpointed => running in a single invocation.
		return runCudaCheckpointOp(sctx, k, cudaCheckpointPath, cudaProcs, timeline, sequential, cudaCheckpointToggle, nil)
	}
	// GPU migration via --device-map requires driver >= R580.
	if major := k.NvidiaDriverVersion.Major(); major < 580 {
		return fmt.Errorf("GPUs changed across restore, but cuda-checkpoint --device-map requires driver >= R580 (have R%d)", major)
	}
	log.Infof("cuda-checkpoint device map: %s", deviceMap)
	restoreOp := cudaCheckpointOp{
		args: []string{"--action", "restore", "--device-map", deviceMap},
		desc: "restore",
	}
	if err := runCudaCheckpointOp(sctx, k, cudaCheckpointPath, cudaProcs, timeline, sequential, restoreOp, nil); err != nil {
		return err
	}
	return runCudaCheckpointOp(sctx, k, cudaCheckpointPath, cudaProcs, timeline, sequential, cudaCheckpointUnlock, nil)
}

// cudaCheckpointOp describes an operation to perform with cuda-checkpoint.
type cudaCheckpointOp struct {
	// args are the arguments to cuda-checkpoint that specify the operation, not
	// including --pid.
	args []string
	// desc is a short name for the operation, used in logs and timeline names.
	desc string
}

var (
	cudaCheckpointToggle = cudaCheckpointOp{
		args: []string{"--toggle"},
		desc: "toggle",
	}
	cudaCheckpointGetState = cudaCheckpointOp{
		args: []string{"--get-state"},
		desc: "get-state",
	}

	cudaCheckpointUnlock = cudaCheckpointOp{
		args: []string{"--action", "unlock"},
		desc: "unlock",
	}
)

type checkpointProc struct {
	desc string
	tg   *kernel.ThreadGroup
	out  *fdcollector.Agent
}

// invokeCudaCheckpoint invokes cuda-checkpoint on the given CUDA process with
// the given operation. On success it returns a checkpointProc struct
// containing the running cuda-checkpoint process and a cleanup function which
// must be called to release resources. If cudaProc has exited, it returns
// (checkpointProc.tg == nil, err == nil).
func invokeCudaCheckpoint(sctx context.Context, k *kernel.Kernel, proc *Proc, cudaCheckpointPath string, cudaProc *kernel.ThreadGroup, op cudaCheckpointOp, nullFD *vfs.FileDescription) (checkpointProc, func(), error) {
	pid := cudaProc.ID()
	leader := cudaProc.Leader()
	contID := leader.ContainerID()
	mntns := leader.MountNamespace()
	if mntns == nil || !mntns.TryIncRef() {
		log.Warningf("PID %d in container %q has exited, skipping CUDA checkpoint for it", pid, contID)
		return checkpointProc{}, nil, nil
	}
	root := mntns.Root(sctx)
	cu := cleanup.Make(func() {
		root.DecRef(sctx)
	})
	defer cu.Clean()
	ctx := vfs.WithRoot(sctx, root)
	cu.Add(func() {
		mntns.DecRef(ctx)
	})
	argv := make([]string, 0, 3+len(op.args))
	argv = append(argv, "cuda-checkpoint")
	argv = append(argv, op.args...)
	argv = append(argv, "--pid", strconv.FormatInt(int64(pid), 10))
	args := &ExecArgs{
		Filename:       cudaCheckpointPath,
		Argv:           argv,
		ContainerID:    contID,
		MountNamespace: mntns,
		PIDNamespace:   leader.PIDNamespace(),
	}
	// Provision environment variables from leader's container spec.
	contName := k.ContainerName(contID)
	args.Envv = k.Saver().SpecEnviron(contName)

	// Provide standard streams to cuda-checkpoint. Use /dev/null as stdin
	// and direct cuda-checkpoint's stdout/stderr to a pipe.
	ckptDesc := fmt.Sprintf("cuda-checkpoint %s for PID %d in container %q", op.desc, pid, contID)
	args.FDTable = k.NewFDTable()
	cu.Add(func() {
		args.FDTable.DecRef(ctx)
	})
	if nullFD != nil {
		if _, err := args.FDTable.NewFDAt(ctx, 0, nullFD, kernel.FDFlags{}); err != nil {
			log.Warningf("Failed to make /dev/null stdin for %s: %v", ckptDesc, err)
		}
	}
	var ckptOut *fdcollector.Agent
	rfd, wfd, err := pipefs.NewConnectedPipeFDs(ctx, k.PipeMount(), 0 /* flags */)
	if err != nil {
		log.Warningf("Failed to create stdout/stderr pipe for %s: %v", ckptDesc, err)
	} else {
		if _, err := args.FDTable.NewFDAt(ctx, 1, wfd, kernel.FDFlags{}); err != nil {
			log.Warningf("Failed to make pipe stdout for %s: %v", ckptDesc, err)
		}
		if _, err := args.FDTable.NewFDAt(ctx, 2, wfd, kernel.FDFlags{}); err != nil {
			log.Warningf("Failed to make pipe stderr for %s: %v", ckptDesc, err)
		}
		wfd.DecRef(ctx)
		ckptOut = fdcollector.NewAgent(ctx, rfd, ckptDesc) // transfers ownership of rfd
		cu.Add(ckptOut.Stop)
	}
	// FIXME(ayushranjan): Get WorkDirectory, Limits and Capabilities from spec?
	ckptTG, _, _, err := ExecAsync(proc, args)
	if err != nil {
		return checkpointProc{}, nil, fmt.Errorf("failed to exec %s: %w", ckptDesc, err)
	}
	return checkpointProc{
		desc: ckptDesc,
		tg:   ckptTG,
		out:  ckptOut,
	}, cu.Release(), nil
}

func filterCudaProcsUsingThreadName(sctx context.Context, cudaProcs []*kernel.ThreadGroup) []*kernel.ThreadGroup {
	log.Debugf("Filtering CUDA processes using thread name")
	cudaThreadRegex := regexp.MustCompile(`^cuda[0-9a-f]{11}$`)
	var res []*kernel.ThreadGroup
	for _, cudaProc := range cudaProcs {
		found := false
		cudaProc.ForEachTask(func(t *kernel.Task) bool {
			if cudaThreadRegex.MatchString(t.Name()) {
				found = true
				return false
			}
			return true
		})
		if found {
			res = append(res, cudaProc)
		}
	}
	return res
}

func filterCudaProcsUsingGetState(sctx context.Context, k *kernel.Kernel, cudaCheckpointPath string, cudaProcs []*kernel.ThreadGroup) []*kernel.ThreadGroup {
	log.Debugf("Filtering CUDA processes using 'cuda-checkpoint --get-state'")
	// Open /dev/null once for the stdin of all cuda-checkpoint processes.
	nullVD := k.VFS().NewAnonVirtualDentry("null")
	defer nullVD.DecRef(sctx)
	nullFD, err := memdev.NewNullFD(sctx, nullVD.Mount(), nullVD.Dentry(), vfs.OpenOptions{})
	if err != nil {
		log.Warningf("Failed to open /dev/null for cuda-checkpoint stdin: %v", err)
	} else {
		defer nullFD.DecRef(sctx)
	}

	// Call cuda-checkpoint for each CUDA PID parallelly.
	proc := &Proc{Kernel: k}
	ckptProcs := make(map[*kernel.ThreadGroup]checkpointProc)
	for _, cudaProc := range cudaProcs {
		ckptProc, cleanup, err := invokeCudaCheckpoint(sctx, k, proc, cudaCheckpointPath, cudaProc, cudaCheckpointGetState, nullFD)
		if err != nil {
			log.Warningf("Failed to get state for PID %d: %v", cudaProc.ID(), err)
			continue
		}
		if ckptProc.tg == nil {
			continue
		}
		ckptProcs[cudaProc] = ckptProc
		defer cleanup()
	}
	// Check the output of all cuda-checkpoint processes. We want the ones with
	// output "running".
	var res []*kernel.ThreadGroup
	for cudaProc, ckptProc := range ckptProcs {
		ckptProc.tg.WaitExited()
		if status := ckptProc.tg.ExitStatus(); status == 0 {
			res = append(res, cudaProc)
			if ckptProc.out != nil {
				output := strings.TrimSpace(ckptProc.out.String())
				if output != "running" {
					log.Warningf("CUDA PID %d in unexpected state %q", cudaProc.ID(), output)
				}
				log.Debugf("%s succeeded; output: %q", ckptProc.desc, output)
			}
		} else {
			if ckptProc.out != nil {
				log.Warningf("%q failed with exit status %d, skipping CUDA checkpoint for PID %d; output: %q", ckptProc.desc, status, cudaProc.ID(), ckptProc.out.String())
			} else {
				log.Warningf("%q failed with exit status %d, skipping CUDA checkpoint for PID %d", ckptProc.desc, status, cudaProc.ID())
			}
		}
	}
	return res
}

// runCudaCheckpointOp invokes cuda-checkpoint with the given operation on all
// of the given CUDA processes and waits for them to finish. If any invocation
// fails and undoOp is non-nil, undoOp is invoked on all processes for which
// op succeeded, on a best-effort basis, to restore their original state.
func runCudaCheckpointOp(sctx context.Context, k *kernel.Kernel, cudaCheckpointPath string, cudaProcs []*kernel.ThreadGroup, timeline *timing.Timeline, sequential bool, op cudaCheckpointOp, undoOp *cudaCheckpointOp) error {
	start := time.Now()

	// Open /dev/null once for the stdin of all cuda-checkpoint processes.
	nullVD := k.VFS().NewAnonVirtualDentry("null")
	defer nullVD.DecRef(sctx)
	nullFD, err := memdev.NewNullFD(sctx, nullVD.Mount(), nullVD.Dentry(), vfs.OpenOptions{})
	if err != nil {
		log.Warningf("Failed to open /dev/null for cuda-checkpoint stdin: %v", err)
	} else {
		defer nullFD.DecRef(sctx)
	}

	// Call cuda-checkpoint for each CUDA PID.
	ckptTimerNames := make([]string, len(cudaProcs))
	for i, cudaProc := range cudaProcs {
		ckptTimerNames[i] = fmt.Sprintf("cuda-ckpt %s %s", op.desc, cudaProc.ID())
	}
	var ckptTimings []*timing.Lease
	if !sequential {
		ckptTimelines := timeline.MultiFork(ckptTimerNames)
		ckptTimings = make([]*timing.Lease, len(cudaProcs))
		for i := range cudaProcs {
			ckptTimings[i] = ckptTimelines[i].Lease()
		}
	}
	defer func() {
		for _, t := range ckptTimings {
			t.End()
		}
	}()
	proc := &Proc{Kernel: k}
	ckptProcs := make(map[*kernel.ThreadGroup]checkpointProc)
	var errs []error
	for i, cudaProc := range cudaProcs {
		var ckptTiming *timing.Lease
		if sequential {
			ckptTiming = timeline.Fork(ckptTimerNames[i]).Lease()
		} else {
			ckptTiming = ckptTimings[i]
		}
		ckptProc, cleanup, err := invokeCudaCheckpoint(sctx, k, proc, cudaCheckpointPath, cudaProc, op, nullFD)
		if err != nil {
			ckptTiming.Reached("invoke error")
			errs = append(errs, err)
			break
		}
		if ckptProc.tg == nil {
			ckptTiming.Reached("tg nil")
			continue
		}
		ckptProcs[cudaProc] = ckptProc
		ckptTimeline := ckptTiming.Transfer()
		if sequential {
			ckptProc.tg.WaitExited()
			if status := ckptProc.tg.ExitStatus(); status != 0 {
				ckptTimeline.Reached("exec error")
			}
			ckptTimeline.End()
		} else {
			go func() {
				defer ckptTimeline.End()
				ckptProc.tg.WaitExited()
				if status := ckptProc.tg.ExitStatus(); status != 0 {
					ckptTimeline.Reached("exec error")
				}
			}()
		}
		defer cleanup()
	}
	timeline.Reached("cuda-ckpts invoked")
	// Wait for all cuda-checkpoint processes to exit. Remove all failed
	// cuda-checkpoint attempts from ckptProcs, so ckptProcs only contains the
	// successful ones.
	for cudaProc, ckptProc := range ckptProcs {
		if !sequential {
			ckptProc.tg.WaitExited()
		}
		if status := ckptProc.tg.ExitStatus(); status != 0 {
			if ckptProc.out != nil {
				errs = append(errs, fmt.Errorf("%q failed with exit status %d; output: %q", ckptProc.desc, status, ckptProc.out.String()))
			} else {
				errs = append(errs, fmt.Errorf("%q failed with exit status %d", ckptProc.desc, status))
			}
			delete(ckptProcs, cudaProc)
		} else if log.IsLogging(log.Debug) && ckptProc.out != nil {
			log.Debugf("%s succeeded; output: %q", ckptProc.desc, ckptProc.out.String())
		}
	}
	timeline.Reached("cuda-ckpts waited")
	if len(errs) > 0 {
		if undoOp == nil {
			return errors.Join(errs...)
		}
		// Undo the operation for all the successful ones to restore the original
		// state. This is best-effort.
		undoCkptProcs := make(map[string]checkpointProc)
		for cudaProc, ckptProc := range ckptProcs {
			undoCkptProc, cleanup, err := invokeCudaCheckpoint(sctx, k, proc, cudaCheckpointPath, cudaProc, *undoOp, nullFD)
			if err != nil {
				log.Warningf("Failed to invoke cuda-checkpoint to undo %q: %v", ckptProc.desc, err)
				continue
			}
			if undoCkptProc.tg == nil {
				continue
			}
			if sequential {
				undoCkptProc.tg.WaitExited()
			}
			undoCkptProcs[ckptProc.desc] = undoCkptProc
			defer cleanup()
		}
		for ckptProcDesc, undoCkptProc := range undoCkptProcs {
			if !sequential {
				undoCkptProc.tg.WaitExited()
			}
			if status := undoCkptProc.tg.ExitStatus(); status != 0 {
				if undoCkptProc.out != nil {
					log.Warningf("Undoing %q failed with exit status %d; output: %q", ckptProcDesc, status, undoCkptProc.out.String())
				} else {
					log.Warningf("Undoing %q failed with exit status %d", ckptProcDesc, status)
				}
			}
		}
		// Combine all errors and return.
		return errors.Join(errs...)
	}
	log.Infof("cuda-checkpoint %s on %d processes took [%s]", op.desc, len(ckptProcs), time.Since(start))
	timeline.Reached("cuda-ckpts done")
	return nil
}
