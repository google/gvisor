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
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fdcollector"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/pipefs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/pkg/urpc"
)

// SaveRestoreExecMode is the mode for the save/restore binary.
type SaveRestoreExecMode string

const (
	// DefaultSaveRestoreExecTimeout is the default timeout for the save/restore
	// binary.
	DefaultSaveRestoreExecTimeout = 10 * time.Minute
	// SaveRestoreExecSave is the save mode for the save/restore exec.
	SaveRestoreExecSave SaveRestoreExecMode = "save"
	// SaveRestoreExecRestore is the restore mode for the save/restore exec.
	SaveRestoreExecRestore SaveRestoreExecMode = "restore"
	// SaveRestoreExecResume is the resume mode for the save/restore binary.
	SaveRestoreExecResume SaveRestoreExecMode = "resume"

	saveRestoreExecEnvVar = "GVISOR_SAVE_RESTORE_AUTO_EXEC_MODE"
)

// ErrInvalidFiles is returned when the urpc call to Save does not include an
// appropriate file payload (e.g. there is no output file!).
var ErrInvalidFiles = errors.New("exactly one file must be provided")

// State includes state-related functions.
type State struct {
	Kernel   *kernel.Kernel
	Watchdog *watchdog.Watchdog
}

// SaveOpts contains options for the Save RPC call.
type SaveOpts struct {
	// Key is used for state integrity check.
	Key []byte `json:"key"`

	// Metadata is the set of metadata to prepend to the state file.
	Metadata map[string]string `json:"metadata"`

	// AppMFExcludeCommittedZeroPages is the value of
	// pgalloc.SaveOpts.ExcludeCommittedZeroPages for the application memory
	// file.
	AppMFExcludeCommittedZeroPages bool `json:"app_mf_exclude_committed_zero_pages"`

	// HavePagesFile indicates whether the pages file and its corresponding
	// metadata file is provided.
	HavePagesFile bool `json:"have_pages_file"`

	// FilePayload contains the following:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	urpc.FilePayload

	// Resume indicates if the sandbox process should continue running
	// after checkpointing.
	Resume bool

	// ExecOpts contains options for executing a binary during save/restore.
	ExecOpts SaveRestoreExecOpts

	SaveOptsExtra
}

// SaveRestoreExecOpts contains options for executing a binary
// during save/restore.
type SaveRestoreExecOpts struct {
	// Argv is the argv of the save/restore binary split by spaces.
	// The first element is the path to the binary.
	Argv string

	// Timeout is the timeout for waiting for the save/restore binary.
	Timeout time.Duration

	// ContainerID is the ID of the container that the save/restore binary executes in.
	ContainerID string
}

// ConvertToStateSaveOpts converts a control.SaveOpts to a state.SaveOpts.
// state.SaveOpts.Close() must be called when the state.SaveOpts is no longer
// needed.
func ConvertToStateSaveOpts(o *SaveOpts) (*state.SaveOpts, error) {
	saveOpts := &state.SaveOpts{
		Key:                            o.Key,
		Metadata:                       o.Metadata,
		AppMFExcludeCommittedZeroPages: o.AppMFExcludeCommittedZeroPages,
		Resume:                         o.Resume,
	}
	if err := setSaveOptsImpl(o, saveOpts); err != nil {
		saveOpts.Close()
		return nil, err
	}
	return saveOpts, nil
}

func setSaveOptsForLocalCheckpointFiles(o *SaveOpts, saveOpts *state.SaveOpts) error {
	wantFiles := 1
	if o.HavePagesFile {
		wantFiles += 2
	}
	if gotFiles := len(o.FilePayload.Files); gotFiles != wantFiles {
		return fmt.Errorf("got %d files, wanted %d", gotFiles, wantFiles)
	}

	// Save to the first provided stream.
	stateFile, err := o.ReleaseFD(0)
	if err != nil {
		return err
	}
	// Setting saveOpts.Destination/PagesMetadata/PagesFile transfers ownership
	// of the created object to saveOpts, even if we return a non-nil error.
	saveOpts.Destination = stateFile
	if o.HavePagesFile {
		pagesMetadataFile, err := o.ReleaseFD(1)
		if err != nil {
			return err
		}
		// //pkg/state/wire writes one byte at a time; buffer writes to
		// pagesMetadataFile to avoid making one syscall per write. For the
		// state file, this buffering is handled by statefile.NewWriter() =>
		// compressio.Writer or compressio.NewSimpleWriter().
		saveOpts.PagesMetadata = stateio.NewBufioWriteCloser(pagesMetadataFile)

		pagesFileFD, err := unix.Dup(int(o.Files[2].Fd()))
		if err != nil {
			return err
		}
		saveOpts.PagesFile = stateio.NewPagesFileFDWriterDefault(int32(pagesFileFD))
	}
	return nil
}

// Save saves the running system.
func (s *State) Save(o *SaveOpts, _ *struct{}) error {
	saveOpts, err := ConvertToStateSaveOpts(o)
	if err != nil {
		return err
	}
	defer saveOpts.Close()

	return s.SaveWithOpts(saveOpts, &o.ExecOpts)
}

// SaveWithOpts saves the running system with the given options.
func (s *State) SaveWithOpts(saveOpts *state.SaveOpts, execOpts *SaveRestoreExecOpts) error {
	if err := preSave(s.Kernel, saveOpts, execOpts); err != nil {
		return err
	}
	if err := saveOpts.Save(s.Kernel.SupervisorContext(), s.Kernel, s.Watchdog); err != nil {
		return err
	}
	if saveOpts.Resume {
		if err := PostResume(s.Kernel, nil); err != nil {
			return err
		}
	}
	return nil
}

// preSave is called before saving the kernel.
func preSave(k *kernel.Kernel, o *state.SaveOpts, execOpts *SaveRestoreExecOpts) error {
	if execOpts.Argv != "" {
		argv := strings.Split(execOpts.Argv, " ")
		if err := ConfigureSaveRestoreExec(k, argv, execOpts.Timeout, execOpts.ContainerID); err != nil {
			return fmt.Errorf("failed to configure save/restore binary: %w", err)
		}
		if err := SaveRestoreExec(k, SaveRestoreExecSave); err != nil {
			return fmt.Errorf("failed to exec save/restore binary: %w", err)
		}
	}
	return preSaveImpl(k, o)
}

// PostResume is called after resuming the kernel.
//
// Precondition: The kernel should be running.
func PostResume(k *kernel.Kernel, timeline *timing.Timeline) error {
	if k.IsPaused() {
		// The kernel is still paused (double-pause can happen with Docker which
		// calls pause first and then checkpoint command). The final resume command
		// will invoke save/restore binary if necessary.
		return nil
	}
	if k.TaskSet().IsExiting() {
		// This can occur when kernel is saved with control.SaveOpts.Resume=false.
		// We can not invoke the save/restore binary on such a kernel.
		return nil
	}
	if err := SaveRestoreExec(k, SaveRestoreExecResume); err != nil {
		return fmt.Errorf("failed to wait for save/restore binary: %w", err)
	}
	return postResumeImpl(k, timeline)
}

// PostRestore is called after restoring the kernel.
//
// Precondition: The kernel should be running.
func PostRestore(k *kernel.Kernel, timeline *timing.Timeline) error {
	if k.IsPaused() {
		// The kernel is still paused (double-pause can happen with Docker which
		// calls pause first and then checkpoint command). The final resume command
		// will invoke cuda-checkpoint if necessary.
		return nil
	}
	if k.TaskSet().IsExiting() {
		// This can occur when kernel is saved with control.SaveOpts.Resume=false.
		// We can not invoke cuda-checkpoint on such a kernel.
		return nil
	}
	if err := SaveRestoreExec(k, SaveRestoreExecRestore); err != nil {
		return fmt.Errorf("failed to wait for save/restore binary: %w", err)
	}
	return postRestoreImpl(k, timeline)
}

// SaveRestoreExec creates a new process that executes the save/restore
// binary specified by k.SaveRestoreExecConfig and waits for it to finish.
//
// Precondition: The kernel should be running; k.SetSaveRestoreExecConfig should
// be setup with an argv, otherwise this function is a no-op.
func SaveRestoreExec(k *kernel.Kernel, mode SaveRestoreExecMode) error {
	if k.SaveRestoreExecConfig == nil {
		return nil
	}

	leader := k.SaveRestoreExecConfig.LeaderTask
	argv := k.SaveRestoreExecConfig.Argv
	timeout := k.SaveRestoreExecConfig.Timeout
	sctx := k.SupervisorContext()
	contID := leader.ContainerID()
	mntns := leader.MountNamespace()
	if mntns == nil || !mntns.TryIncRef() {
		log.Warningf("PID %d in container %q has exited, skipping CUDA checkpoint for it", leader.ThreadGroup().ID(), contID)
		return nil
	}
	mntns.IncRef()
	root := mntns.Root(sctx)
	cu := cleanup.Make(func() {
		root.DecRef(sctx)
	})
	defer cu.Clean()
	ctx := vfs.WithRoot(sctx, root)
	cu.Add(func() {
		mntns.DecRef(ctx)
	})

	fdTable := k.NewFDTable()
	cu.Add(func() {
		fdTable.DecRef(sctx)
	})
	var execOut *fdcollector.Agent
	rfd, wfd, err := pipefs.NewConnectedPipeFDs(ctx, k.PipeMount(), 0 /* flags */)
	if err != nil {
		log.Warningf("Failed to create stdout/stderr pipe for %s: %v", argv[0], err)
	} else {
		if _, err := fdTable.NewFDAt(ctx, 1, wfd, kernel.FDFlags{}); err != nil {
			log.Warningf("Failed to make pipe stdout for %s: %v", argv[0], err)
		}
		if _, err := fdTable.NewFDAt(ctx, 2, wfd, kernel.FDFlags{}); err != nil {
			log.Warningf("Failed to make pipe stderr for %s: %v", argv[0], err)
		}
		wfd.DecRef(ctx)
		execOut = fdcollector.NewAgent(ctx, rfd, argv[0]) // transfers ownership of rfd
		cu.Add(execOut.Stop)
	}
	// TODO(b/419041893): Support running the save/restore binary with container
	// env vars without relying on the Saver().
	var envv []string
	if k.Saver() != nil {
		contName := k.ContainerName(contID)
		envv = k.Saver().SpecEnviron(contName)
	}

	proc := Proc{
		Kernel: k,
	}
	execArgs := ExecArgs{
		Filename:       argv[0],
		Argv:           argv,
		Envv:           append(envv, fmt.Sprintf("%s=%s", saveRestoreExecEnvVar, mode)),
		ContainerID:    contID,
		MountNamespace: mntns,
		PIDNamespace:   leader.PIDNamespace(),
		Limits:         limits.NewLimitSet(),
		FDTable:        fdTable,
	}
	tg, _, _, err := ExecAsync(&proc, &execArgs)
	if err != nil {
		return fmt.Errorf("failed to exec save/restore binary: %w", err)
	}

	waitC := make(chan struct{})
	go func() {
		tg.WaitExited()
		waitC <- struct{}{}
	}()
	select {
	case <-waitC:
		if tg.ExitStatus() != 0 {
			return fmt.Errorf("%v exited with non-zero status %d", argv[0], tg.ExitStatus())
		}
	case <-time.After(timeout):
		tg.SendSignal(&linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		return fmt.Errorf("%s timed out after %v", argv[0], timeout)
	}
	log.Debugf("save/restore binary %s output: %s", argv[0], execOut.String())
	return nil
}

// ConfigureSaveRestoreExec sets the configuration for the save/restore binary.
// If containerID is empty, the global init process will be used for the
// save/restore binary's leader task.
func ConfigureSaveRestoreExec(k *kernel.Kernel, argv []string, timeout time.Duration, containerID string) error {
	if k.SaveRestoreExecConfig != nil {
		return fmt.Errorf("save/restore binary is already set")
	}
	k.SaveRestoreExecConfig = &kernel.SaveRestoreExecConfig{
		Argv:    argv,
		Timeout: timeout,
	}

	var leader *kernel.Task
	if containerID != "" {
		for _, tg := range k.RootPIDNamespace().ThreadGroups() {
			// Find all processes with no parent (root of execution).
			if tg.Leader().Parent() == nil {
				cid := tg.Leader().ContainerID()
				if cid == containerID {
					leader = tg.Leader()
					break
				}
			}
		}
		if leader == nil {
			return fmt.Errorf("failed to find process associated with container %s", containerID)
		}
	} else {
		leader = k.GlobalInit().Leader()
	}
	k.SaveRestoreExecConfig.LeaderTask = leader
	return nil
}
