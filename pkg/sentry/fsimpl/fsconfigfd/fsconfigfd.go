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

// Package fsconfigfd provides an implementation of a *filesystem creation context*,
// part of the new file-descriptor-based mount API.
//
// Applications can create and mount a filesystem separately from placing it on the
// real mount tree. An fs context is created using fsopen() and configured with fsconfig(),
// and a mount file descriptor (fsimpl/mountfd) is created with fsmount().
//
// The implementation is currently a work-in-progress. Currently, the primary differences
// to the Linux implementation are:
//   - Filesystem parameters are parsed (and errors handled) at FSCONFIG_CMD_CREATE time rather
//     than when parameters are set
//   - FSCONFIG_CMD_CREATE_EXL and FSCONFIG_CMD_RECONFIGURE are not supported (see sys_mount_fd.go)
//   - Only FLAG and STRING arguments are supported
package fsconfigfd

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Fd represents a filesystem configuration context.
//
// +stateify savable
type Fd struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// contextMu protects context.
	contextMu sync.Mutex `state:"nosave"`

	// The filesystem configuration context.
	// context is protected by contextMu.
	context fsContext
}

// FSValue represents the value assigned to a parameter passed to the filesystem. There are 5
// valid types: bool, string, []byte, FileDescription, and string (path).
type FSValue interface {
	isFSValue()
}

// FSValueFlag represents a binary value passed to the filesystem.
//
// +stateify savable
type FSValueFlag struct{}

// FSValueString represents a string value passed to the filesystem.
//
// +stateify savable
type FSValueString string

// FSValueBlob represents a binary blob value passed to the filesystem.
//
// +stateify savable
type FSValueBlob []byte

// FSValuePath represents a path value passed to the filesystem.
//
// +stateify savable
type FSValuePath string

// FSValueFd represents a file descriptor value passed to the filesystem.
//
// +stateify savable
type FSValueFd struct {
	FileDescription *vfs.FileDescription
}

func (FSValueFlag) isFSValue()   {}
func (FSValueString) isFSValue() {}
func (FSValueBlob) isFSValue()   {}
func (FSValuePath) isFSValue()   {}
func (FSValueFd) isFSValue()     {}

// FSParameter (together with a key) represents a parameter passed to the filesystem.
//
// +stateify savable
type FSParameter struct {
	Value FSValue
	DirFd int
}

// An fsconfigfd has different "states", and in each state, only some operations
// are valid. We use different types for each state to make logic bugs harder to
// write.
//
// Analogous to include/linux/fs_context.h:fs_context_phase.
//
// +stateify savable
type fsContext interface {
	isFSContext()
}

// createParamsContext represents a filesystem configuration context that is awaiting
// parameters to be set using fsconfig(2).
//
// +stateify savable
type createParamsContext struct {
	// The filesystem type, e.g. "tmpfs"
	fsName string

	// The mount source
	source *string

	// A mutable list of parameters to be passed to the filesystem.
	params map[string]FSParameter

	// The credentials of the process mounting the filesystem.
	creds *auth.Credentials
}

func (c *createParamsContext) parseMountOptions() (*vfs.MountOptions, error) {
	params := c.params

	var opts vfs.MountOptions

	// Handle mount-specific options
	_, ro := params["ro"]
	if ro {
		opts.ReadOnly = true
	}

	var data []string
	for key, param := range params {
		if key == "ro" {
			continue
		}
		value := param.Value
		switch v := value.(type) {
		case FSValueFlag:
			data = append(data, key)
		case FSValueString:
			data = append(data, fmt.Sprintf("%s=%s", key, string(v)))
		default:
			// TODO(b/513024543): when filesystems are refactored to parse options at
			// fsconfig() time, we should also support non-flag/non-string mount options.
			return nil, linuxerr.EINVAL
		}
	}

	opts.GetFilesystemOptions.Data = strings.Join(data, ",")

	return &opts, nil
}

func (createParamsContext) isFSContext() {}

// awaitingMountContext represents a filesystem configuration context that is waiting
// to be mounted with fsmount(2).
//
// +stateify savable
type awaitingMountContext struct {
	// The filesystem created using FSCONFIG_CMD_CREATE.
	filesystem *vfs.Filesystem

	// The root of the filesystem created using FSCONFIG_CMD_CREATE.
	root *vfs.Dentry

	// The MountOptions which will be used to mount the filesystem by fsmount(2).
	// Note that the filesystem-specific options have already been processed by
	// FSCONFIG_CMD_CREATE, so only the mount-specific options are relevant here.
	opts *vfs.MountOptions
}

func (awaitingMountContext) isFSContext() {}

// doneContext represents a filesystem configuration context after fsmount(2) has been called.
// TODO(b/513024543): this should be removed once reconfiguration support is added.
type doneContext struct {
}

func (doneContext) isFSContext() {}

// failedContext represents a filesystem configuration context after an operation has failed
// and left an unrecoverable state.
//
// +stateify savable
type failedContext struct {
}

func (failedContext) isFSContext() {}

// New returns a new filesystem configuration context fd.
// The context's credentials are saved as they are used for the eventual mount.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, fsname string, fileFlags uint32) (*vfs.FileDescription, error) {
	creds := auth.CredentialsFromContext(ctx)
	fd := &Fd{
		context: &createParamsContext{
			fsName: fsname,
			creds:  creds,
			params: make(map[string]FSParameter),
		},
	}

	vd := vfsObj.NewAnonVirtualDentry("[fscontext]")
	defer vd.DecRef(ctx)

	err := fd.vfsfd.Init(fd, fileFlags, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	})
	if err != nil {
		return nil, err
	}

	return &fd.vfsfd, nil
}

// clearFlags defines flags that, rather than themselves being flags, clear another flag.
// clearFlags is immutable.
var clearFlags = map[string]string{
	"rw": "ro",
}

// SetParam sets the parameter named key to param.
func (fd *Fd) SetParam(key string, param FSParameter) error {
	fd.contextMu.Lock()
	defer fd.contextMu.Unlock()

	fdContext, ok := fd.context.(*createParamsContext)
	if !ok {
		// Filesystem context is in the wrong state to add a param
		return linuxerr.EBUSY
	}

	if key == "source" {
		// source= is handled separately
		source, ok := param.Value.(FSValueString)
		if !ok {
			// source= must be a string
			return linuxerr.EINVAL
		}
		if fdContext.source != nil {
			// source= can only be set once
			return linuxerr.EINVAL
		}
		src := string(source)
		fdContext.source = &src
	} else if clearFlag, ok := clearFlags[key]; ok {
		delete(fdContext.params, clearFlag)
	} else {
		// TODO(b/513024543): refactor filesystems to parse options at fsconfig() time
		// rather than at mount time
		fdContext.params[key] = param
	}

	return nil
}

// DoCmdCreate instantiates an instance of the requested filesystem, including permission checks.
// If filesystem instantiation fails, an error will be returned and the context
// may be placed in a failed state.
func (fd *Fd) DoCmdCreate(ctx context.Context, vfsObj *vfs.VirtualFilesystem) error {
	fd.contextMu.Lock()
	defer fd.contextMu.Unlock()

	fdContext, ok := fd.context.(*createParamsContext)
	if !ok {
		// Filesystem context is in the wrong state to create the fs
		return linuxerr.EBUSY
	}

	if fdContext.source == nil {
		// Source was not specified
		return linuxerr.EINVAL
	}

	// Check for CAP_SYS_ADMIN in the fd origin's user ns.
	// Analogous to fs/super.c:mount_capable().
	//
	// Note that unlike in Linux, all filesystems marked with registeredFilesystemType.AllowUserMount
	// can be mounted by CAP_SYS_ADMIN in a non-initial user namespace. This matches the behavior
	// of the traditional mount(2) API in gVisor.
	creds := fdContext.creds
	if !creds.HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return linuxerr.EPERM
	}

	// Create the filesystem
	opts, err := fdContext.parseMountOptions()
	if err != nil {
		return err
	}
	fs, root, err := vfsObj.NewFilesystem(ctx, creds, *fdContext.source, fdContext.fsName, opts)
	if err != nil {
		// Transition into the failed state (i.e. no retries for this error)
		fd.context = &failedContext{}
		return err
	}

	// Transition into the awaitingMountContext state
	fd.context = &awaitingMountContext{
		filesystem: fs,
		root:       root,
		opts:       opts,
	}

	return nil
}

// GetFilesystem returns the filesystem and transitions the fd into the appropriate state if the
// fd is in "awaiting-mount" mode. If the fd is not in "awaiting-mount" mode, returns an error.
func (fd *Fd) GetFilesystem() (*vfs.Filesystem, *vfs.Dentry, *vfs.MountOptions, error) {
	fd.contextMu.Lock()
	defer fd.contextMu.Unlock()

	fdContext, ok := fd.context.(*awaitingMountContext)
	if !ok {
		// Filesystem context is in the wrong state
		var err error
		switch fd.context.(type) {
		case *createParamsContext:
			// Linux returns EINVAL in this case for some reason
			err = linuxerr.EINVAL
		default:
			err = linuxerr.EBUSY
		}
		return nil, nil, nil, err
	}

	fs := fdContext.filesystem
	root := fdContext.root
	opts := fdContext.opts

	// Transition into doneContext
	fd.context = &doneContext{}

	return fs, root, opts, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *Fd) Release(ctx context.Context) {
	fdContext, ok := fd.context.(*awaitingMountContext)
	if ok {
		// Destroy the created filesystem if the fd is dropped without
		// calling fsmount(2).
		fdContext.root.DecRef(ctx)
		fdContext.filesystem.DecRef(ctx)
	}
}
