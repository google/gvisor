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

package fdimport

import (
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// devptsPath is the path at which the console is exposed.
const devptsPath = "/dev/pts"

// ExposeConsole exposes the console TTY ttyFile, as returned by Import, as a
// replica node in the devpts filesystem mounted at /dev/pts in mntns. This
// lets applications find the name of the console, e.g. with ttyname(3).
//
// It replaces the stdio FDs in fdTable that refer to ttyFile with FDs opened
// through the node, and returns the TTY file of these FDs. The credentials in
// ctx own the node.
func ExposeConsole(ctx context.Context, mntns *vfs.MountNamespace, fdTable *kernel.FDTable, ttyFile *host.TTYFileDescription) (*host.TTYFileDescription, error) {
	creds := auth.CredentialsFromContext(ctx)
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	vfsObj := root.Mount().Filesystem().VirtualFilesystem()

	ptsVD, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse(devptsPath),
		FollowFinalSymlink: true,
	}, &vfs.GetDentryOptions{})
	if err != nil {
		return nil, fmt.Errorf("finding %s: %w", devptsPath, err)
	}
	defer ptsVD.DecRef(ctx)

	node, err := devpts.AddExternalReplica(ctx, ptsVD, creds, ttyFile.TTY())
	if err != nil {
		return nil, fmt.Errorf("adding console to %s: %w", devptsPath, err)
	}
	ttyFile.SetTTYNode(node)
	cu := cleanup.Make(func() {
		ttyFile.SetTTYNode(nil)
		node.Remove(ctx)
	})
	defer cu.Clean()

	// All stdio FDs that refer to the console share one file description,
	// so that they share its status flags. Replace it with one new file
	// description.
	consoleFDs := make(map[int32]kernel.FDFlags)
	var statusFlags uint32
	for fd := int32(0); fd < 3; fd++ {
		file, flags := fdTable.Get(fd)
		if file == nil {
			continue
		}
		if file.Impl() == ttyFile {
			consoleFDs[fd] = flags
			statusFlags = file.StatusFlags()
		}
		file.DecRef(ctx)
	}
	if len(consoleFDs) == 0 {
		return nil, fmt.Errorf("console is not a stdio FD")
	}
	newFile, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: ptsVD,
		Path:  fspath.Parse(strconv.FormatUint(uint64(node.Index()), 10)),
	}, &vfs.OpenOptions{
		Flags: statusFlags | linux.O_NOCTTY,
	})
	if err != nil {
		return nil, fmt.Errorf("opening console in %s: %w", devptsPath, err)
	}
	defer newFile.DecRef(ctx)
	// The path may name another file if a mount covers the node.
	newTTYFile, ok := newFile.Impl().(*host.TTYFileDescription)
	if !ok || newTTYFile.TTY() != ttyFile.TTY() {
		return nil, fmt.Errorf("%s/%d is not the console", devptsPath, node.Index())
	}

	for fd, flags := range consoleFDs {
		displaced, err := fdTable.NewFDAt(ctx, fd, newFile, flags)
		if err != nil {
			return nil, fmt.Errorf("replacing FD %d: %w", fd, err)
		}
		if displaced != nil {
			displaced.DecRef(ctx)
		}
	}
	cu.Release()
	return newTTYFile, nil
}
