// Copyright 2020 The gVisor Authors.
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

package user

import (
	"fmt"
	"path"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ResolveExecutablePath resolves the given executable name given the working
// dir and environment.
func ResolveExecutablePath(ctx context.Context, args *kernel.CreateProcessArgs) (string, error) {
	name := args.Filename
	if len(name) == 0 {
		if len(args.Argv) == 0 {
			return "", fmt.Errorf("no filename or command provided")
		}
		name = args.Argv[0]
	}

	// Absolute paths can be used directly.
	if path.IsAbs(name) {
		return name, nil
	}

	// Paths with '/' in them should be joined to the working directory, or
	// to the root if working directory is not set.
	if strings.IndexByte(name, '/') > 0 {
		wd := args.WorkingDirectory
		if wd == "" {
			wd = "/"
		}
		if !path.IsAbs(wd) {
			return "", fmt.Errorf("working directory %q must be absolute", wd)
		}
		return path.Join(wd, name), nil
	}

	// Otherwise, We must lookup the name in the paths.
	paths := getPath(args.Envv)
	if kernel.VFS2Enabled {
		f, err := resolveVFS2(ctx, args.Credentials, args.MountNamespaceVFS2, paths, name)
		if err != nil {
			return "", fmt.Errorf("error finding executable %q in PATH %v: %v", name, paths, err)
		}
		return f, nil
	}

	f, err := resolve(ctx, args.MountNamespace, paths, name)
	if err != nil {
		return "", fmt.Errorf("error finding executable %q in PATH %v: %v", name, paths, err)
	}
	return f, nil
}

func resolve(ctx context.Context, mns *fs.MountNamespace, paths []string, name string) (string, error) {
	root := fs.RootFromContext(ctx)
	if root == nil {
		// Caller has no root. Don't bother traversing anything.
		return "", linuxerr.ENOENT
	}
	defer root.DecRef(ctx)
	for _, p := range paths {
		if !path.IsAbs(p) {
			// Relative paths aren't safe, no one should be using them.
			log.Warningf("Skipping relative path %q in $PATH", p)
			continue
		}

		binPath := path.Join(p, name)
		traversals := uint(linux.MaxSymlinkTraversals)
		d, err := mns.FindInode(ctx, root, nil, binPath, &traversals)
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.EACCES, err) {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return "", err
		}
		defer d.DecRef(ctx)

		// Check that it is a regular file.
		if !fs.IsRegular(d.Inode.StableAttr) {
			continue
		}

		// Check whether we can read and execute the found file.
		if err := d.Inode.CheckPermission(ctx, fs.PermMask{Read: true, Execute: true}); err != nil {
			log.Infof("Found executable at %q, but user cannot execute it: %v", binPath, err)
			continue
		}
		return path.Join("/", p, name), nil
	}

	// Couldn't find it.
	return "", linuxerr.ENOENT
}

func resolveVFS2(ctx context.Context, creds *auth.Credentials, mns *vfs.MountNamespace, paths []string, name string) (string, error) {
	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)
	for _, p := range paths {
		if !path.IsAbs(p) {
			// Relative paths aren't safe, no one should be using them.
			log.Warningf("Skipping relative path %q in $PATH", p)
			continue
		}

		binPath := path.Join(p, name)
		pop := &vfs.PathOperation{
			Root:               root,
			Start:              root,
			Path:               fspath.Parse(binPath),
			FollowFinalSymlink: true,
		}
		opts := &vfs.OpenOptions{
			FileExec: true,
			Flags:    linux.O_RDONLY,
		}
		dentry, err := root.Mount().Filesystem().VirtualFilesystem().OpenAt(ctx, creds, pop, opts)
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.EACCES, err) {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return "", err
		}
		dentry.DecRef(ctx)

		return binPath, nil
	}

	// Couldn't find it.
	return "", linuxerr.ENOENT
}

// getPath returns the PATH as a slice of strings given the environment
// variables.
func getPath(env []string) []string {
	const prefix = "PATH="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.Split(strings.TrimPrefix(e, prefix), ":")
		}
	}
	return nil
}
