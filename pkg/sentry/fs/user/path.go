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
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// ResolveExecutablePath resolves the given executable name given the working
// dir and environment.
func ResolveExecutablePath(ctx context.Context, creds *auth.Credentials, mns *fs.MountNamespace, envv []string, wd, name string) (string, error) {
	// Absolute paths can be used directly.
	if path.IsAbs(name) {
		return name, nil
	}

	// Paths with '/' in them should be joined to the working directory, or
	// to the root if working directory is not set.
	if strings.IndexByte(name, '/') > 0 {
		if wd == "" {
			wd = "/"
		}
		if !path.IsAbs(wd) {
			return "", fmt.Errorf("working directory %q must be absolute", wd)
		}
		return path.Join(wd, name), nil
	}

	// Otherwise, We must lookup the name in the paths, starting from the
	// calling context's root directory.
	paths := getPath(envv)

	root := fs.RootFromContext(ctx)
	if root == nil {
		// Caller has no root. Don't bother traversing anything.
		return "", syserror.ENOENT
	}
	defer root.DecRef()
	for _, p := range paths {
		if !path.IsAbs(p) {
			// Relative paths aren't safe, no one should be using them.
			log.Warningf("Skipping relative path %q in $PATH", p)
			continue
		}

		binPath := path.Join(p, name)
		traversals := uint(linux.MaxSymlinkTraversals)
		d, err := mns.FindInode(ctx, root, nil, binPath, &traversals)
		if err == syserror.ENOENT || err == syserror.EACCES {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return "", err
		}
		defer d.DecRef()

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
	return "", syserror.ENOENT
}

// ResolveExecutablePathVFS2 resolves the given executable name given the
// working dir and environment.
func ResolveExecutablePathVFS2(ctx context.Context, creds *auth.Credentials, mns *vfs.MountNamespace, envv []string, wd, name string) (string, error) {
	// Absolute paths can be used directly.
	if path.IsAbs(name) {
		return name, nil
	}

	// Paths with '/' in them should be joined to the working directory, or
	// to the root if working directory is not set.
	if strings.IndexByte(name, '/') > 0 {
		if wd == "" {
			wd = "/"
		}
		if !path.IsAbs(wd) {
			return "", fmt.Errorf("working directory %q must be absolute", wd)
		}
		return path.Join(wd, name), nil
	}

	// Otherwise, We must lookup the name in the paths, starting from the
	// calling context's root directory.
	paths := getPath(envv)

	root := mns.Root()
	defer root.DecRef()
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
		if err == syserror.ENOENT || err == syserror.EACCES {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return "", err
		}
		dentry.DecRef()

		return binPath, nil
	}

	// Couldn't find it.
	return "", syserror.ENOENT
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
