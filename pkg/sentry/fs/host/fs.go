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

// Package host implements an fs.Filesystem for files backed by host
// file descriptors.
package host

import (
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// FilesystemName is the name under which Filesystem is registered.
const FilesystemName = "whitelistfs"

const (
	// whitelistKey is the mount option containing a comma-separated list
	// of host paths to whitelist.
	whitelistKey = "whitelist"

	// rootPathKey is the mount option containing the root path of the
	// mount.
	rootPathKey = "root"

	// dontTranslateOwnershipKey is the key to superOperations.dontTranslateOwnership.
	dontTranslateOwnershipKey = "dont_translate_ownership"
)

// maxTraversals determines link traversals in building the whitelist.
const maxTraversals = 10

// Filesystem is a pseudo file system that is only available during the setup
// to lock down the configurations. This filesystem should only be mounted at root.
//
// Think twice before exposing this to applications.
//
// +stateify savable
type Filesystem struct {
	// whitelist is a set of host paths to whitelist.
	paths []string
}

var _ fs.Filesystem = (*Filesystem)(nil)

// Name is the identifier of this file system.
func (*Filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount prohibits users from using mount(2) with this file system.
func (*Filesystem) AllowUserMount() bool {
	return false
}

// AllowUserList allows this filesystem to be listed in /proc/filesystems.
func (*Filesystem) AllowUserList() bool {
	return true
}

// Flags returns that there is nothing special about this file system.
func (*Filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns an fs.Inode exposing the host file system.  It is intended to be locked
// down in PreExec below.
func (f *Filesystem) Mount(ctx context.Context, _ string, flags fs.MountSourceFlags, data string, _ interface{}) (*fs.Inode, error) {
	// Parse generic comma-separated key=value options.
	options := fs.GenericMountSourceOptions(data)

	// Grab the whitelist if one was specified.
	// TODO(edahlgren/mpratt/hzy): require another option "testonly" in order to allow
	// no whitelist.
	if wl, ok := options[whitelistKey]; ok {
		f.paths = strings.Split(wl, "|")
		delete(options, whitelistKey)
	}

	// If the rootPath was set, use it. Othewise default to the root of the
	// host fs.
	rootPath := "/"
	if rp, ok := options[rootPathKey]; ok {
		rootPath = rp
		delete(options, rootPathKey)

		// We must relativize the whitelisted paths to the new root.
		for i, p := range f.paths {
			rel, err := filepath.Rel(rootPath, p)
			if err != nil {
				return nil, fmt.Errorf("whitelist path %q must be a child of root path %q", p, rootPath)
			}
			f.paths[i] = path.Join("/", rel)
		}
	}
	fd, err := open(nil, rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find root: %v", err)
	}

	var dontTranslateOwnership bool
	if v, ok := options[dontTranslateOwnershipKey]; ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid value for %q: %v", dontTranslateOwnershipKey, err)
		}
		dontTranslateOwnership = b
		delete(options, dontTranslateOwnershipKey)
	}

	// Fail if the caller passed us more options than we know about.
	if len(options) > 0 {
		return nil, fmt.Errorf("unsupported mount options: %v", options)
	}

	// The mounting EUID/EGID will be cached by this file system. This will
	// be used to assign ownership to files that we own.
	owner := fs.FileOwnerFromContext(ctx)

	// Construct the host file system mount and inode.
	msrc := newMountSource(ctx, rootPath, owner, f, flags, dontTranslateOwnership)
	return newInode(ctx, msrc, fd, false /* saveable */, false /* donated */)
}

// InstallWhitelist locks down the MountNamespace to only the currently installed
// Dirents and the given paths.
func (f *Filesystem) InstallWhitelist(ctx context.Context, m *fs.MountNamespace) error {
	return installWhitelist(ctx, m, f.paths)
}

func installWhitelist(ctx context.Context, m *fs.MountNamespace, paths []string) error {
	if len(paths) == 0 || (len(paths) == 1 && paths[0] == "") {
		// Warning will be logged during filter installation if the empty
		// whitelist matters (allows for host file access).
		return nil
	}

	// Done tracks entries already added.
	done := make(map[string]bool)
	root := m.Root()
	defer root.DecRef()

	for i := 0; i < len(paths); i++ {
		// Make sure the path is absolute. This is a sanity check.
		if !path.IsAbs(paths[i]) {
			return fmt.Errorf("path %q is not absolute", paths[i])
		}

		// We need to add all the intermediate paths, in case one of
		// them is a symlink that needs to be resolved.
		for j := 1; j <= len(paths[i]); j++ {
			if j < len(paths[i]) && paths[i][j] != '/' {
				continue
			}
			current := paths[i][:j]

			// Lookup the given component in the tree.
			remainingTraversals := uint(maxTraversals)
			d, err := m.FindLink(ctx, root, nil, current, &remainingTraversals)
			if err != nil {
				log.Warningf("populate failed for %q: %v", current, err)
				continue
			}

			// It's critical that this DecRef happens after the
			// freeze below. This ensures that the dentry is in
			// place to be frozen. Otherwise, we freeze without
			// these entries.
			defer d.DecRef()

			// Expand the last component if necessary.
			if current == paths[i] {
				// Is it a directory or symlink?
				sattr := d.Inode.StableAttr
				if fs.IsDir(sattr) {
					for name := range childDentAttrs(ctx, d) {
						paths = append(paths, path.Join(current, name))
					}
				}
				if fs.IsSymlink(sattr) {
					// Only expand symlinks once. The
					// folder structure may contain
					// recursive symlinks and we don't want
					// to end up infinitely expanding this
					// symlink. This is safe because this
					// is the last component. If a later
					// path wants to symlink something
					// beneath this symlink that will still
					// be handled by the FindLink above.
					if done[current] {
						continue
					}

					s, err := d.Inode.Readlink(ctx)
					if err != nil {
						log.Warningf("readlink failed for %q: %v", current, err)
						continue
					}
					if path.IsAbs(s) {
						paths = append(paths, s)
					} else {
						target := path.Join(path.Dir(current), s)
						paths = append(paths, target)
					}
				}
			}

			// Only report this one once even though we may look
			// it up more than once. If we whitelist /a/b,/a then
			// /a will be "done" when it is looked up for /a/b,
			// however we still need to expand all of its contents
			// when whitelisting /a.
			if !done[current] {
				log.Debugf("whitelisted: %s", current)
			}
			done[current] = true
		}
	}

	// Freeze the mount tree in place. This prevents any new paths from
	// being opened and any old ones from being removed. If we do provide
	// tmpfs mounts, we'll want to freeze/thaw those separately.
	m.Freeze()
	return nil
}

func childDentAttrs(ctx context.Context, d *fs.Dirent) map[string]fs.DentAttr {
	dirname, _ := d.FullName(nil /* root */)
	dir, err := d.Inode.GetFile(ctx, d, fs.FileFlags{Read: true})
	if err != nil {
		log.Warningf("failed to open directory %q: %v", dirname, err)
		return nil
	}
	dir.DecRef()
	var stubSerializer fs.CollectEntriesSerializer
	if err := dir.Readdir(ctx, &stubSerializer); err != nil {
		log.Warningf("failed to iterate on host directory %q: %v", dirname, err)
		return nil
	}
	delete(stubSerializer.Entries, ".")
	delete(stubSerializer.Entries, "..")
	return stubSerializer.Entries
}

// newMountSource constructs a new host fs.MountSource
// relative to a root path. The root should match the mount point.
func newMountSource(ctx context.Context, root string, mounter fs.FileOwner, filesystem fs.Filesystem, flags fs.MountSourceFlags, dontTranslateOwnership bool) *fs.MountSource {
	return fs.NewMountSource(&superOperations{
		root:                   root,
		inodeMappings:          make(map[uint64]string),
		mounter:                mounter,
		dontTranslateOwnership: dontTranslateOwnership,
	}, filesystem, flags)
}

// superOperations implements fs.MountSourceOperations.
//
// +stateify savable
type superOperations struct {
	fs.SimpleMountSourceOperations

	// root is the path of the mount point. All inode mappings
	// are relative to this root.
	root string

	// inodeMappings contains mappings of fs.Inodes associated
	// with this MountSource to paths under root.
	inodeMappings map[uint64]string

	// mounter is the cached EUID/EGID that mounted this file system.
	mounter fs.FileOwner

	// dontTranslateOwnership indicates whether to not translate file
	// ownership.
	//
	// By default, files/directories owned by the sandbox uses UID/GID
	// of the mounter. For files/directories that are not owned by the
	// sandbox, file UID/GID is translated to a UID/GID which cannot
	// be mapped in the sandboxed application's user namespace. The
	// UID/GID will look like the nobody UID/GID (65534) but is not
	// strictly owned by the user "nobody".
	//
	// If whitelistfs is a lower filesystem in an overlay, set
	// dont_translate_ownership=true in mount options.
	dontTranslateOwnership bool
}

var _ fs.MountSourceOperations = (*superOperations)(nil)

// ResetInodeMappings implements fs.MountSourceOperations.ResetInodeMappings.
func (m *superOperations) ResetInodeMappings() {
	m.inodeMappings = make(map[uint64]string)
}

// SaveInodeMapping implements fs.MountSourceOperations.SaveInodeMapping.
func (m *superOperations) SaveInodeMapping(inode *fs.Inode, path string) {
	// This is very unintuitive. We *CANNOT* trust the inode's StableAttrs,
	// because overlay copyUp may have changed them out from under us.
	// So much for "immutable".
	sattr := inode.InodeOperations.(*inodeOperations).fileState.sattr
	m.inodeMappings[sattr.InodeID] = path
}

// Keep implements fs.MountSourceOperations.Keep.
//
// TODO(b/72455313,b/77596690): It is possible to change the permissions on a
// host file while it is in the dirent cache (say from RO to RW), but it is not
// possible to re-open the file with more relaxed permissions, since the host
// FD is already open and stored in the inode.
//
// Using the dirent LRU cache increases the odds that this bug is encountered.
// Since host file access is relatively fast anyways, we disable the LRU cache
// for host fs files.  Once we can properly deal with permissions changes and
// re-opening host files, we should revisit whether or not to make use of the
// LRU cache.
func (*superOperations) Keep(*fs.Dirent) bool {
	return false
}

func init() {
	fs.RegisterFilesystem(&Filesystem{})
}
