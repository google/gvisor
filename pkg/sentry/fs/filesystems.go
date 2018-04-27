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

package fs

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

// FilesystemFlags matches include/linux/fs.h:file_system_type.fs_flags.
type FilesystemFlags int

const (
	// FilesystemRequiresDev indicates that the file system requires a device name
	// on mount. It is used to construct the output of /proc/filesystems.
	FilesystemRequiresDev FilesystemFlags = 1

	// Currently other flags are not used, but can be pulled in from
	// include/linux/fs.h:file_system_type as needed.
)

// Filesystem is a mountable file system.
type Filesystem interface {
	// Name is the unique identifier of the file system. It corresponds to the
	// filesystemtype argument of sys_mount and will appear in the output of
	// /proc/filesystems.
	Name() string

	// Flags indicate common properties of the file system.
	Flags() FilesystemFlags

	// Mount generates a mountable Inode backed by device and configured
	// using file system independent flags and file system dependent
	// data options.
	Mount(ctx context.Context, device string, flags MountSourceFlags, data string) (*Inode, error)

	// AllowUserMount determines whether mount(2) is allowed to mount a
	// file system of this type.
	AllowUserMount() bool
}

// filesystems is the global set of registered file systems. It does not need
// to be saved. Packages registering and unregistering file systems must do so
// before calling save/restore methods.
var filesystems = struct {
	// mu protects registered below.
	mu sync.Mutex

	// registered is a set of registered Filesystems.
	registered map[string]Filesystem
}{
	registered: make(map[string]Filesystem),
}

// RegisterFilesystem registers a new file system that is visible to mount and
// the /proc/filesystems list. Packages implementing Filesystem should call
// RegisterFilesystem in init().
func RegisterFilesystem(f Filesystem) {
	filesystems.mu.Lock()
	defer filesystems.mu.Unlock()

	if _, ok := filesystems.registered[f.Name()]; ok {
		panic(fmt.Sprintf("filesystem already registered at %q", f.Name()))
	}
	filesystems.registered[f.Name()] = f
}

// UnregisterFilesystem removes a file system from the global set. To keep the
// file system set compatible with save/restore, UnregisterFilesystem must be
// called before save/restore methods.
//
// For instance, packages may unregister their file system after it is mounted.
// This makes sense for pseudo file systems that should not be visible or
// mountable. See whitelistfs in fs/host/fs.go for one example.
func UnregisterFilesystem(name string) {
	filesystems.mu.Lock()
	defer filesystems.mu.Unlock()

	delete(filesystems.registered, name)
}

// FindFilesystem returns a Filesystem registered at name or (nil, false) if name
// is not a file system type that can be found in /proc/filesystems.
func FindFilesystem(name string) (Filesystem, bool) {
	filesystems.mu.Lock()
	defer filesystems.mu.Unlock()

	f, ok := filesystems.registered[name]
	return f, ok
}

// GetFilesystems returns the set of registered filesystems in a consistent order.
func GetFilesystems() []Filesystem {
	filesystems.mu.Lock()
	defer filesystems.mu.Unlock()

	var ss []Filesystem
	for _, s := range filesystems.registered {
		ss = append(ss, s)
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].Name() < ss[j].Name() })
	return ss
}

// MountSourceFlags represents all mount option flags as a struct.
type MountSourceFlags struct {
	// ReadOnly corresponds to mount(2)'s "MS_RDONLY" and indicates that
	// the filesystem should be mounted read-only.
	ReadOnly bool

	// NoAtime corresponds to mount(2)'s "MS_NOATIME" and indicates that
	// the filesystem should not update access time in-place.
	NoAtime bool

	// ForcePageCache causes all filesystem I/O operations to use the page
	// cache, even when the platform supports direct mapped I/O. This
	// doesn't correspond to any Linux mount options.
	ForcePageCache bool
}

// GenericMountSourceOptions splits a string containing comma separated tokens of the
// format 'key=value' or 'key' into a map of keys and values. For example:
//
// data = "key0=value0,key1,key2=value2" -> map{'key0':'value0','key1':'','key2':'value2'}
//
// If data contains duplicate keys, then the last token wins.
func GenericMountSourceOptions(data string) map[string]string {
	options := make(map[string]string)
	if len(data) == 0 {
		// Don't return a nil map, callers might not be expecting that.
		return options
	}

	// Parse options and skip empty ones.
	for _, opt := range strings.Split(data, ",") {
		if len(opt) > 0 {
			res := strings.SplitN(opt, "=", 2)
			if len(res) == 2 {
				options[res[0]] = res[1]
			} else {
				options[opt] = ""
			}
		}
	}
	return options
}
