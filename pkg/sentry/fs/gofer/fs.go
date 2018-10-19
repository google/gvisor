// Copyright 2018 Google LLC
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

// Package gofer implements a remote 9p filesystem.
package gofer

import (
	"errors"
	"fmt"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// The following are options defined by the Linux 9p client that we support,
// see Documentation/filesystems/9p.txt.
const (
	// The transport method.
	transportKey = "trans"

	// The file tree to access when the file server
	// is exporting several file systems. Stands for "attach name".
	anameKey = "aname"

	// The caching policy.
	cacheKey = "cache"

	// The file descriptor for reading with trans=fd.
	readFDKey = "rfdno"

	// The file descriptor for writing with trans=fd.
	writeFDKey = "wfdno"

	// The number of bytes to use for a 9p packet payload.
	msizeKey = "msize"

	// The 9p protocol version.
	versionKey = "version"

	// If set to true allows the creation of unix domain sockets inside the
	// sandbox using files backed by the gofer. If set to false, unix sockets
	// cannot be bound to gofer files without an overlay on top.
	privateUnixSocketKey = "privateunixsocket"
)

// defaultAname is the default attach name.
const defaultAname = "/"

// defaultMSize is the message size used for chunking large read and write requests.
// This has been tested to give good enough performance up to 64M.
const defaultMSize = 1024 * 1024 // 1M

// defaultVersion is the default 9p protocol version. Will negotiate downwards with
// file server if needed.
var defaultVersion = p9.HighestVersionString()

// Number of names of non-children to cache, preventing unneeded walks.  64 is
// plenty for nodejs, which seems to stat about 4 children on every require().
const nonChildrenCacheSize = 64

var (
	// ErrNoTransport is returned when there is no 'trans' option.
	ErrNoTransport = errors.New("missing required option: 'trans='")

	// ErrNoReadFD is returned when there is no 'rfdno' option.
	ErrNoReadFD = errors.New("missing required option: 'rfdno='")

	// ErrNoWriteFD is returned when there is no 'wfdno' option.
	ErrNoWriteFD = errors.New("missing required option: 'wfdno='")
)

// filesystem is a 9p client.
//
// +stateify savable
type filesystem struct{}

func init() {
	fs.RegisterFilesystem(&filesystem{})
}

// FilesystemName is the name under which the filesystem is registered.
// The name matches fs/9p/vfs_super.c:v9fs_fs_type.name.
const FilesystemName = "9p"

// Name is the name of the filesystem.
func (*filesystem) Name() string {
	return FilesystemName
}

// AllowUserMount prohibits users from using mount(2) with this file system.
func (*filesystem) AllowUserMount() bool {
	return false
}

// AllowUserList allows this filesystem to be listed in /proc/filesystems.
func (*filesystem) AllowUserList() bool {
	return true
}

// Flags returns that there is nothing special about this file system.
//
// The 9p Linux client returns FS_RENAME_DOES_D_MOVE, see fs/9p/vfs_super.c.
func (*filesystem) Flags() fs.FilesystemFlags {
	return 0
}

// Mount returns an attached 9p client that can be positioned in the vfs.
func (f *filesystem) Mount(ctx context.Context, device string, flags fs.MountSourceFlags, data string) (*fs.Inode, error) {
	// Parse and validate the mount options.
	o, err := options(data)
	if err != nil {
		return nil, err
	}

	// Construct the 9p root to mount. We intentionally diverge from Linux in that
	// the first Tversion and Tattach requests are done lazily.
	return Root(ctx, device, f, flags, o)
}

// opts are parsed 9p mount options.
type opts struct {
	fd                int
	aname             string
	policy            cachePolicy
	msize             uint32
	version           string
	privateunixsocket bool
}

// options parses mount(2) data into structured options.
func options(data string) (opts, error) {
	var o opts

	// Parse generic comma-separated key=value options, this file system expects them.
	options := fs.GenericMountSourceOptions(data)

	// Check for the required 'trans=fd' option.
	trans, ok := options[transportKey]
	if !ok {
		return o, ErrNoTransport
	}
	if trans != "fd" {
		return o, fmt.Errorf("unsupported transport: 'trans=%s'", trans)
	}
	delete(options, transportKey)

	// Check for the required 'rfdno=' option.
	srfd, ok := options[readFDKey]
	if !ok {
		return o, ErrNoReadFD
	}
	delete(options, readFDKey)

	// Check for the required 'wfdno=' option.
	swfd, ok := options[writeFDKey]
	if !ok {
		return o, ErrNoWriteFD
	}
	delete(options, writeFDKey)

	// Parse the read fd.
	rfd, err := strconv.Atoi(srfd)
	if err != nil {
		return o, fmt.Errorf("invalid fd for 'rfdno=%s': %v", srfd, err)
	}

	// Parse the write fd.
	wfd, err := strconv.Atoi(swfd)
	if err != nil {
		return o, fmt.Errorf("invalid fd for 'wfdno=%s': %v", swfd, err)
	}

	// Require that the read and write fd are the same.
	if rfd != wfd {
		return o, fmt.Errorf("fd in 'rfdno=%d' and 'wfdno=%d' must match", rfd, wfd)
	}
	o.fd = rfd

	// Parse the attach name.
	o.aname = defaultAname
	if an, ok := options[anameKey]; ok {
		o.aname = an
		delete(options, anameKey)
	}

	// Parse the cache policy. Reject unsupported policies.
	o.policy = cacheAll
	if policy, ok := options[cacheKey]; ok {
		cp, err := parseCachePolicy(policy)
		if err != nil {
			return o, err
		}
		o.policy = cp
		delete(options, cacheKey)
	}

	// Parse the message size. Reject malformed options.
	o.msize = uint32(defaultMSize)
	if m, ok := options[msizeKey]; ok {
		i, err := strconv.ParseUint(m, 10, 32)
		if err != nil {
			return o, fmt.Errorf("invalid message size for 'msize=%s': %v", m, err)
		}
		o.msize = uint32(i)
		delete(options, msizeKey)
	}

	// Parse the protocol version.
	o.version = defaultVersion
	if v, ok := options[versionKey]; ok {
		o.version = v
		delete(options, versionKey)
	}

	// Parse the unix socket policy. Reject non-booleans.
	if v, ok := options[privateUnixSocketKey]; ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return o, fmt.Errorf("invalid boolean value for '%s=%s': %v", privateUnixSocketKey, v, err)
		}
		o.privateunixsocket = b
		delete(options, privateUnixSocketKey)
	}

	// Fail to attach if the caller wanted us to do something that we
	// don't support.
	if len(options) > 0 {
		return o, fmt.Errorf("unsupported mount options: %v", options)
	}

	return o, nil
}
