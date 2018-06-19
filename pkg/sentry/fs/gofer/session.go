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

package gofer

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

type endpointMap struct {
	mu sync.RWMutex `state:"nosave"`
	// TODO: Make map with private unix sockets savable.
	m map[device.MultiDeviceKey]unix.BoundEndpoint
}

// add adds the endpoint to the map.
//
// Precondition: map must have been locked with 'lock'.
func (e *endpointMap) add(key device.MultiDeviceKey, ep unix.BoundEndpoint) {
	e.m[key] = ep
}

// remove deletes the key from the map.
//
// Precondition: map must have been locked with 'lock'.
func (e *endpointMap) remove(key device.MultiDeviceKey) {
	delete(e.m, key)
}

// lock blocks other addition and removal operations from happening while
// the backing file is being created or deleted. Returns a function that unlocks
// the endpoint map.
func (e *endpointMap) lock() func() {
	e.mu.Lock()
	return func() { e.mu.Unlock() }
}

func (e *endpointMap) get(key device.MultiDeviceKey) unix.BoundEndpoint {
	e.mu.RLock()
	ep := e.m[key]
	e.mu.RUnlock()
	return ep
}

// session holds state for each 9p session established during sys_mount.
type session struct {
	refs.AtomicRefCount

	// conn is a unet.Socket that wraps the readFD/writeFD mount option,
	// see fs/gofer/fs.go.
	conn *unet.Socket `state:"nosave"`

	// msize is the value of the msize mount option, see fs/gofer/fs.go.
	msize uint32 `state:"wait"`

	// version is the value of the version mount option, see fs/gofer/fs.go.
	version string `state:"wait"`

	// cachePolicy is the cache policy. It may be either cacheAll or cacheNone.
	cachePolicy cachePolicy `state:"wait"`

	// aname is the value of the aname mount option, see fs/gofer/fs.go.
	aname string `state:"wait"`

	// The client associated with this session. This will be initialized lazily.
	client *p9.Client `state:"nosave"`

	// The p9.File pointing to attachName via the client. This will be initialized
	// lazily.
	attach contextFile `state:"nosave"`

	// Flags provided to the mount.
	superBlockFlags fs.MountSourceFlags `state:"wait"`

	// connID is a unique identifier for the session connection.
	connID string `state:"wait"`

	// inodeMappings contains mappings of fs.Inodes associated with this session
	// to paths relative to the attach point, where inodeMappings is keyed by
	// Inode.StableAttr.InodeID.
	inodeMappings map[uint64]string `state:"wait"`

	// mounter is the EUID/EGID that mounted this file system.
	mounter fs.FileOwner `state:"wait"`

	// endpoints is used to map inodes that represent socket files to their
	// corresponding endpoint. Socket files are created as regular files in the
	// gofer and their presence in this map indicate that they should indeed be
	// socket files. This allows unix domain sockets to be used with paths that
	// belong to a gofer.
	//
	// TODO: there are few possible races with someone stat'ing the
	// file and another deleting it concurrently, where the file will not be
	// reported as socket file.
	endpoints *endpointMap `state:"wait"`
}

// Destroy tears down the session.
func (s *session) Destroy() {
	s.conn.Close()
}

// Revalidate returns true if the cache policy is does not allow for VFS caching.
func (s *session) Revalidate(*fs.Dirent) bool {
	return s.cachePolicy.revalidateDirent()
}

// TakeRefs takes an extra reference on dirent if possible.
func (s *session) Keep(d *fs.Dirent) bool {
	return s.cachePolicy.keepDirent(d.Inode)
}

// ResetInodeMappings implements fs.MountSourceOperations.ResetInodeMappings.
func (s *session) ResetInodeMappings() {
	s.inodeMappings = make(map[uint64]string)
}

// SaveInodeMapping implements fs.MountSourceOperations.SaveInodeMapping.
func (s *session) SaveInodeMapping(inode *fs.Inode, path string) {
	// This is very unintuitive. We *CANNOT* trust the inode's StableAttrs,
	// because overlay copyUp may have changed them out from under us.
	// So much for "immutable".
	sattr := inode.InodeOperations.(*inodeOperations).fileState.sattr
	s.inodeMappings[sattr.InodeID] = path
}

// newInodeOperations creates a new 9p fs.InodeOperations backed by a p9.File and attributes
// (p9.QID, p9.AttrMask, p9.Attr).
func newInodeOperations(ctx context.Context, s *session, file contextFile, qid p9.QID, valid p9.AttrMask, attr p9.Attr) (fs.StableAttr, *inodeOperations) {
	deviceKey := device.MultiDeviceKey{
		Device:          attr.RDev,
		SecondaryDevice: s.connID,
		Inode:           qid.Path,
	}

	sattr := fs.StableAttr{
		Type:      ntype(attr),
		DeviceID:  goferDevice.DeviceID(),
		InodeID:   goferDevice.Map(deviceKey),
		BlockSize: bsize(attr),
	}

	if s.endpoints != nil {
		// If unix sockets are allowed on this filesystem, check if this file is
		// supposed to be a socket file.
		if s.endpoints.get(deviceKey) != nil {
			sattr.Type = fs.Socket
		}
	}

	fileState := &inodeFileState{
		s:     s,
		file:  file,
		sattr: sattr,
		key:   deviceKey,
	}

	uattr := unstable(ctx, valid, attr, s.mounter, s.client)
	return sattr, &inodeOperations{
		fileState:       fileState,
		cachingInodeOps: fsutil.NewCachingInodeOperations(ctx, fileState, uattr, s.superBlockFlags.ForcePageCache),
	}
}

// Root returns the root of a 9p mount. This mount is bound to a 9p server
// based on conn. Otherwise configuration parameters are:
//
// * dev:         connection id
// * filesystem:  the filesystem backing the mount
// * superBlockFlags:  the mount flags describing general mount options
// * opts:        parsed 9p mount options
func Root(ctx context.Context, dev string, filesystem fs.Filesystem, superBlockFlags fs.MountSourceFlags, o opts) (*fs.Inode, error) {
	// The mounting EUID/EGID will be cached by this file system. This will
	// be used to assign ownership to files that the Gofer owns.
	mounter := fs.FileOwnerFromContext(ctx)

	conn, err := unet.NewSocket(o.fd)
	if err != nil {
		return nil, err
	}

	// Construct the session.
	s := &session{
		connID:          dev,
		conn:            conn,
		msize:           o.msize,
		version:         o.version,
		cachePolicy:     o.policy,
		aname:           o.aname,
		superBlockFlags: superBlockFlags,
		mounter:         mounter,
	}

	if o.privateunixsocket {
		s.endpoints = &endpointMap{m: make(map[device.MultiDeviceKey]unix.BoundEndpoint)}
	}

	// Construct the MountSource with the session and superBlockFlags.
	m := fs.NewMountSource(s, filesystem, superBlockFlags)

	// Send the Tversion request.
	s.client, err = p9.NewClient(s.conn, s.msize, s.version)
	if err != nil {
		// Drop our reference on the session, it needs to be torn down.
		s.DecRef()
		return nil, err
	}

	// Notify that we're about to call the Gofer and block.
	ctx.UninterruptibleSleepStart(false)
	// Send the Tattach request.
	s.attach.file, err = s.client.Attach(s.aname)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		// Same as above.
		s.DecRef()
		return nil, err
	}

	qid, valid, attr, err := s.attach.getAttr(ctx, p9.AttrMaskAll())
	if err != nil {
		s.attach.close(ctx)
		// Same as above, but after we execute the Close request.
		s.DecRef()
		return nil, err
	}

	sattr, iops := newInodeOperations(ctx, s, s.attach, qid, valid, attr)
	return fs.NewInode(iops, m, sattr), nil
}
