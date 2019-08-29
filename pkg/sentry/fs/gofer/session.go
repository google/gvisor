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

package gofer

import (
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/unet"
)

// DefaultDirentCacheSize is the default dirent cache size for 9P mounts. It can
// be adjusted independently from the other dirent caches.
var DefaultDirentCacheSize uint64 = fs.DefaultDirentCacheSize

// +stateify savable
type endpointMaps struct {
	// mu protexts the direntMap, the keyMap, and the pathMap below.
	mu sync.RWMutex `state:"nosave"`

	// direntMap links sockets to their dirents.
	// It is filled concurrently with the keyMap and is stored upon save.
	// Before saving, this map is used to populate the pathMap.
	direntMap map[transport.BoundEndpoint]*fs.Dirent

	// keyMap links MultiDeviceKeys (containing inode IDs) to their sockets.
	// It is not stored during save because the inode ID may change upon restore.
	keyMap map[device.MultiDeviceKey]transport.BoundEndpoint `state:"nosave"`

	// pathMap links the sockets to their paths.
	// It is filled before saving from the direntMap and is stored upon save.
	// Upon restore, this map is used to re-populate the keyMap.
	pathMap map[transport.BoundEndpoint]string
}

// add adds the endpoint to the maps.
// A reference is taken on the dirent argument.
//
// Precondition: maps must have been locked with 'lock'.
func (e *endpointMaps) add(key device.MultiDeviceKey, d *fs.Dirent, ep transport.BoundEndpoint) {
	e.keyMap[key] = ep
	d.IncRef()
	e.direntMap[ep] = d
}

// remove deletes the key from the maps.
//
// Precondition: maps must have been locked with 'lock'.
func (e *endpointMaps) remove(key device.MultiDeviceKey) {
	endpoint := e.get(key)
	delete(e.keyMap, key)

	d := e.direntMap[endpoint]
	d.DecRef()
	delete(e.direntMap, endpoint)
}

// lock blocks other addition and removal operations from happening while
// the backing file is being created or deleted. Returns a function that unlocks
// the endpoint map.
func (e *endpointMaps) lock() func() {
	e.mu.Lock()
	return func() { e.mu.Unlock() }
}

// get returns the endpoint mapped to the given key.
//
// Precondition: maps must have been locked for reading.
func (e *endpointMaps) get(key device.MultiDeviceKey) transport.BoundEndpoint {
	return e.keyMap[key]
}

// session holds state for each 9p session established during sys_mount.
//
// +stateify savable
type session struct {
	refs.AtomicRefCount

	// msize is the value of the msize mount option, see fs/gofer/fs.go.
	msize uint32 `state:"wait"`

	// version is the value of the version mount option, see fs/gofer/fs.go.
	version string `state:"wait"`

	// cachePolicy is the cache policy.
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

	// limitHostFDTranslation is the value used for
	// CachingInodeOperationsOptions.LimitHostFDTranslation for all
	// CachingInodeOperations created by the session.
	limitHostFDTranslation bool

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
	// TODO(b/77154739): there are few possible races with someone stat'ing the
	// file and another deleting it concurrently, where the file will not be
	// reported as socket file.
	endpoints *endpointMaps `state:"wait"`
}

// Destroy tears down the session.
func (s *session) Destroy() {
	s.client.Close()
}

// Revalidate implements MountSourceOperations.Revalidate.
func (s *session) Revalidate(ctx context.Context, name string, parent, child *fs.Inode) bool {
	return s.cachePolicy.revalidate(ctx, name, parent, child)
}

// Keep implements MountSourceOperations.Keep.
func (s *session) Keep(d *fs.Dirent) bool {
	return s.cachePolicy.keep(d)
}

// CacheReaddir implements MountSourceOperations.CacheReaddir.
func (s *session) CacheReaddir() bool {
	return s.cachePolicy.cacheReaddir()
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
//
// Endpoints lock must not be held if socket == false.
func newInodeOperations(ctx context.Context, s *session, file contextFile, qid p9.QID, valid p9.AttrMask, attr p9.Attr, socket bool) (fs.StableAttr, *inodeOperations) {
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
		if socket {
			sattr.Type = fs.Socket
		} else {
			// If unix sockets are allowed on this filesystem, check if this file is
			// supposed to be a socket file.
			unlock := s.endpoints.lock()
			if s.endpoints.get(deviceKey) != nil {
				sattr.Type = fs.Socket
			}
			unlock()
		}
	}

	fileState := &inodeFileState{
		s:     s,
		file:  file,
		sattr: sattr,
		key:   deviceKey,
	}
	if s.cachePolicy == cacheRemoteRevalidating && fs.IsFile(sattr) {
		fileState.hostMappable = fsutil.NewHostMappable(fileState)
	}

	uattr := unstable(ctx, valid, attr, s.mounter, s.client)
	return sattr, &inodeOperations{
		fileState: fileState,
		cachingInodeOps: fsutil.NewCachingInodeOperations(ctx, fileState, uattr, fsutil.CachingInodeOperationsOptions{
			ForcePageCache:         s.superBlockFlags.ForcePageCache,
			LimitHostFDTranslation: s.limitHostFDTranslation,
		}),
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
	s := session{
		connID:                 dev,
		msize:                  o.msize,
		version:                o.version,
		cachePolicy:            o.policy,
		aname:                  o.aname,
		superBlockFlags:        superBlockFlags,
		limitHostFDTranslation: o.limitHostFDTranslation,
		mounter:                mounter,
	}
	s.EnableLeakCheck("gofer.session")

	if o.privateunixsocket {
		s.endpoints = newEndpointMaps()
	}

	// Construct the MountSource with the session and superBlockFlags.
	m := fs.NewMountSource(ctx, &s, filesystem, superBlockFlags)

	// Given that gofer files can consume host FDs, restrict the number
	// of files that can be held by the cache.
	m.SetDirentCacheMaxSize(DefaultDirentCacheSize)
	m.SetDirentCacheLimiter(fs.DirentCacheLimiterFromContext(ctx))

	// Send the Tversion request.
	s.client, err = p9.NewClient(conn, s.msize, s.version)
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

	sattr, iops := newInodeOperations(ctx, &s, s.attach, qid, valid, attr, false)
	return fs.NewInode(ctx, iops, m, sattr), nil
}

// newEndpointMaps creates a new endpointMaps.
func newEndpointMaps() *endpointMaps {
	return &endpointMaps{
		direntMap: make(map[transport.BoundEndpoint]*fs.Dirent),
		keyMap:    make(map[device.MultiDeviceKey]transport.BoundEndpoint),
		pathMap:   make(map[transport.BoundEndpoint]string),
	}
}

// fillKeyMap populates key and dirent maps upon restore from saved
// pathmap.
func (s *session) fillKeyMap(ctx context.Context) error {
	unlock := s.endpoints.lock()
	defer unlock()

	for ep, dirPath := range s.endpoints.pathMap {
		_, file, err := s.attach.walk(ctx, splitAbsolutePath(dirPath))
		if err != nil {
			return fmt.Errorf("error filling endpointmaps, failed to walk to %q: %v", dirPath, err)
		}

		qid, _, attr, err := file.getAttr(ctx, p9.AttrMaskAll())
		if err != nil {
			return fmt.Errorf("failed to get file attributes of %s: %v", dirPath, err)
		}

		key := device.MultiDeviceKey{
			Device:          attr.RDev,
			SecondaryDevice: s.connID,
			Inode:           qid.Path,
		}

		s.endpoints.keyMap[key] = ep
	}
	return nil
}

// fillPathMap populates paths for endpoints from dirents in direntMap
// before save.
func (s *session) fillPathMap() error {
	unlock := s.endpoints.lock()
	defer unlock()

	for ep, dir := range s.endpoints.direntMap {
		mountRoot := dir.MountRoot()
		defer mountRoot.DecRef()
		dirPath, _ := dir.FullName(mountRoot)
		if dirPath == "" {
			return fmt.Errorf("error getting path from dirent")
		}
		s.endpoints.pathMap[ep] = dirPath
	}
	return nil
}

// restoreEndpointMaps recreates and fills the key and dirent maps.
func (s *session) restoreEndpointMaps(ctx context.Context) error {
	// When restoring, only need to create the keyMap because the dirent and path
	// maps got stored through the save.
	s.endpoints.keyMap = make(map[device.MultiDeviceKey]transport.BoundEndpoint)
	if err := s.fillKeyMap(ctx); err != nil {
		return fmt.Errorf("failed to insert sockets into endpoint map: %v", err)
	}

	// Re-create pathMap because it can no longer be trusted as socket paths can
	// change while process continues to run. Empty pathMap will be re-filled upon
	// next save.
	s.endpoints.pathMap = make(map[transport.BoundEndpoint]string)
	return nil
}
