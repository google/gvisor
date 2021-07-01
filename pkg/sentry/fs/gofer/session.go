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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// DefaultDirentCacheSize is the default dirent cache size for 9P mounts. It can
// be adjusted independently from the other dirent caches.
var DefaultDirentCacheSize uint64 = fs.DefaultDirentCacheSize

// +stateify savable
type overrideInfo struct {
	dirent *fs.Dirent

	// endpoint is set when dirent points to a socket. inode must not be set.
	endpoint transport.BoundEndpoint

	// inode is set when dirent points to a pipe. endpoint must not be set.
	inode *fs.Inode
}

func (l *overrideInfo) inodeType() fs.InodeType {
	switch {
	case l.endpoint != nil:
		return fs.Socket
	case l.inode != nil:
		return fs.Pipe
	}
	panic("endpoint or node must be set")
}

// +stateify savable
type overrideMaps struct {
	// mu protexts the keyMap, and the pathMap below.
	mu sync.RWMutex `state:"nosave"`

	// keyMap links MultiDeviceKeys (containing inode IDs) to their sockets/pipes.
	// It is not stored during save because the inode ID may change upon restore.
	keyMap map[device.MultiDeviceKey]*overrideInfo `state:"nosave"`

	// pathMap links the sockets/pipes to their paths.
	// It is filled before saving from the direntMap and is stored upon save.
	// Upon restore, this map is used to re-populate the keyMap.
	pathMap map[*overrideInfo]string
}

// addBoundEndpoint adds the bound endpoint to the map.
// A reference is taken on the dirent argument.
//
// Precondition: maps must have been locked with 'lock'.
func (e *overrideMaps) addBoundEndpoint(key device.MultiDeviceKey, d *fs.Dirent, ep transport.BoundEndpoint) {
	d.IncRef()
	e.keyMap[key] = &overrideInfo{dirent: d, endpoint: ep}
}

// addPipe adds the pipe inode to the map.
// A reference is taken on the dirent argument.
//
// Precondition: maps must have been locked with 'lock'.
func (e *overrideMaps) addPipe(key device.MultiDeviceKey, d *fs.Dirent, inode *fs.Inode) {
	d.IncRef()
	e.keyMap[key] = &overrideInfo{dirent: d, inode: inode}
}

// remove deletes the key from the maps.
//
// Precondition: maps must have been locked with 'lock'.
func (e *overrideMaps) remove(ctx context.Context, key device.MultiDeviceKey) {
	endpoint := e.keyMap[key]
	delete(e.keyMap, key)
	endpoint.dirent.DecRef(ctx)
}

// lock blocks other addition and removal operations from happening while
// the backing file is being created or deleted. Returns a function that unlocks
// the endpoint map.
// +checklocksacquire:e.mu
func (e *overrideMaps) lock() {
	e.mu.Lock()
}

// +checklocksrelease:e.mu
func (e *overrideMaps) unlock() {
	e.mu.Unlock()
}

// getBoundEndpoint returns the bound endpoint mapped to the given key.
//
// Precondition: maps must have been locked.
func (e *overrideMaps) getBoundEndpoint(key device.MultiDeviceKey) transport.BoundEndpoint {
	if v := e.keyMap[key]; v != nil {
		return v.endpoint
	}
	return nil
}

// getPipe returns the pipe inode mapped to the given key.
//
// Precondition: maps must have been locked.
func (e *overrideMaps) getPipe(key device.MultiDeviceKey) *fs.Inode {
	if v := e.keyMap[key]; v != nil {
		return v.inode
	}
	return nil
}

// getType returns the inode type if there is a corresponding endpoint for the
// given key. Returns false otherwise.
func (e *overrideMaps) getType(key device.MultiDeviceKey) (fs.InodeType, bool) {
	e.mu.Lock()
	v := e.keyMap[key]
	e.mu.Unlock()

	if v != nil {
		return v.inodeType(), true
	}
	return 0, false
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

	// overlayfsStaleRead when set causes the readonly handle to be invalidated
	// after file is open for write.
	overlayfsStaleRead bool

	// connID is a unique identifier for the session connection.
	connID string `state:"wait"`

	// inodeMappings contains mappings of fs.Inodes associated with this session
	// to paths relative to the attach point, where inodeMappings is keyed by
	// Inode.StableAttr.InodeID.
	inodeMappings map[uint64]string `state:"wait"`

	// mounter is the EUID/EGID that mounted this file system.
	mounter fs.FileOwner `state:"wait"`

	// overrides is used to map inodes that represent socket/pipes files to their
	// corresponding endpoint/iops. These files are created as regular files in
	// the gofer and their presence in this map indicate that they should indeed
	// be socket/pipe files. This allows unix domain sockets and named pipes to
	// be used with paths that belong to a gofer.
	//
	// There are a few possible races with someone stat'ing the file and another
	// deleting it concurrently, where the file will not be reported as socket
	// file.
	overrides *overrideMaps `state:"wait"`
}

// Destroy tears down the session.
func (s *session) Destroy(ctx context.Context) {
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
	switch iops := inode.InodeOperations.(type) {
	case *inodeOperations:
		s.inodeMappings[iops.fileState.sattr.InodeID] = path
	case *fifo:
		s.inodeMappings[iops.fileIops.fileState.sattr.InodeID] = path
	default:
		panic(fmt.Sprintf("Invalid type: %T", iops))
	}
}

// newInodeOperations creates a new 9p fs.InodeOperations backed by a p9.File
// and attributes (p9.QID, p9.AttrMask, p9.Attr).
//
// Endpoints lock must not be held if socket == false.
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

	if s.overrides != nil && sattr.Type == fs.RegularFile {
		// If overrides are allowed on this filesystem, check if this file is
		// supposed to be of a different type, e.g. socket.
		if t, ok := s.overrides.getType(deviceKey); ok {
			sattr.Type = t
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
		overlayfsStaleRead:     o.overlayfsStaleRead,
		mounter:                mounter,
	}
	s.EnableLeakCheck("gofer.session")

	if o.privateunixsocket {
		s.overrides = newOverrideMaps()
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
		s.DecRef(ctx)
		return nil, err
	}

	// Notify that we're about to call the Gofer and block.
	ctx.UninterruptibleSleepStart(false)
	// Send the Tattach request.
	s.attach.file, err = s.client.Attach(s.aname)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		// Same as above.
		s.DecRef(ctx)
		return nil, err
	}

	qid, valid, attr, err := s.attach.getAttr(ctx, p9.AttrMaskAll())
	if err != nil {
		s.attach.close(ctx)
		// Same as above, but after we execute the Close request.
		s.DecRef(ctx)
		return nil, err
	}

	sattr, iops := newInodeOperations(ctx, &s, s.attach, qid, valid, attr)
	return fs.NewInode(ctx, iops, m, sattr), nil
}

// newOverrideMaps creates a new overrideMaps.
func newOverrideMaps() *overrideMaps {
	return &overrideMaps{
		keyMap:  make(map[device.MultiDeviceKey]*overrideInfo),
		pathMap: make(map[*overrideInfo]string),
	}
}

// fillKeyMap populates key and dirent maps upon restore from saved pathmap.
func (s *session) fillKeyMap(ctx context.Context) error {
	s.overrides.lock()
	defer s.overrides.unlock()

	for ep, dirPath := range s.overrides.pathMap {
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

		s.overrides.keyMap[key] = ep
	}
	return nil
}

// fillPathMap populates paths for overrides from dirents in direntMap
// before save.
func (s *session) fillPathMap(ctx context.Context) error {
	s.overrides.lock()
	defer s.overrides.unlock()

	for _, endpoint := range s.overrides.keyMap {
		mountRoot := endpoint.dirent.MountRoot()
		defer mountRoot.DecRef(ctx)
		dirPath, _ := endpoint.dirent.FullName(mountRoot)
		if dirPath == "" {
			return fmt.Errorf("error getting path from dirent")
		}
		s.overrides.pathMap[endpoint] = dirPath
	}
	return nil
}

// restoreEndpointMaps recreates and fills the key and dirent maps.
func (s *session) restoreEndpointMaps(ctx context.Context) error {
	// When restoring, only need to create the keyMap because the dirent and path
	// maps got stored through the save.
	s.overrides.keyMap = make(map[device.MultiDeviceKey]*overrideInfo)
	if err := s.fillKeyMap(ctx); err != nil {
		return fmt.Errorf("failed to insert sockets into endpoint map: %v", err)
	}

	// Re-create pathMap because it can no longer be trusted as socket paths can
	// change while process continues to run. Empty pathMap will be re-filled upon
	// next save.
	s.overrides.pathMap = make(map[*overrideInfo]string)
	return nil
}
