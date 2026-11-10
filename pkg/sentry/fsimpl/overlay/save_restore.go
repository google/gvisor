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

package overlay

import (
	goContext "context"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (d *dentry) afterLoad(goContext.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
		d.fs.dirInoCacheMu.Lock()
		d.fs.restoredDentries = append(d.fs.restoredDentries, d)
		d.fs.dirInoCacheMu.Unlock()
	}
	// Directory listings were built from layer inode numbers, or from a
	// cache that is not restored. The next readdir builds them again.
	d.dirents = nil
}

// rebuildRestoredDirInos rekeys copy-up origins and derives the identities of
// surviving dentries from their current layers.
func (fs *filesystem) rebuildRestoredDirInos(ctx context.Context) error {
	fs.dirInoCacheMu.Lock()
	pending := fs.restoredDentries
	fs.restoredDentries = nil
	origins := fs.dirInoCache
	// Pin the layer while it is stated. destroyLocked drops its own layer
	// references only after it takes dirInoCacheMu, so the pin is still held
	// when that DecRef runs.
	type pinnedLayer struct {
		d  *dentry
		vd vfs.VirtualDentry
	}
	pins := make([]pinnedLayer, 0, len(pending))
	for _, d := range pending {
		if d.refs.Load() < 0 {
			continue
		}
		vd, ok := d.layerIdentityVD()
		if !ok {
			continue
		}
		vd.IncRef()
		pins = append(pins, pinnedLayer{d: d, vd: vd})
	}
	fs.dirInoCacheMu.Unlock()
	defer func() {
		for _, pin := range pins {
			pin.vd.DecRef(ctx)
		}
	}()

	// Only copy-up origins require saved state. Their upper references identify
	// the current objects even when the backing filesystem changed at restore.
	rebuilt := make(map[layerDevNoAndIno]*overlayOrigin, len(origins))
	identities := make(map[overlayIdentity]struct{}, len(origins))
	var discarded []*overlayOrigin
	for _, origin := range origins {
		stat, err := fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  origin.upper,
			Start: origin.upper,
		}, &vfs.StatOptions{Mask: linux.STATX_INO})
		if err != nil {
			return err
		}
		if stat.Mask&linux.STATX_INO == 0 {
			return linuxerr.EREMOTE
		}
		key := layerDevNoAndIno{layerDevNumber{stat.DevMajor, stat.DevMinor}, stat.Ino}
		if _, ok := rebuilt[key]; ok {
			return linuxerr.EREMOTE
		}
		lowerStat, err := fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  origin.lower,
			Start: origin.lower,
		}, &vfs.StatOptions{Mask: linux.STATX_INO | linux.STATX_NLINK})
		if err != nil {
			return err
		}
		const lowerMask = linux.STATX_INO | linux.STATX_NLINK
		if lowerStat.Mask&lowerMask != lowerMask {
			return linuxerr.EREMOTE
		}
		if lowerStat.Nlink != 1 {
			// Other lower names can now expose the origin. The independent
			// upper file must use its own identity instead of that origin.
			discarded = append(discarded, origin)
			continue
		}
		origin.identity = fs.encodeIdentity(layerDevNoAndIno{
			layerDevNumber{lowerStat.DevMajor, lowerStat.DevMinor}, lowerStat.Ino,
		})
		if _, ok := identities[origin.identity]; ok {
			return linuxerr.EREMOTE
		}
		identities[origin.identity] = struct{}{}
		rebuilt[key] = origin
	}
	fs.dirInoCacheMu.Lock()
	fs.dirInoCache = rebuilt
	fs.dirInoCacheMu.Unlock()
	for _, origin := range discarded {
		origin.upper.DecRef(ctx)
		origin.lower.DecRef(ctx)
	}

	for _, pin := range pins {
		key, ok := pin.d.statLayerIdentity(ctx, pin.vd)
		if !ok {
			return linuxerr.EREMOTE
		}
		pin.d.assignOverlayIdentity(ctx, key)
	}
	return nil
}

// dropUnlinkedOrigin releases copy-up metadata after the last link and overlay
// reference disappear. The layer references are still held by d.
func (d *dentry) dropUnlinkedOrigin(ctx context.Context) {
	d.fs.dirInoCacheMu.Lock()
	origin := d.origin
	d.origin = nil
	if origin == nil {
		d.fs.dirInoCacheMu.Unlock()
		return
	}
	origin.liveDentries--
	haveAliases := origin.liveDentries != 0
	d.fs.dirInoCacheMu.Unlock()
	if haveAliases {
		return
	}
	if !d.vfsd.IsDead() || !d.upperVD.Ok() || d.isDir() {
		return
	}
	stat, err := d.fs.vfsfs.VirtualFilesystem().StatAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  d.upperVD,
		Start: d.upperVD,
	}, &vfs.StatOptions{Mask: linux.STATX_INO | linux.STATX_NLINK})
	if err != nil || stat.Mask&(linux.STATX_INO|linux.STATX_NLINK) != linux.STATX_INO|linux.STATX_NLINK || stat.Nlink != 0 {
		return
	}
	key := layerDevNoAndIno{layerDevNumber{stat.DevMajor, stat.DevMinor}, stat.Ino}
	d.fs.dirInoCacheMu.Lock()
	ok := d.fs.dirInoCache[key] == origin && origin.liveDentries == 0
	if ok {
		delete(d.fs.dirInoCache, key)
	}
	d.fs.dirInoCacheMu.Unlock()
	if ok {
		origin.upper.DecRef(ctx)
		origin.lower.DecRef(ctx)
	}
}

// layerIdentityVD returns the layer dentry that identifies d.
// Directories other than the root use the bottom layer. The root and every
// other file use the top layer.
func (d *dentry) layerIdentityVD() (vfs.VirtualDentry, bool) {
	var vd vfs.VirtualDentry
	switch {
	case d.isDir() && d.parent.Load() != nil:
		d.iterLayers(func(layerVD vfs.VirtualDentry, _ bool) bool {
			vd = layerVD
			return true
		})
	case d.upperVD.Ok():
		vd = d.upperVD
	case len(d.lowerVDs) > 0:
		vd = d.lowerVDs[0]
	default:
		return vfs.VirtualDentry{}, false
	}
	return vd, vd.Ok()
}

func (d *dentry) statLayerIdentity(ctx context.Context, vd vfs.VirtualDentry) (layerDevNoAndIno, bool) {
	stat, err := d.fs.vfsfs.VirtualFilesystem().StatAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  vd,
		Start: vd,
	}, &vfs.StatOptions{
		Mask: linux.STATX_INO,
	})
	if err != nil {
		log.Warningf("overlay: failed to read layer identity for %q: %v", d.name, err)
		return layerDevNoAndIno{}, false
	}
	if stat.Mask&linux.STATX_INO == 0 {
		return layerDevNoAndIno{}, false
	}
	return layerDevNoAndIno{
		layerDevNumber: layerDevNumber{stat.DevMajor, stat.DevMinor},
		ino:            stat.Ino,
	}, true
}

func (fd *directoryFD) afterLoad(goContext.Context) {
	fd.dirents = nil
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ goContext.Context, parent *dentry) {
	d.parent.Store(parent)
}

// saveAccessACL is called by stateify.
func (d *dentry) saveAccessACL() *vfs.PosixACL {
	return d.accessACL.Load()
}

// loadAccessACL is called by stateify.
func (d *dentry) loadAccessACL(_ goContext.Context, accessACL *vfs.PosixACL) {
	d.accessACL.Store(accessACL)
}

// saveDefaultACL is called by stateify.
func (d *dentry) saveDefaultACL() *vfs.PosixACL {
	return d.defaultACL.Load()
}

// loadDefaultACL is called by stateify.
func (d *dentry) loadDefaultACL(_ goContext.Context, defaultACL *vfs.PosixACL) {
	d.defaultACL.Store(defaultACL)
}
