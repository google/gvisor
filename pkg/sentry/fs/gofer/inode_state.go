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
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// Some fs implementations may not support atime, ctime, or mtime in getattr.
// The unstable() logic would try to use clock time for them. However, we do not
// want to use such time during S/R as that would cause restore timestamp
// checking failure. Hence a dummy stable-time clock is needed.
//
// Note that application-visible UnstableAttrs either come from CachingInodeOps
// (in which case they are saved), or they are requested from the gofer on each
// stat (for non-caching), so the dummy time only affects the modification
// timestamp check.
type dummyClock struct {
	time.Clock
}

// Now returns a stable dummy time.
func (d *dummyClock) Now() time.Time {
	return time.Time{}
}

type dummyClockContext struct {
	context.Context
}

// Value implements context.Context
func (d *dummyClockContext) Value(key interface{}) interface{} {
	switch key {
	case time.CtxRealtimeClock:
		return &dummyClock{}
	default:
		return d.Context.Value(key)
	}
}

// beforeSave is invoked by stateify.
func (i *inodeFileState) beforeSave() {
	if _, ok := i.s.inodeMappings[i.sattr.InodeID]; !ok {
		panic(fmt.Sprintf("failed to find path for inode number %d. Device %s contains %s", i.sattr.InodeID, i.s.connID, fs.InodeMappings(i.s.inodeMappings)))
	}
	if i.sattr.Type == fs.RegularFile {
		uattr, err := i.unstableAttr(&dummyClockContext{context.Background()})
		if err != nil {
			panic(fs.ErrSaveRejection{fmt.Errorf("failed to get unstable atttribute of %s: %v", i.s.inodeMappings[i.sattr.InodeID], err)})
		}
		i.savedUAttr = &uattr
	}
}

// saveLoading is invoked by stateify.
func (i *inodeFileState) saveLoading() struct{} {
	return struct{}{}
}

// splitAbsolutePath splits the path on slashes ignoring the leading slash.
func splitAbsolutePath(path string) []string {
	if len(path) == 0 {
		panic("There is no path!")
	}
	if path != filepath.Clean(path) {
		panic(fmt.Sprintf("path %q is not clean", path))
	}
	// This case is to return {} rather than {""}
	if path == "/" {
		return []string{}
	}
	if path[0] != '/' {
		panic(fmt.Sprintf("path %q is not absolute", path))
	}

	s := strings.Split(path, "/")

	// Since p is absolute, the first component of s
	// is an empty string. We must remove that.
	return s[1:]
}

// loadLoading is invoked by stateify.
func (i *inodeFileState) loadLoading(_ struct{}) {
	i.loading.Lock()
}

// afterLoad is invoked by stateify.
func (i *inodeFileState) afterLoad() {
	load := func() (err error) {
		// See comment on i.loading().
		defer func() {
			if err == nil {
				i.loading.Unlock()
			}
		}()

		// Manually restore the p9.File.
		name, ok := i.s.inodeMappings[i.sattr.InodeID]
		if !ok {
			// This should be impossible, see assertion in
			// beforeSave.
			return fmt.Errorf("failed to find path for inode number %d. Device %s contains %s", i.sattr.InodeID, i.s.connID, fs.InodeMappings(i.s.inodeMappings))
		}
		ctx := &dummyClockContext{context.Background()}

		_, i.file, err = i.s.attach.walk(ctx, splitAbsolutePath(name))
		if err != nil {
			return fs.ErrCorruption{fmt.Errorf("failed to walk to %q: %v", name, err)}
		}

		// Remap the saved inode number into the gofer device using the
		// actual device and actual inode that exists in our new
		// environment.
		qid, mask, attrs, err := i.file.getAttr(ctx, p9.AttrMaskAll())
		if err != nil {
			return fs.ErrCorruption{fmt.Errorf("failed to get file attributes of %s: %v", name, err)}
		}
		if !mask.RDev {
			return fs.ErrCorruption{fmt.Errorf("file %s lacks device", name)}
		}
		i.key = device.MultiDeviceKey{
			Device:          attrs.RDev,
			SecondaryDevice: i.s.connID,
			Inode:           qid.Path,
		}
		if !goferDevice.Load(i.key, i.sattr.InodeID) {
			return fs.ErrCorruption{fmt.Errorf("gofer device %s -> %d conflict in gofer device mappings: %s", i.key, i.sattr.InodeID, goferDevice)}
		}

		if i.sattr.Type == fs.RegularFile {
			var cindex int
			var notUsed string
			fmt.Sscanf(i.s.connID, "9pfs-%d%v", &cindex, &notUsed)
			env, ok := fs.CurrentRestoreEnvironment(cindex)
			if !ok {
				return errors.New("missing restore environment")
			}
			uattr := unstable(ctx, mask, attrs, i.s.mounter, i.s.client)
			if env.ValidateFileSize && uattr.Size != i.savedUAttr.Size {
				return fs.ErrCorruption{fmt.Errorf("file size has changed for %s: previously %d, now %d", i.s.inodeMappings[i.sattr.InodeID], i.savedUAttr.Size, uattr.Size)}
			}
			if env.ValidateFileTimestamp && uattr.ModificationTime != i.savedUAttr.ModificationTime {
				return fs.ErrCorruption{fmt.Errorf("file modification time has changed for %s: previously %v, now %v", i.s.inodeMappings[i.sattr.InodeID], i.savedUAttr.ModificationTime, uattr.ModificationTime)}
			}
			i.savedUAttr = nil
		}

		return nil
	}

	fs.Async(fs.CatchError(load))
}
