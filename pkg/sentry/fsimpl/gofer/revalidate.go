// Copyright 2021 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

type errPartialRevalidation struct{}

// Error implements error.Error.
func (errPartialRevalidation) Error() string {
	return "partial revalidation"
}

type errRevalidationStepDone struct{}

// Error implements error.Error.
func (errRevalidationStepDone) Error() string {
	return "stop revalidation"
}

// revalidatePath checks cached dentries for external modification. File
// attributes are refreshed and cache is invalidated in case the dentry has been
// deleted, or a new file/directory created in its place.
//
// Revalidation stops at symlinks and mount points. The caller is responsible
// for revalidating again after symlinks are resolved and after changing to
// different mounts.
//
// Preconditions:
//   - fs.renameMu must be locked.
func (fs *filesystem) revalidatePath(ctx context.Context, rpOrig resolvingPath, start *dentry, ds **[]*dentry) error {
	// Revalidation is done even if start is synthetic in case the path is
	// something like: ../non_synthetic_file.
	if fs.opts.interop != InteropModeShared {
		return nil
	}

	// Copy resolving path to walk the path for revalidation.
	rp := rpOrig.copy()
	err := fs.revalidate(ctx, rp, start, ds)
	rp.Release(ctx)
	return err
}

// revalidateOne does the same as revalidatePath, but checks a single dentry.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - parent must have up to date metadata.
func (fs *filesystem) revalidateOne(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, ds **[]*dentry) error {
	// Skip revalidation for interop mode different than InteropModeShared or
	// if the parent is synthetic (child must be synthetic too, but it cannot be
	// replaced without first replacing the parent).
	if parent.cachedMetadataAuthoritative() {
		return nil
	}

	parent.childrenMu.Lock()
	child, ok := parent.children[name]
	parent.childrenMu.Unlock()
	if !ok {
		return nil
	}

	state := makeRevalidateState(parent, false /* refreshStart */)
	defer state.release()
	// Note that child can not be nil, because we don't cache negative entries
	// when InteropModeShared is in effect.
	state.add(child)
	return state.doRevalidation(ctx, vfsObj, ds)
}

// revalidate revalidates path components in rp until done returns true, or
// until a mount point or symlink is reached. It may send multiple MultiGetAttr
// calls to the gofer to handle ".." in the path.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - InteropModeShared is in effect.
func (fs *filesystem) revalidate(ctx context.Context, rp resolvingPath, start *dentry, ds **[]*dentry) error {
	state := makeRevalidateState(start, true /* refreshStart */)
	defer state.release()

done:
	for cur := start; !rp.done(); {
		var err error
		cur, err = fs.revalidateStep(ctx, rp, cur, state)
		if err != nil {
			switch err.(type) {
			case errPartialRevalidation:
				if err := state.doRevalidation(ctx, rp.VirtualFilesystem(), ds); err != nil {
					return err
				}

				// Reset state to release any remaining locks and restart from where
				// stepping stopped.
				state.reset(cur /* start */, true /* refreshStart */)

			case errRevalidationStepDone:
				break done

			default:
				return err
			}
		}
	}
	return state.doRevalidation(ctx, rp.VirtualFilesystem(), ds)
}

// revalidateStep walks one element of the path and updates revalidationState
// with the dentry if needed. It may also stop the stepping or ask for a
// partial revalidation. Partial revalidation requires the caller to revalidate
// the current revalidationState, release all locks, and resume stepping.
// In case a symlink is hit, revalidation stops and the caller is responsible
// for calling revalidate again after the symlink is resolved. Revalidation may
// also stop for other reasons, like hitting a child not in the cache.
//
// Returns:
//   - (dentry, nil): step worked, continue stepping.`
//   - (dentry, errPartialRevalidation): revalidation should be done with the
//     state gathered so far. Then continue stepping with the remainder of the
//     path, starting at `dentry`.
//   - (nil, errRevalidationStepDone): revalidation doesn't need to step any
//     further. It hit a symlink, a mount point, or an uncached dentry.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - !rp.Done().
//   - InteropModeShared is in effect (assumes no negative dentries).
func (fs *filesystem) revalidateStep(ctx context.Context, rp resolvingPath, d *dentry, state *revalidateState) (*dentry, error) {
	switch name := rp.Component(); name {
	case ".":
		// Do nothing.

	case "..":
		// Partial revalidation is required when ".." is hit because metadata locks
		// can only be acquired from parent to child to avoid deadlocks.
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, errRevalidationStepDone{}
		} else if isRoot || d.parent.Load() == nil {
			rp.Advance()
			return d, errPartialRevalidation{}
		}
		// We must assume that d.parent is correct, because if d has been moved
		// elsewhere in the remote filesystem so that its parent has changed,
		// we have no way of determining its new parent's location in the
		// filesystem.
		//
		// Call rp.CheckMount() before updating d.parent's metadata, since if
		// we traverse to another mount then d.parent's metadata is irrelevant.
		if err := rp.CheckMount(ctx, &d.parent.Load().vfsd); err != nil {
			return nil, errRevalidationStepDone{}
		}
		rp.Advance()
		return d.parent.Load(), errPartialRevalidation{}

	default:
		d.childrenMu.Lock()
		child, ok := d.children[name]
		d.childrenMu.Unlock()
		if !ok {
			// child is not cached, no need to validate any further.
			return nil, errRevalidationStepDone{}
		}

		// Note that child can not be nil, because we don't cache negative entries
		// when InteropModeShared is in effect.
		state.add(child)

		// Symlink must be resolved before continuing with revalidation.
		if child.isSymlink() {
			return nil, errRevalidationStepDone{}
		}

		d = child
	}

	rp.Advance()
	return d, nil
}

// Precondition: fs.renameMu must be locked.
func (d *dentry) invalidate(ctx context.Context, vfsObj *vfs.VirtualFilesystem, ds **[]*dentry) {
	// If the dentry is a mountpoint, InvalidateDentry may drop the
	// last reference on it, resulting in lock recursion. To avoid
	// this, take a dentry reference first, then drop it while
	// deferring the call to dentry.checkCachingLocked().
	d.IncRef()
	rcs := vfsObj.InvalidateDentry(ctx, &d.vfsd)
	for _, rc := range rcs {
		rc.DecRef(ctx)
	}
	d.decRefNoCaching()

	// Re-evaluate its caching status (i.e. if it has 0 references, drop it).
	// The dentry will be reloaded next time it's accessed.
	*ds = appendDentry(*ds, d)

	parent := d.parent.Load()
	parent.opMu.RLock()
	defer parent.opMu.RUnlock()
	parent.childrenMu.Lock()
	defer parent.childrenMu.Unlock()

	if d.isSynthetic() {
		// Normally we don't mark invalidated dentries as deleted since
		// they may still exist (but at a different path), and also for
		// consistency with Linux. However, synthetic files are guaranteed
		// to become unreachable if their dentries are invalidated, so
		// treat their invalidation as deletion.
		d.setDeleted()
		d.decRefNoCaching()
		*ds = appendDentry(*ds, d)

		parent.syntheticChildren--
		parent.clearDirentsLocked()
	}

	// Since the opMu was just reacquired above, re-check that the
	// parent's child with this name is still the same. Do not touch it if
	// it has been replaced with a different one.
	if child := parent.children[d.name]; child == d {
		// Invalidate dentry so it gets reloaded next time it's accessed.
		delete(parent.children, d.name)
	}
}

// revalidateStatePool caches revalidateState instances to save array
// allocations for dentries and names.
var revalidateStatePool = sync.Pool{
	New: func() any {
		return &revalidateState{}
	},
}

// revalidateState keeps state related to a revalidation request. It keeps track
// of {name, dentry} list being revalidated, as well as metadata locks on the
// dentries. The list must be in ancestry order, in other words `n` must be
// `n-1` child.
type revalidateState struct {
	// start is the dentry where to start the revalidation of dentries.
	start *dentry

	// refreshStart indicates whether the attributes of the start dentry should
	// be refreshed.
	refreshStart bool

	// names is just a slice of names which can be used while making LISAFS RPCs.
	// This exists to avoid the cost of repeated string slice allocation to make
	// RPCs.
	names []string

	// dentries is the list of dentries that need to be revalidated. The first
	// dentry is a child of start and each successive dentry is a child of the
	// previous.
	dentries []*dentry
}

func makeRevalidateState(start *dentry, refreshStart bool) *revalidateState {
	r := revalidateStatePool.Get().(*revalidateState)
	r.start = start
	r.refreshStart = refreshStart
	return r
}

// release must be called after the caller is done with this object. It releases
// all metadata locks and resources.
func (r *revalidateState) release() {
	r.reset(nil /* start */, false /* refreshStart */)
	revalidateStatePool.Put(r)
}

// Preconditions:
//   - d != nil.
//   - d is a descendant of all dentries in r.dentries.
func (r *revalidateState) add(d *dentry) {
	r.dentries = append(r.dentries, d)
}

// reset releases all metadata locks and resets all fields to allow this
// instance to be reused.
// +checklocksignore
func (r *revalidateState) reset(start *dentry, refreshStart bool) {
	r.start = start
	r.refreshStart = refreshStart
	r.names = r.names[:0]
	r.dentries = r.dentries[:0]
}
