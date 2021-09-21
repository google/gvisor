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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/p9"
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
// * fs.renameMu must be locked.
func (fs *filesystem) revalidatePath(ctx context.Context, rpOrig *vfs.ResolvingPath, start *dentry, ds **[]*dentry) error {
	// Revalidation is done even if start is synthetic in case the path is
	// something like: ../non_synthetic_file.
	if fs.opts.interop != InteropModeShared {
		return nil
	}

	// Copy resolving path to walk the path for revalidation.
	rp := rpOrig.Copy()
	err := fs.revalidate(ctx, rp, start, rp.Done, ds)
	rp.Release(ctx)
	return err
}

// revalidateParentDir does the same as revalidatePath, but stops at the parent.
//
// Preconditions:
// * fs.renameMu must be locked.
func (fs *filesystem) revalidateParentDir(ctx context.Context, rpOrig *vfs.ResolvingPath, start *dentry, ds **[]*dentry) error {
	// Revalidation is done even if start is synthetic in case the path is
	// something like: ../non_synthetic_file and parent is non synthetic.
	if fs.opts.interop != InteropModeShared {
		return nil
	}

	// Copy resolving path to walk the path for revalidation.
	rp := rpOrig.Copy()
	err := fs.revalidate(ctx, rp, start, rp.Final, ds)
	rp.Release(ctx)
	return err
}

// revalidateOne does the same as revalidatePath, but checks a single dentry.
//
// Preconditions:
// * fs.renameMu must be locked.
func (fs *filesystem) revalidateOne(ctx context.Context, vfsObj *vfs.VirtualFilesystem, parent *dentry, name string, ds **[]*dentry) error {
	// Skip revalidation for interop mode different than InteropModeShared or
	// if the parent is synthetic (child must be synthetic too, but it cannot be
	// replaced without first replacing the parent).
	if parent.cachedMetadataAuthoritative() {
		return nil
	}

	parent.dirMu.Lock()
	child, ok := parent.children[name]
	parent.dirMu.Unlock()
	if !ok {
		return nil
	}

	state := makeRevalidateState(parent)
	defer state.release()

	state.add(name, child)
	return fs.revalidateHelper(ctx, vfsObj, state, ds)
}

// revalidate revalidates path components in rp until done returns true, or
// until a mount point or symlink is reached. It may send multiple MultiGetAttr
// calls to the gofer to handle ".." in the path.
//
// Preconditions:
// * fs.renameMu must be locked.
// * InteropModeShared is in effect.
func (fs *filesystem) revalidate(ctx context.Context, rp *vfs.ResolvingPath, start *dentry, done func() bool, ds **[]*dentry) error {
	state := makeRevalidateState(start)
	defer state.release()

	// Skip synthetic dentries because the start dentry cannot be replaced in case
	// it has been created in the remote file system.
	if !start.isSynthetic() {
		state.add("", start)
	}

done:
	for cur := start; !done(); {
		var err error
		cur, err = fs.revalidateStep(ctx, rp, cur, state)
		if err != nil {
			switch err.(type) {
			case errPartialRevalidation:
				if err := fs.revalidateHelper(ctx, rp.VirtualFilesystem(), state, ds); err != nil {
					return err
				}

				// Reset state to release any remaining locks and restart from where
				// stepping stopped.
				state.reset()
				state.start = cur

				// Skip synthetic dentries because the start dentry cannot be replaced in
				// case it has been created in the remote file system.
				if !cur.isSynthetic() {
					state.add("", cur)
				}

			case errRevalidationStepDone:
				break done

			default:
				return err
			}
		}
	}
	return fs.revalidateHelper(ctx, rp.VirtualFilesystem(), state, ds)
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
// * (dentry, nil): step worked, continue stepping.`
// * (dentry, errPartialRevalidation): revalidation should be done with the
//     state gathered so far. Then continue stepping with the remainder of the
//     path, starting at `dentry`.
// * (nil, errRevalidationStepDone): revalidation doesn't need to step any
//     further. It hit a symlink, a mount point, or an uncached dentry.
//
// Preconditions:
// * fs.renameMu must be locked.
// * !rp.Done().
// * InteropModeShared is in effect (assumes no negative dentries).
func (fs *filesystem) revalidateStep(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, state *revalidateState) (*dentry, error) {
	switch name := rp.Component(); name {
	case ".":
		// Do nothing.

	case "..":
		// Partial revalidation is required when ".." is hit because metadata locks
		// can only be acquired from parent to child to avoid deadlocks.
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, errRevalidationStepDone{}
		} else if isRoot || d.parent == nil {
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
		if err := rp.CheckMount(ctx, &d.parent.vfsd); err != nil {
			return nil, errRevalidationStepDone{}
		}
		rp.Advance()
		return d.parent, errPartialRevalidation{}

	default:
		d.dirMu.Lock()
		child, ok := d.children[name]
		d.dirMu.Unlock()
		if !ok {
			// child is not cached, no need to validate any further.
			return nil, errRevalidationStepDone{}
		}

		state.add(name, child)

		// Symlink must be resolved before continuing with revalidation.
		if child.isSymlink() {
			return nil, errRevalidationStepDone{}
		}

		d = child
	}

	rp.Advance()
	return d, nil
}

// revalidateHelper calls the gofer to stat all dentries in `state`. It will
// update or invalidate dentries in the cache based on the result.
//
// Preconditions:
// * fs.renameMu must be locked.
// * InteropModeShared is in effect.
func (fs *filesystem) revalidateHelper(ctx context.Context, vfsObj *vfs.VirtualFilesystem, state *revalidateState, ds **[]*dentry) error {
	if len(state.names) == 0 {
		return nil
	}
	// Lock metadata on all dentries *before* getting attributes for them.
	state.lockAllMetadata()

	var (
		stats     []p9.FullStat
		statsLisa []linux.Statx
		numStats  int
	)
	if fs.opts.lisaEnabled {
		var err error
		statsLisa, err = state.start.controlFDLisa.WalkStat(ctx, state.names)
		if err != nil {
			return err
		}
		numStats = len(statsLisa)
	} else {
		var err error
		stats, err = state.start.file.multiGetAttr(ctx, state.names)
		if err != nil {
			return err
		}
		numStats = len(stats)
	}

	i := -1
	for d := state.popFront(); d != nil; d = state.popFront() {
		i++
		found := i < numStats
		if i == 0 && len(state.names[0]) == 0 {
			if found && !d.isSynthetic() {
				// First dentry is where the search is starting, just update attributes
				// since it cannot be replaced.
				if fs.opts.lisaEnabled {
					d.updateFromLisaStatLocked(&statsLisa[i]) // +checklocksforce: acquired by lockAllMetadata.
				} else {
					d.updateFromP9AttrsLocked(stats[i].Valid, &stats[i].Attr) // +checklocksforce: acquired by lockAllMetadata.
				}
			}
			d.metadataMu.Unlock() // +checklocksforce: see above.
			continue
		}

		// Note that synthetic dentries will always fail this comparison check.
		var shouldInvalidate bool
		if fs.opts.lisaEnabled {
			shouldInvalidate = !found || d.inoKey != inoKeyFromStat(&statsLisa[i])
		} else {
			shouldInvalidate = !found || d.qidPath != stats[i].QID.Path
		}
		if shouldInvalidate {
			d.metadataMu.Unlock() // +checklocksforce: see above.
			if !found && d.isSynthetic() {
				// We have a synthetic file, and no remote file has arisen to replace
				// it.
				return nil
			}
			// The file at this path has changed or no longer exists. Mark the
			// dentry invalidated, and re-evaluate its caching status (i.e. if it
			// has 0 references, drop it). The dentry will be reloaded next time it's
			// accessed.
			vfsObj.InvalidateDentry(ctx, &d.vfsd)

			name := state.names[i]
			d.parent.dirMu.Lock()

			if d.isSynthetic() {
				// Normally we don't mark invalidated dentries as deleted since
				// they may still exist (but at a different path), and also for
				// consistency with Linux. However, synthetic files are guaranteed
				// to become unreachable if their dentries are invalidated, so
				// treat their invalidation as deletion.
				d.setDeleted()
				d.decRefNoCaching()
				*ds = appendDentry(*ds, d)

				d.parent.syntheticChildren--
				d.parent.dirents = nil
			}

			// Since the dirMu was released and reacquired, re-check that the
			// parent's child with this name is still the same. Do not touch it if
			// it has been replaced with a different one.
			if child := d.parent.children[name]; child == d {
				// Invalidate dentry so it gets reloaded next time it's accessed.
				delete(d.parent.children, name)
			}
			d.parent.dirMu.Unlock()

			return nil
		}

		// The file at this path hasn't changed. Just update cached metadata.
		if fs.opts.lisaEnabled {
			d.updateFromLisaStatLocked(&statsLisa[i]) // +checklocksforce: see above.
		} else {
			d.updateFromP9AttrsLocked(stats[i].Valid, &stats[i].Attr) // +checklocksforce: see above.
		}
		d.metadataMu.Unlock()
	}

	return nil
}

// revalidateStatePool caches revalidateState instances to save array
// allocations for dentries and names.
var revalidateStatePool = sync.Pool{
	New: func() interface{} {
		return &revalidateState{}
	},
}

// revalidateState keeps state related to a revalidation request. It keeps track
// of {name, dentry} list being revalidated, as well as metadata locks on the
// dentries. The list must be in ancestry order, in other words `n` must be
// `n-1` child.
type revalidateState struct {
	// start is the dentry where to start the attributes search.
	start *dentry

	// List of names of entries to refresh attributes. Names length must be the
	// same as detries length. They are kept in separate slices because names is
	// used to call File.MultiGetAttr().
	names []string

	// dentries is the list of dentries that correspond to the names above.
	// dentry.metadataMu is acquired as each dentry is added to this list.
	dentries []*dentry

	// locked indicates if metadata lock has been acquired on dentries.
	locked bool
}

func makeRevalidateState(start *dentry) *revalidateState {
	r := revalidateStatePool.Get().(*revalidateState)
	r.start = start
	return r
}

// release must be called after the caller is done with this object. It releases
// all metadata locks and resources.
func (r *revalidateState) release() {
	r.reset()
	revalidateStatePool.Put(r)
}

// Preconditions:
// * d is a descendant of all dentries in r.dentries.
func (r *revalidateState) add(name string, d *dentry) {
	r.names = append(r.names, name)
	r.dentries = append(r.dentries, d)
}

// +checklocksignore
func (r *revalidateState) lockAllMetadata() {
	for _, d := range r.dentries {
		d.metadataMu.Lock()
	}
	r.locked = true
}

func (r *revalidateState) popFront() *dentry {
	if len(r.dentries) == 0 {
		return nil
	}
	d := r.dentries[0]
	r.dentries = r.dentries[1:]
	return d
}

// reset releases all metadata locks and resets all fields to allow this
// instance to be reused.
// +checklocksignore
func (r *revalidateState) reset() {
	if r.locked {
		// Unlock any remaining dentries.
		for _, d := range r.dentries {
			d.metadataMu.Unlock()
		}
		r.locked = false
	}
	r.start = nil
	r.names = r.names[:0]
	r.dentries = r.dentries[:0]
}
