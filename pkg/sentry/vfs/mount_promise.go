// Copyright 2026 The gVisor Authors.
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

package vfs

import (
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	epb "gvisor.dev/gvisor/pkg/sentry/vfs/events_go_proto"
	"gvisor.dev/gvisor/pkg/waiter"
)

// MountPromiseOptions holds arguments to RegisterMountPromise.
type MountPromiseOptions struct {
	// If Timeout > 0, TimeoutAction is the action taken after Timeout expires
	// while waiting for the mount promise to be resolved. If Timeout <= 0, no
	// timeout applies.
	Timeout       time.Duration
	TimeoutAction MountPromiseTimeoutAction
}

// MountPromiseTimeoutAction is the type of MountPromiseOptions.TimeoutAction.
type MountPromiseTimeoutAction uint8

const (
	// MountPromiseTimeoutReturnError returns ETIMEDOUT to the triggering
	// filesystem operation.
	MountPromiseTimeoutReturnError MountPromiseTimeoutAction = iota

	// MountPromiseTimeoutLogWarningAndReturnError logs a warning, then returns
	// ETIMEDOUT to the triggering filesystem operation.
	MountPromiseTimeoutLogWarningAndReturnError

	// MountPromiseTimeoutLogWarningAndWait logs a warning, then continues to
	// wait for the mount promise to be resolved. The filesystem operation that
	// logged the warning will not log again, although other goroutines that
	// time out while waiting for the same mount promise to be resolved may do
	// so.
	MountPromiseTimeoutLogWarningAndWait

	// MountPromiseTimeoutPanic panics.
	MountPromiseTimeoutPanic
)

type mountPromise struct {
	wq       waiter.Queue
	resolved atomicbitops.Bool
	opts     MountPromiseOptions
}

func (vfs *VirtualFilesystem) getMountPromise(vd VirtualDentry) *mountPromise {
	if mp, ok := vfs.mountPromises.Load(vd); ok {
		return mp.(*mountPromise)
	}
	return nil
}

// RegisterMountPromise marks vd as a mount promise. This means any VFS
// operation on vd will be blocked until another process mounts over it or the
// mount promise times out.
func (vfs *VirtualFilesystem) RegisterMountPromise(vd VirtualDentry, opts MountPromiseOptions) error {
	if _, loaded := vfs.mountPromises.LoadOrStore(vd, &mountPromise{
		opts: opts,
	}); loaded {
		return fmt.Errorf("mount promise already registered for %v", vd)
	}
	return nil
}

// Emit a SentryMountPromiseBlockEvent and wait for the mount promise to be
// resolved or time out.
func (vfs *VirtualFilesystem) maybeBlockOnMountPromise(ctx context.Context, rp *ResolvingPath) error {
	vd := VirtualDentry{rp.mount, rp.start}
	mp := vfs.getMountPromise(vd)
	if mp == nil {
		return nil
	} else if mp.resolved.Load() {
		vfs.updateResolvingPathForMountPromise(ctx, rp)
		return nil
	}

	e, ch := waiter.NewChannelEntry(waiter.EventOut)
	mp.wq.EventRegister(&e)
	defer mp.wq.EventUnregister(&e)

	var (
		path string
		err  error
	)
	// Unblock waiter entries that were created after this mount promise was
	// resolved by a racing thread.
	if mp.resolved.Load() {
		close(ch)
	} else {
		root := RootFromContext(ctx)
		defer root.DecRef(ctx)
		path, err = vfs.PathnameReachable(ctx, root, vd)
		if err != nil {
			panic(fmt.Sprintf("could not reach %v from root", rp.Component()))
		}
		if path == "" {
			log.Warningf("Attempting to block for a mount promise on an empty path.")
			return nil
		}
		eventchannel.Emit(&epb.SentryMountPromiseBlockEvent{Path: path})
	}

	var timeoutCh <-chan time.Time
	if mp.opts.Timeout > 0 {
		timeoutCh = time.After(mp.opts.Timeout)
	}
retry:
	select {
	case <-ch:
		vfs.updateResolvingPathForMountPromise(ctx, rp)
	case <-timeoutCh:
		switch mp.opts.TimeoutAction {
		case MountPromiseTimeoutReturnError:
			return linuxerr.ETIMEDOUT
		case MountPromiseTimeoutLogWarningAndReturnError:
			log.Traceback("Mount promise for %s timed out", path)
			return linuxerr.ETIMEDOUT
		case MountPromiseTimeoutLogWarningAndWait:
			log.Traceback("Mount promise for %s timeout expired", path)
			timeoutCh = nil
			goto retry
		case MountPromiseTimeoutPanic:
			panic(fmt.Sprintf("mount promise for %s timed out, unable to proceed", path))
		}
	}
	return nil
}

func (vfs *VirtualFilesystem) updateResolvingPathForMountPromise(ctx context.Context, rp *ResolvingPath) {
	newMnt := vfs.getMountAt(ctx, rp.mount, rp.start)
	rp.mount = newMnt
	rp.start = newMnt.root
	rp.flags = rp.flags&^rpflagsHaveStartRef | rpflagsHaveMountRef
}

func (vfs *VirtualFilesystem) maybeResolveMountPromise(vd VirtualDentry) {
	if mp := vfs.getMountPromise(vd); mp != nil {
		mp.resolved.Store(true)
		mp.wq.Notify(waiter.EventOut)
	}
}
