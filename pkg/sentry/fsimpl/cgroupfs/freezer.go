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

package cgroupfs

import (
	"bytes"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type freezerController struct {
	controllerCommon
	controllerStateless
	controllerNoResource

	isRoot bool

	mu sync.Mutex `state:"nosave"`

	// selfFreezing indicates whether this specific cgroup was set to FROZEN.
	// Protected by mu (and tasksMu during hierarchy updates).
	selfFreezing bool

	// cg is the cgroupInode associated with this controller.
	// Protected by mu.
	cg *cgroupInode
}

var _ controller = (*freezerController)(nil)

func newRootFreezerController(fs *filesystem) *freezerController {
	c := &freezerController{
		isRoot: true,
	}
	c.controllerCommon.init(kernel.CgroupControllerFreezer, fs)
	return c
}

// Clone implements controller.Clone.
func (c *freezerController) Clone() controller {
	c.mu.Lock()
	defer c.mu.Unlock()
	new := &freezerController{
		isRoot:       false,
		selfFreezing: false,
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *freezerController) AddControlFiles(ctx context.Context, creds *auth.Credentials, cg *cgroupInode, contents map[string]kernfs.Inode) {
	c.mu.Lock()
	c.cg = cg
	c.mu.Unlock()

	contents["freezer.state"] = c.fs.newControllerWritableFile(ctx, creds, &freezerStateData{c: c}, true)
	contents["freezer.self_freezing"] = c.fs.newControllerFile(ctx, creds, &freezerSelfFreezingData{c: c}, true)
	contents["freezer.parent_freezing"] = c.fs.newControllerFile(ctx, creds, &freezerParentFreezingData{c: c}, true)
}

// isParentFreezing returns true if any ancestor freezer controller is selfFreezing.
func (c *freezerController) isParentFreezing() bool {
	for p := c.parent; p != nil; {
		pf, ok := p.(*freezerController)
		if !ok || pf == nil {
			break
		}
		pf.mu.Lock()
		frozen := pf.selfFreezing
		pf.mu.Unlock()
		if frozen {
			return true
		}
		p = pf.parent
	}
	return false
}

// effectiveFrozenLocked returns true if this controller or any of its ancestors is freezing.
func (c *freezerController) effectiveFrozenLocked() bool {
	c.mu.Lock()
	self := c.selfFreezing
	c.mu.Unlock()
	if self {
		return true
	}
	return c.isParentFreezing()
}

// collectSubtree returns all descendant freezerControllers (including c itself).
// Precondition: c.fs.tasksMu is locked.
func (c *freezerController) collectSubtree() []*freezerController {
	res := []*freezerController{c}
	c.mu.Lock()
	cg := c.cg
	c.mu.Unlock()
	if cg != nil {
		cg.dir.OrderedChildren.ForEachChild(func(_ string, i kernfs.Inode) {
			if childCG, ok := i.(*cgroupInode); ok {
				if childCtl, ok := childCG.controllers[kernel.CgroupControllerFreezer].(*freezerController); ok {
					res = append(res, childCtl.collectSubtree()...)
				}
			}
		})
	}
	return res
}

// updateFreezerStateLocked updates the selfFreezing state and returns tasks to freeze/thaw.
// Precondition: c.fs.tasksMu is locked.
func (c *freezerController) updateFreezerStateLocked(targetFreezing bool) (toFreeze []*kernel.Task, toThaw []*kernel.Task) {
	c.mu.Lock()
	if c.selfFreezing == targetFreezing {
		c.mu.Unlock()
		return nil, nil
	}
	c.mu.Unlock()

	controllers := c.collectSubtree()

	wasFrozen := make([]bool, len(controllers))
	for i, ctl := range controllers {
		wasFrozen[i] = ctl.effectiveFrozenLocked()
	}

	c.mu.Lock()
	c.selfFreezing = targetFreezing
	c.mu.Unlock()

	for i, ctl := range controllers {
		isFrozen := ctl.effectiveFrozenLocked()
		if !wasFrozen[i] && isFrozen {
			ctl.mu.Lock()
			cg := ctl.cg
			ctl.mu.Unlock()
			if cg != nil {
				for t := range cg.ts {
					toFreeze = append(toFreeze, t)
				}
			}
		} else if wasFrozen[i] && !isFrozen {
			ctl.mu.Lock()
			cg := ctl.cg
			ctl.mu.Unlock()
			if cg != nil {
				for t := range cg.ts {
					toThaw = append(toThaw, t)
				}
			}
		}
	}
	return toFreeze, toThaw
}

// +stateify savable
type freezerStateData struct {
	c *freezerController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *freezerStateData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if d.c.effectiveFrozenLocked() {
		fmt.Fprintf(buf, "FROZEN\n")
	} else {
		fmt.Fprintf(buf, "THAWED\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *freezerStateData) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	const maxLen = 32
	buf := copyScratchBufferFromContext(ctx, maxLen)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return int64(n), err
	}
	str := strings.TrimSpace(string(buf[:n]))

	var targetFreezing bool
	switch str {
	case "FROZEN":
		targetFreezing = true
	case "THAWED":
		targetFreezing = false
	default:
		return int64(n), linuxerr.EINVAL
	}

	if d.c.isRoot {
		if targetFreezing {
			return int64(n), linuxerr.EINVAL
		}
		return int64(n), nil
	}

	d.c.fs.tasksMu.Lock()
	toFreeze, toThaw := d.c.updateFreezerStateLocked(targetFreezing)
	d.c.fs.tasksMu.Unlock()

	for _, t := range toFreeze {
		t.BeginCgroupFreeze()
	}
	for _, t := range toThaw {
		t.EndCgroupFreeze()
	}

	return int64(n), nil
}

// +stateify savable
type freezerSelfFreezingData struct {
	c *freezerController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *freezerSelfFreezingData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	self := d.c.selfFreezing
	d.c.mu.Unlock()

	if self {
		fmt.Fprintf(buf, "1\n")
	} else {
		fmt.Fprintf(buf, "0\n")
	}
	return nil
}

// +stateify savable
type freezerParentFreezingData struct {
	c *freezerController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *freezerParentFreezingData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if d.c.isParentFreezing() {
		fmt.Fprintf(buf, "1\n")
	} else {
		fmt.Fprintf(buf, "0\n")
	}
	return nil
}
