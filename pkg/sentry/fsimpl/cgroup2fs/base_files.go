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

package cgroup2fs

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cgroupInterfaceFile struct {
	kernfs.DynamicBytesFile
	c *cgroup
}

// Valid implements kernfs.Inode.Valid.
func (f *cgroupInterfaceFile) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	return !f.c.deleted.Load()
}

// SetStat implements kernfs.Inode.SetStat.
func (f *cgroupInterfaceFile) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return f.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// +stateify savable
type cgroupSourceReadOnly struct {
	c    *cgroup
	ctrl controller
	src  vfs.DynamicBytesSource
}

func (s *cgroupSourceReadOnly) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if s.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	if s.ctrl != nil && !s.ctrl.isActive() {
		return linuxerr.ENODEV
	}
	return s.src.Generate(ctx, buf)
}

// +stateify savable
type cgroupSourceWritable struct {
	c    *cgroup
	ctrl controller
	src  vfs.WritableDynamicBytesSource
}

func (s *cgroupSourceWritable) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if s.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	if s.ctrl != nil && !s.ctrl.isActive() {
		return linuxerr.ENODEV
	}
	return s.src.Generate(ctx, buf)
}

func (s *cgroupSourceWritable) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if s.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	if s.ctrl != nil && !s.ctrl.isActive() {
		return 0, linuxerr.ENODEV
	}
	return s.src.Write(ctx, fd, src, offset)
}

func (fs *filesystem) newInode(ctx context.Context, uid auth.KUID, gid auth.KGID, c *cgroup, def interfaceFile) kernfs.Inode {
	if def.isEvent {
		eventFile := fs.newEventFile(ctx, uid, gid, c, def.source, def.ctrl)
		if def.onEventCreated != nil {
			def.onEventCreated(eventFile)
		}
		return eventFile
	}
	f := &cgroupInterfaceFile{c: c}
	var src vfs.DynamicBytesSource
	if ws, ok := def.source.(vfs.WritableDynamicBytesSource); ok {
		src = &cgroupSourceWritable{c: c, ctrl: def.ctrl, src: ws}
	} else {
		src = &cgroupSourceReadOnly{c: c, ctrl: def.ctrl, src: def.source}
	}
	f.InitWithIDs(ctx, uid, gid, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), src, def.perm)
	return f
}

func (fs *filesystem) rootInodes(ctx context.Context, uid auth.KUID, gid auth.KGID, c *cgroup) map[string]kernfs.Inode {
	contents := make(map[string]kernfs.Inode)
	contents["cgroup.procs"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.procs", source: &cgroupProcs{c: c}, perm: 0644})
	contents["cgroup.controllers"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.controllers", source: &cgroupControllers{c: c}, perm: 0444})
	contents["cgroup.subtree_control"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.subtree_control", source: &cgroupSubtreeControl{c: c}, perm: 0644})
	contents["cgroup.max.descendants"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.max.descendants", source: &cgroupMaxDescendants{c: c}, perm: 0644})
	contents["cgroup.max.depth"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.max.depth", source: &cgroupMaxDepth{c: c}, perm: 0644})
	contents["cgroup.stat"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.stat", source: &cgroupStat{c: c}, perm: 0444})
	return contents
}

func (fs *filesystem) cgroupInodes(ctx context.Context, uid auth.KUID, gid auth.KGID, c *cgroup) map[string]kernfs.Inode {
	contents := make(map[string]kernfs.Inode)
	contents["cgroup.procs"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.procs", source: &cgroupProcs{c: c}, perm: 0644})
	contents["cgroup.controllers"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.controllers", source: &cgroupControllers{c: c}, perm: 0444})
	contents["cgroup.subtree_control"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.subtree_control", source: &cgroupSubtreeControl{c: c}, perm: 0644})
	contents["cgroup.max.descendants"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.max.descendants", source: &cgroupMaxDescendants{c: c}, perm: 0644})
	contents["cgroup.max.depth"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.max.depth", source: &cgroupMaxDepth{c: c}, perm: 0644})
	contents["cgroup.stat"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.stat", source: &cgroupStat{c: c}, perm: 0444})
	contents["cgroup.type"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.type", source: &cgroupType{c: c}, perm: 0444})
	contents["cgroup.kill"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.kill", source: &cgroupKill{c: c}, perm: 0200})
	contents["cgroup.freeze"] = fs.newInode(ctx, uid, gid, c, interfaceFile{name: "cgroup.freeze", source: &cgroupFreeze{c: c}, perm: 0644})

	contents["cgroup.events"] = fs.newInode(ctx, uid, gid, c, interfaceFile{
		name:    "cgroup.events",
		source:  &cgroupEvents{c: c},
		perm:    0444,
		isEvent: true,
		onEventCreated: func(inode *eventFile) {
			c.eventsFile = inode
		},
	})
	return contents
}

// cgroupProcs implements vfs.DynamicBytesSource for "cgroup.procs".
// +stateify savable
type cgroupProcs struct {
	c *cgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupProcs) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return nil
	}

	pids := cf.c.getPIDs(t)
	for _, pid := range pids {
		fmt.Fprintf(buf, "%d\n", pid)
	}

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupProcs) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	pid, err := strconv.ParseInt(str, 10, 64)
	if err != nil || pid < 0 {
		return 0, linuxerr.EINVAL
	}

	if err := cf.c.attachProcess(ctx, fd.Credentials(), pid); err != nil {
		return 0, err
	}

	return src.NumBytes(), nil
}

// cgroupControllers implements vfs.DynamicBytesSource for "cgroup.controllers".
// +stateify savable
type cgroupControllers struct {
	c *cgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupControllers) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	var available []string
	cf.c.fs.treeMu.RLock()
	defer cf.c.fs.treeMu.RUnlock()
	for ctl := firstController; ctl < numControllers; ctl++ {
		if cf.c.isControllerAvailableLocked(ctl) {
			available = append(available, ctrlTypeStr[ctl])
		}
	}
	if len(available) > 0 {
		buf.WriteString(strings.Join(available, " ") + "\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupControllers) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return 0, linuxerr.EINVAL
}

// cgroupSubtreeControl implements vfs.DynamicBytesSource for "cgroup.subtree_control".
// It is used to enable or disable specific controllers for the cgroup's children.
// +stateify savable
type cgroupSubtreeControl struct {
	c *cgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupSubtreeControl) Generate(ctx context.Context, buf *bytes.Buffer) error {
	var enabled []string
	cf.c.fs.treeMu.RLock()
	defer cf.c.fs.treeMu.RUnlock()
	for ctl := firstController; ctl < numControllers; ctl++ {
		if cf.c.subtreeCtrls[ctl] {
			enabled = append(enabled, ctrlTypeStr[ctl])
		}
	}
	if len(enabled) > 0 {
		buf.WriteString(strings.Join(enabled, " ") + "\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupSubtreeControl) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	if str == "" {
		return src.NumBytes(), nil
	}
	var enable []kernel.Cgroup2Ctrl
	var disable []kernel.Cgroup2Ctrl

	for _, ctrl := range strings.Split(str, " ") {
		if ctrl == "" {
			continue
		}
		if len(ctrl) < 2 {
			return 0, linuxerr.EINVAL
		}
		op := ctrl[0]
		name := ctrl[1:]

		if op != '+' && op != '-' {
			return 0, linuxerr.EINVAL
		}
		cType, ok := ctrlNames[name]
		if !ok {
			return 0, linuxerr.EINVAL
		}

		if op == '+' {
			enable = append(enable, cType)
		} else {
			disable = append(disable, cType)
		}
	}

	if err := cf.c.setSubtreeControl(ctx, enable, disable); err != nil {
		return 0, err
	}

	return src.NumBytes(), nil
}

// cgroupStat implements vfs.DynamicBytesSource for "cgroup.stat".
// +stateify savable
type cgroupStat struct {
	c *cgroup
}

func (cf *cgroupStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	cf.c.fs.treeMu.RLock()
	defer cf.c.fs.treeMu.RUnlock()
	cf.c.fs.tasksMu.RLock()
	defer cf.c.fs.tasksMu.RUnlock()
	descendants := cf.c.nrDescendants.Load()
	fmt.Fprintf(buf, "nr_descendants %d\nnr_dying_descendants 0\n", descendants)
	return nil
}

// cgroupType implements vfs.DynamicBytesSource for "cgroup.type".
// It identifies the cgroup namespace type.
// +stateify savable
type cgroupType struct {
	c *cgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupType) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	buf.WriteString("domain\n")
	return nil
}

// +stateify savable
type cgroupMaxDescendants struct{ c *cgroup }

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupMaxDescendants) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}

	val := cf.c.maxDescendants.Load()
	if val == limitMax {
		buf.WriteString("max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", val)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupMaxDescendants) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	var val int64
	if str == "max" {
		val = limitMax
	} else {
		var err error
		val, err = strconv.ParseInt(str, 10, 64)
		if err != nil || val < 0 {
			return 0, linuxerr.EINVAL
		}
	}

	cf.c.fs.treeMu.Lock()
	defer cf.c.fs.treeMu.Unlock()
	cf.c.maxDescendants.Store(val)
	return src.NumBytes(), nil
}

// cgroupMaxDepth implements vfs.DynamicBytesSource for "cgroup.max.depth".
// +stateify savable
type cgroupMaxDepth struct{ c *cgroup }

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupMaxDepth) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}

	val := cf.c.maxDepth.Load()
	if val == limitMax {
		buf.WriteString("max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", val)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupMaxDepth) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	var val int64
	if str == "max" {
		val = limitMax
	} else {
		var err error
		val, err = strconv.ParseInt(str, 10, 64)
		if err != nil || val < 0 {
			return 0, linuxerr.EINVAL
		}
	}

	cf.c.fs.treeMu.Lock()
	defer cf.c.fs.treeMu.Unlock()
	cf.c.maxDepth.Store(val)
	return src.NumBytes(), nil
}

// cgroupKill implements vfs.DynamicBytesSource for "cgroup.kill".
// +stateify savable
type cgroupKill struct{ c *cgroup }

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupKill) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupKill) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if val != 1 {
		return 0, linuxerr.ERANGE
	}
	if err := cf.c.kill(); err != nil {
		return 0, err
	}
	return src.NumBytes(), nil
}

// cgroupFreeze implements vfs.WritableDynamicBytesSource for "cgroup.freeze".
// Unlike cgroup.kill it is readable (reports the self-requested freeze state)
// and accepts both 0 (thaw) and 1 (freeze).
// +stateify savable
type cgroupFreeze struct{ c *cgroup }

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupFreeze) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	// cgroup.freeze reports this cgroup's own requested state, not the
	// effective (ancestor-inherited) state; the effective state is surfaced via
	// the "frozen" line in cgroup.events. This matches Linux.
	cf.c.fs.tasksMu.RLock()
	frozen := cf.c.frozen
	cf.c.fs.tasksMu.RUnlock()
	if frozen {
		fmt.Fprintf(buf, "1\n")
	} else {
		fmt.Fprintf(buf, "0\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cf *cgroupFreeze) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if cf.c.deleted.Load() {
		return 0, linuxerr.ENODEV
	}
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	// Match Linux cgroup_freeze_write: a non-integer is EINVAL (above), but an
	// out-of-range integer is ERANGE.
	if val != 0 && val != 1 {
		return 0, linuxerr.ERANGE
	}
	if err := cf.c.freeze(val == 1); err != nil {
		return 0, err
	}
	return src.NumBytes(), nil
}

// cgroupEvents implements vfs.DynamicBytesSource for "cgroup.events".
// +stateify savable
type cgroupEvents struct {
	c *cgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cf *cgroupEvents) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if cf.c.deleted.Load() {
		return linuxerr.ENODEV
	}
	populated := 0
	if cf.c.populated() {
		populated = 1
	}
	// Unlike cgroup.freeze (which reports this cgroup's own requested state),
	// the events "frozen" line reports the effective state: 1 if this cgroup or
	// any ancestor is frozen. This matches Linux's CGRP_FROZEN semantics.
	frozen := 0
	if cf.c.IsFrozen() {
		frozen = 1
	}
	fmt.Fprintf(buf, "populated %d\nfrozen %d\n", populated, frozen)
	return nil
}
