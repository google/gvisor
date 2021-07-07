// Copyright 2019 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/p9"
)

// p9file is a wrapper around p9.File that provides methods that are
// Context-aware.
type p9file struct {
	file p9.File
}

func (f p9file) isNil() bool {
	return f.file == nil
}

func (f p9file) walk(ctx context.Context, names []string) ([]p9.QID, p9file, error) {
	ctx.UninterruptibleSleepStart(false)
	qids, newfile, err := f.file.Walk(names)
	ctx.UninterruptibleSleepFinish(false)
	return qids, p9file{newfile}, err
}

func (f p9file) walkGetAttr(ctx context.Context, names []string) ([]p9.QID, p9file, p9.AttrMask, p9.Attr, error) {
	ctx.UninterruptibleSleepStart(false)
	qids, newfile, attrMask, attr, err := f.file.WalkGetAttr(names)
	ctx.UninterruptibleSleepFinish(false)
	return qids, p9file{newfile}, attrMask, attr, err
}

// walkGetAttrOne is a wrapper around p9.File.WalkGetAttr that takes a single
// path component and returns a single qid.
func (f p9file) walkGetAttrOne(ctx context.Context, name string) (p9.QID, p9file, p9.AttrMask, p9.Attr, error) {
	ctx.UninterruptibleSleepStart(false)
	qids, newfile, attrMask, attr, err := f.file.WalkGetAttr([]string{name})
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		return p9.QID{}, p9file{}, p9.AttrMask{}, p9.Attr{}, err
	}
	if len(qids) != 1 {
		ctx.Warningf("p9.File.WalkGetAttr returned %d qids (%v), wanted 1", len(qids), qids)
		if newfile != nil {
			p9file{newfile}.close(ctx)
		}
		return p9.QID{}, p9file{}, p9.AttrMask{}, p9.Attr{}, linuxerr.EIO
	}
	return qids[0], p9file{newfile}, attrMask, attr, nil
}

func (f p9file) statFS(ctx context.Context) (p9.FSStat, error) {
	ctx.UninterruptibleSleepStart(false)
	fsstat, err := f.file.StatFS()
	ctx.UninterruptibleSleepFinish(false)
	return fsstat, err
}

func (f p9file) getAttr(ctx context.Context, req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	ctx.UninterruptibleSleepStart(false)
	qid, attrMask, attr, err := f.file.GetAttr(req)
	ctx.UninterruptibleSleepFinish(false)
	return qid, attrMask, attr, err
}

func (f p9file) setAttr(ctx context.Context, valid p9.SetAttrMask, attr p9.SetAttr) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.SetAttr(valid, attr)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) listXattr(ctx context.Context, size uint64) (map[string]struct{}, error) {
	ctx.UninterruptibleSleepStart(false)
	xattrs, err := f.file.ListXattr(size)
	ctx.UninterruptibleSleepFinish(false)
	return xattrs, err
}

func (f p9file) getXattr(ctx context.Context, name string, size uint64) (string, error) {
	ctx.UninterruptibleSleepStart(false)
	val, err := f.file.GetXattr(name, size)
	ctx.UninterruptibleSleepFinish(false)
	return val, err
}

func (f p9file) setXattr(ctx context.Context, name, value string, flags uint32) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.SetXattr(name, value, flags)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) removeXattr(ctx context.Context, name string) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.RemoveXattr(name)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) allocate(ctx context.Context, mode p9.AllocateMode, offset, length uint64) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.Allocate(mode, offset, length)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) close(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.Close()
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) setAttrClose(ctx context.Context, valid p9.SetAttrMask, attr p9.SetAttr) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.SetAttrClose(valid, attr)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) open(ctx context.Context, flags p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	ctx.UninterruptibleSleepStart(false)
	fdobj, qid, iounit, err := f.file.Open(flags)
	ctx.UninterruptibleSleepFinish(false)
	return fdobj, qid, iounit, err
}

func (f p9file) readAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	ctx.UninterruptibleSleepStart(false)
	n, err := f.file.ReadAt(p, offset)
	ctx.UninterruptibleSleepFinish(false)
	return n, err
}

func (f p9file) writeAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	ctx.UninterruptibleSleepStart(false)
	n, err := f.file.WriteAt(p, offset)
	ctx.UninterruptibleSleepFinish(false)
	return n, err
}

func (f p9file) fsync(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.FSync()
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) create(ctx context.Context, name string, flags p9.OpenFlags, permissions p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, p9file, p9.QID, uint32, error) {
	ctx.UninterruptibleSleepStart(false)
	fdobj, newfile, qid, iounit, err := f.file.Create(name, flags, permissions, uid, gid)
	ctx.UninterruptibleSleepFinish(false)
	return fdobj, p9file{newfile}, qid, iounit, err
}

func (f p9file) mkdir(ctx context.Context, name string, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	qid, err := f.file.Mkdir(name, permissions, uid, gid)
	ctx.UninterruptibleSleepFinish(false)
	return qid, err
}

func (f p9file) symlink(ctx context.Context, oldName string, newName string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	qid, err := f.file.Symlink(oldName, newName, uid, gid)
	ctx.UninterruptibleSleepFinish(false)
	return qid, err
}

func (f p9file) link(ctx context.Context, target p9file, newName string) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.Link(target.file, newName)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) mknod(ctx context.Context, name string, mode p9.FileMode, major uint32, minor uint32, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	qid, err := f.file.Mknod(name, mode, major, minor, uid, gid)
	ctx.UninterruptibleSleepFinish(false)
	return qid, err
}

func (f p9file) rename(ctx context.Context, newDir p9file, newName string) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.Rename(newDir.file, newName)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) unlinkAt(ctx context.Context, name string, flags uint32) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.UnlinkAt(name, flags)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) readdir(ctx context.Context, offset uint64, count uint32) ([]p9.Dirent, error) {
	ctx.UninterruptibleSleepStart(false)
	dirents, err := f.file.Readdir(offset, count)
	ctx.UninterruptibleSleepFinish(false)
	return dirents, err
}

func (f p9file) readlink(ctx context.Context) (string, error) {
	ctx.UninterruptibleSleepStart(false)
	target, err := f.file.Readlink()
	ctx.UninterruptibleSleepFinish(false)
	return target, err
}

func (f p9file) flush(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	err := f.file.Flush()
	ctx.UninterruptibleSleepFinish(false)
	return err
}

func (f p9file) connect(ctx context.Context, flags p9.ConnectFlags) (*fd.FD, error) {
	ctx.UninterruptibleSleepStart(false)
	fdobj, err := f.file.Connect(flags)
	ctx.UninterruptibleSleepFinish(false)
	return fdobj, err
}

func (f p9file) multiGetAttr(ctx context.Context, names []string) ([]p9.FullStat, error) {
	ctx.UninterruptibleSleepStart(false)
	stats, err := f.file.MultiGetAttr(names)
	ctx.UninterruptibleSleepFinish(false)
	return stats, err
}
