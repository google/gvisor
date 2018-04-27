// Copyright 2018 Google Inc.
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

package p9test

import (
	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/p9"
)

// StatFSMock mocks p9.File.StatFS.
type StatFSMock struct {
	Called bool

	// Return.
	Stat p9.FSStat
	Err  error
}

// StatFS implements p9.File.StatFS.
func (f *StatFSMock) StatFS() (p9.FSStat, error) {
	f.Called = true
	return f.Stat, f.Err
}

// GetAttrMock mocks p9.File.GetAttr.
type GetAttrMock struct {
	Called bool

	// Args.
	Req p9.AttrMask

	// Return.
	QID   p9.QID
	Valid p9.AttrMask
	Attr  p9.Attr
	Err   error
}

// GetAttr implements p9.File.GetAttr.
func (g *GetAttrMock) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	g.Called, g.Req = true, req
	return g.QID, g.Valid, g.Attr, g.Err
}

// WalkGetAttrMock mocks p9.File.WalkGetAttr.
type WalkGetAttrMock struct {
	Called bool

	// Args.
	Names []string

	// Return.
	QIDs  []p9.QID
	File  p9.File
	Valid p9.AttrMask
	Attr  p9.Attr
	Err   error
}

// WalkGetAttr implements p9.File.WalkGetAttr.
func (w *WalkGetAttrMock) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	w.Called, w.Names = true, names
	return w.QIDs, w.File, w.Valid, w.Attr, w.Err
}

// SetAttrMock mocks p9.File.SetAttr.
type SetAttrMock struct {
	Called bool

	// Args.
	Valid p9.SetAttrMask
	Attr  p9.SetAttr

	// Return.
	Err error
}

// SetAttr implements p9.File.SetAttr.
func (s *SetAttrMock) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	s.Called, s.Valid, s.Attr = true, valid, attr
	return s.Err
}

// RemoveMock mocks p9.File.Remove.
type RemoveMock struct {
	Called bool

	// Return.
	Err error
}

// Remove implements p9.File.Remove.
func (r *RemoveMock) Remove() error {
	r.Called = true
	return r.Err
}

// OpenMock mocks p9.File.Open.
type OpenMock struct {
	Called bool

	// Args.
	Flags p9.OpenFlags

	// Return.
	File   *fd.FD
	QID    p9.QID
	IOUnit uint32
	Err    error
}

// Open implements p9.File.Open.
func (o *OpenMock) Open(flags p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	o.Called, o.Flags = true, flags
	return o.File, o.QID, o.IOUnit, o.Err
}

// ReadAtMock mocks p9.File.ReadAt.
type ReadAtMock struct {
	Called bool

	// Args.
	P      []byte
	Offset uint64

	// Return.
	N   int
	Err error
}

// ReadAt implements p9.File.ReadAt.
func (r *ReadAtMock) ReadAt(p []byte, offset uint64) (int, error) {
	r.Called, r.P, r.Offset = true, p, offset
	return r.N, r.Err
}

// WriteAtMock mocks p9.File.WriteAt.
type WriteAtMock struct {
	Called bool

	// Args.
	P      []byte
	Offset uint64

	// Return.
	N   int
	Err error
}

// WriteAt implements p9.File.WriteAt.
func (w *WriteAtMock) WriteAt(p []byte, offset uint64) (int, error) {
	w.Called, w.P, w.Offset = true, p, offset
	return w.N, w.Err
}

// FSyncMock mocks p9.File.FSync.
type FSyncMock struct {
	Called bool

	// Return.
	Err error
}

// FSync implements p9.File.FSync.
func (f *FSyncMock) FSync() error {
	f.Called = true
	return f.Err
}

// MkdirMock mocks p9.File.Mkdir.
type MkdirMock struct {
	Called bool

	// Args.
	Name        string
	Permissions p9.FileMode
	UID         p9.UID
	GID         p9.GID

	// Return.
	QID p9.QID
	Err error
}

// Mkdir implements p9.File.Mkdir.
func (s *MkdirMock) Mkdir(name string, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	s.Called, s.Name, s.Permissions, s.UID, s.GID = true, name, permissions, uid, gid
	return s.QID, s.Err
}

// SymlinkMock mocks p9.File.Symlink.
type SymlinkMock struct {
	Called bool

	// Args.
	Oldname string
	Newname string
	UID     p9.UID
	GID     p9.GID

	// Return.
	QID p9.QID
	Err error
}

// Symlink implements p9.File.Symlink.
func (s *SymlinkMock) Symlink(oldname string, newname string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	s.Called, s.Oldname, s.Newname, s.UID, s.GID = true, oldname, newname, uid, gid
	return s.QID, s.Err
}

// MknodMock mocks p9.File.Mknod.
type MknodMock struct {
	Called bool

	// Args.
	Name        string
	Permissions p9.FileMode
	Major       uint32
	Minor       uint32
	UID         p9.UID
	GID         p9.GID

	// Return.
	QID p9.QID
	Err error
}

// Mknod implements p9.File.Mknod.
func (m *MknodMock) Mknod(name string, permissions p9.FileMode, major uint32, minor uint32, uid p9.UID, gid p9.GID) (p9.QID, error) {
	m.Called, m.Name, m.Permissions, m.Major, m.Minor, m.UID, m.GID = true, name, permissions, major, minor, uid, gid
	return m.QID, m.Err
}

// UnlinkAtMock mocks p9.File.UnlinkAt.
type UnlinkAtMock struct {
	Called bool

	// Args.
	Name  string
	Flags uint32

	// Return.
	Err error
}

// UnlinkAt implements p9.File.UnlinkAt.
func (u *UnlinkAtMock) UnlinkAt(name string, flags uint32) error {
	u.Called, u.Name, u.Flags = true, name, flags
	return u.Err
}

// ReaddirMock mocks p9.File.Readdir.
type ReaddirMock struct {
	Called bool

	// Args.
	Offset uint64
	Count  uint32

	// Return.
	Dirents []p9.Dirent
	Err     error
}

// Readdir implements p9.File.Readdir.
func (r *ReaddirMock) Readdir(offset uint64, count uint32) ([]p9.Dirent, error) {
	r.Called, r.Offset, r.Count = true, offset, count
	return r.Dirents, r.Err
}

// ReadlinkMock mocks p9.File.Readlink.
type ReadlinkMock struct {
	Called bool

	// Return.
	Target string
	Err    error
}

// Readlink implements p9.File.Readlink.
func (r *ReadlinkMock) Readlink() (string, error) {
	r.Called = true
	return r.Target, r.Err
}

// AttachMock mocks p9.Attacher.Attach.
type AttachMock struct {
	Called bool

	// Args.
	AttachName string

	// Return.
	File p9.File
	Err  error
}

// Attach implements p9.Attacher.Attach.
func (a *AttachMock) Attach(attachName string) (p9.File, error) {
	a.Called, a.AttachName = true, attachName
	return a.File, a.Err
}

// WalkMock mocks p9.File.Walk.
type WalkMock struct {
	Called bool

	// Args.
	Names []string

	// Return.
	QIDs []p9.QID
	File p9.File
	Err  error
}

// Walk implements p9.File.Walk.
func (w *WalkMock) Walk(names []string) ([]p9.QID, p9.File, error) {
	w.Called, w.Names = true, names
	return w.QIDs, w.File, w.Err
}

// RenameMock mocks p9.File.Rename.
type RenameMock struct {
	Called bool

	// Args.
	Directory p9.File
	Name      string

	// Return.
	Err error
}

// Rename implements p9.File.Rename.
func (r *RenameMock) Rename(directory p9.File, name string) error {
	r.Called, r.Directory, r.Name = true, directory, name
	return r.Err
}

// CloseMock mocks p9.File.Close.
type CloseMock struct {
	Called bool

	// Return.
	Err error
}

// Close implements p9.File.Close.
func (d *CloseMock) Close() error {
	d.Called = true
	return d.Err
}

// CreateMock mocks p9.File.Create.
type CreateMock struct {
	Called bool

	// Args.
	Name        string
	Flags       p9.OpenFlags
	Permissions p9.FileMode
	UID         p9.UID
	GID         p9.GID

	// Return.
	HostFile *fd.FD
	File     p9.File
	QID      p9.QID
	IOUnit   uint32
	Err      error
}

// Create implements p9.File.Create.
func (c *CreateMock) Create(name string, flags p9.OpenFlags, permissions p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, p9.File, p9.QID, uint32, error) {
	c.Called, c.Name, c.Flags, c.Permissions, c.UID, c.GID = true, name, flags, permissions, uid, gid
	return c.HostFile, c.File, c.QID, c.IOUnit, c.Err
}

// LinkMock mocks p9.File.Link.
type LinkMock struct {
	Called bool

	// Args.
	Target  p9.File
	Newname string

	// Return.
	Err error
}

// Link implements p9.File.Link.
func (l *LinkMock) Link(target p9.File, newname string) error {
	l.Called, l.Target, l.Newname = true, target, newname
	return l.Err
}

// RenameAtMock mocks p9.File.RenameAt.
type RenameAtMock struct {
	Called bool

	// Args.
	Oldname string
	Newdir  p9.File
	Newname string

	// Return.
	Err error
}

// RenameAt implements p9.File.RenameAt.
func (r *RenameAtMock) RenameAt(oldname string, newdir p9.File, newname string) error {
	r.Called, r.Oldname, r.Newdir, r.Newname = true, oldname, newdir, newname
	return r.Err
}

// FlushMock mocks p9.File.Flush.
type FlushMock struct {
	Called bool

	// Return.
	Err error
}

// Flush implements p9.File.Flush.
func (f *FlushMock) Flush() error {
	return f.Err
}

// ConnectMock mocks p9.File.Connect.
type ConnectMock struct {
	Called bool

	// Args.
	Flags p9.ConnectFlags

	// Return.
	File *fd.FD
	Err  error
}

// Connect implements p9.File.Connect.
func (o *ConnectMock) Connect(flags p9.ConnectFlags) (*fd.FD, error) {
	o.Called, o.Flags = true, flags
	return o.File, o.Err
}

// FileMock mocks p9.File.
type FileMock struct {
	WalkMock
	WalkGetAttrMock
	StatFSMock
	GetAttrMock
	SetAttrMock
	RemoveMock
	RenameMock
	CloseMock
	OpenMock
	ReadAtMock
	WriteAtMock
	FSyncMock
	CreateMock
	MkdirMock
	SymlinkMock
	LinkMock
	MknodMock
	RenameAtMock
	UnlinkAtMock
	ReaddirMock
	ReadlinkMock
	FlushMock
	ConnectMock
}

var (
	_ p9.File = &FileMock{}
)
