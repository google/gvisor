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

package p9

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/fd"
)

// ErrInvalidMsgType is returned when an unsupported message type is found.
type ErrInvalidMsgType struct {
	MsgType
}

// Error returns a useful string.
func (e *ErrInvalidMsgType) Error() string {
	return fmt.Sprintf("invalid message type: %d", e.MsgType)
}

// message is a generic 9P message.
type message interface {
	encoder
	fmt.Stringer

	// Type returns the message type number.
	Type() MsgType
}

// payloader is a special message which may include an inline payload.
type payloader interface {
	// FixedSize returns the size of the fixed portion of this message.
	FixedSize() uint32

	// Payload returns the payload for sending.
	Payload() []byte

	// SetPayload returns the decoded message.
	//
	// This is going to be total message size - FixedSize. But this should
	// be validated during Decode, which will be called after SetPayload.
	SetPayload([]byte)
}

// filer is a message capable of passing a file.
type filer interface {
	// FilePayload returns the file payload.
	FilePayload() *fd.FD

	// SetFilePayload sets the file payload.
	SetFilePayload(*fd.FD)
}

// filePayload embeds a File object.
type filePayload struct {
	File *fd.FD
}

// FilePayload returns the file payload.
func (f *filePayload) FilePayload() *fd.FD {
	return f.File
}

// SetFilePayload sets the received file.
func (f *filePayload) SetFilePayload(file *fd.FD) {
	f.File = file
}

// Tversion is a version request.
type Tversion struct {
	// MSize is the message size to use.
	MSize uint32

	// Version is the version string.
	//
	// For this implementation, this must be 9P2000.L.
	Version string
}

// Decode implements encoder.Decode.
func (t *Tversion) Decode(b *buffer) {
	t.MSize = b.Read32()
	t.Version = b.ReadString()
}

// Encode implements encoder.Encode.
func (t *Tversion) Encode(b *buffer) {
	b.Write32(t.MSize)
	b.WriteString(t.Version)
}

// Type implements message.Type.
func (*Tversion) Type() MsgType {
	return MsgTversion
}

// String implements fmt.Stringer.
func (t *Tversion) String() string {
	return fmt.Sprintf("Tversion{MSize: %d, Version: %s}", t.MSize, t.Version)
}

// Rversion is a version response.
type Rversion struct {
	// MSize is the negotiated size.
	MSize uint32

	// Version is the negotiated version.
	Version string
}

// Decode implements encoder.Decode.
func (r *Rversion) Decode(b *buffer) {
	r.MSize = b.Read32()
	r.Version = b.ReadString()
}

// Encode implements encoder.Encode.
func (r *Rversion) Encode(b *buffer) {
	b.Write32(r.MSize)
	b.WriteString(r.Version)
}

// Type implements message.Type.
func (*Rversion) Type() MsgType {
	return MsgRversion
}

// String implements fmt.Stringer.
func (r *Rversion) String() string {
	return fmt.Sprintf("Rversion{MSize: %d, Version: %s}", r.MSize, r.Version)
}

// Tflush is a flush request.
type Tflush struct {
	// OldTag is the tag to wait on.
	OldTag Tag
}

// Decode implements encoder.Decode.
func (t *Tflush) Decode(b *buffer) {
	t.OldTag = b.ReadTag()
}

// Encode implements encoder.Encode.
func (t *Tflush) Encode(b *buffer) {
	b.WriteTag(t.OldTag)
}

// Type implements message.Type.
func (*Tflush) Type() MsgType {
	return MsgTflush
}

// String implements fmt.Stringer.
func (t *Tflush) String() string {
	return fmt.Sprintf("Tflush{OldTag: %d}", t.OldTag)
}

// Rflush is a flush response.
type Rflush struct {
}

// Decode implements encoder.Decode.
func (*Rflush) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rflush) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rflush) Type() MsgType {
	return MsgRflush
}

// String implements fmt.Stringer.
func (r *Rflush) String() string {
	return fmt.Sprintf("RFlush{}")
}

// Twalk is a walk request.
type Twalk struct {
	// FID is the FID to be walked.
	FID FID

	// NewFID is the resulting FID.
	NewFID FID

	// Names are the set of names to be walked.
	Names []string
}

// Decode implements encoder.Decode.
func (t *Twalk) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.NewFID = b.ReadFID()
	n := b.Read16()
	t.Names = t.Names[:0]
	for i := 0; i < int(n); i++ {
		t.Names = append(t.Names, b.ReadString())
	}
}

// Encode implements encoder.Encode.
func (t *Twalk) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteFID(t.NewFID)
	b.Write16(uint16(len(t.Names)))
	for _, name := range t.Names {
		b.WriteString(name)
	}
}

// Type implements message.Type.
func (*Twalk) Type() MsgType {
	return MsgTwalk
}

// String implements fmt.Stringer.
func (t *Twalk) String() string {
	return fmt.Sprintf("Twalk{FID: %d, NewFID: %d, Names: %v}", t.FID, t.NewFID, t.Names)
}

// Rwalk is a walk response.
type Rwalk struct {
	// QIDs are the set of QIDs returned.
	QIDs []QID
}

// Decode implements encoder.Decode.
func (r *Rwalk) Decode(b *buffer) {
	n := b.Read16()
	r.QIDs = r.QIDs[:0]
	for i := 0; i < int(n); i++ {
		var q QID
		q.Decode(b)
		r.QIDs = append(r.QIDs, q)
	}
}

// Encode implements encoder.Encode.
func (r *Rwalk) Encode(b *buffer) {
	b.Write16(uint16(len(r.QIDs)))
	for _, q := range r.QIDs {
		q.Encode(b)
	}
}

// Type implements message.Type.
func (*Rwalk) Type() MsgType {
	return MsgRwalk
}

// String implements fmt.Stringer.
func (r *Rwalk) String() string {
	return fmt.Sprintf("Rwalk{QIDs: %v}", r.QIDs)
}

// Tclunk is a close request.
type Tclunk struct {
	// FID is the FID to be closed.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Tclunk) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Tclunk) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Tclunk) Type() MsgType {
	return MsgTclunk
}

// String implements fmt.Stringer.
func (t *Tclunk) String() string {
	return fmt.Sprintf("Tclunk{FID: %d}", t.FID)
}

// Rclunk is a close response.
type Rclunk struct {
}

// Decode implements encoder.Decode.
func (*Rclunk) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rclunk) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rclunk) Type() MsgType {
	return MsgRclunk
}

// String implements fmt.Stringer.
func (r *Rclunk) String() string {
	return fmt.Sprintf("Rclunk{}")
}

// Tremove is a remove request.
//
// This will eventually be replaced by Tunlinkat.
type Tremove struct {
	// FID is the FID to be removed.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Tremove) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Tremove) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Tremove) Type() MsgType {
	return MsgTremove
}

// String implements fmt.Stringer.
func (t *Tremove) String() string {
	return fmt.Sprintf("Tremove{FID: %d}", t.FID)
}

// Rremove is a remove response.
type Rremove struct {
}

// Decode implements encoder.Decode.
func (*Rremove) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rremove) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rremove) Type() MsgType {
	return MsgRremove
}

// String implements fmt.Stringer.
func (r *Rremove) String() string {
	return fmt.Sprintf("Rremove{}")
}

// Rlerror is an error response.
//
// Note that this replaces the error code used in 9p.
type Rlerror struct {
	Error uint32
}

// Decode implements encoder.Decode.
func (r *Rlerror) Decode(b *buffer) {
	r.Error = b.Read32()
}

// Encode implements encoder.Encode.
func (r *Rlerror) Encode(b *buffer) {
	b.Write32(r.Error)
}

// Type implements message.Type.
func (*Rlerror) Type() MsgType {
	return MsgRlerror
}

// String implements fmt.Stringer.
func (r *Rlerror) String() string {
	return fmt.Sprintf("Rlerror{Error: %d}", r.Error)
}

// Tauth is an authentication request.
type Tauth struct {
	// AuthenticationFID is the FID to attach the authentication result.
	AuthenticationFID FID

	// UserName is the user to attach.
	UserName string

	// AttachName is the attach name.
	AttachName string

	// UserID is the numeric identifier for UserName.
	UID UID
}

// Decode implements encoder.Decode.
func (t *Tauth) Decode(b *buffer) {
	t.AuthenticationFID = b.ReadFID()
	t.UserName = b.ReadString()
	t.AttachName = b.ReadString()
	t.UID = b.ReadUID()
}

// Encode implements encoder.Encode.
func (t *Tauth) Encode(b *buffer) {
	b.WriteFID(t.AuthenticationFID)
	b.WriteString(t.UserName)
	b.WriteString(t.AttachName)
	b.WriteUID(t.UID)
}

// Type implements message.Type.
func (*Tauth) Type() MsgType {
	return MsgTauth
}

// String implements fmt.Stringer.
func (t *Tauth) String() string {
	return fmt.Sprintf("Tauth{AuthFID: %d, UserName: %s, AttachName: %s, UID: %d", t.AuthenticationFID, t.UserName, t.AttachName, t.UID)
}

// Rauth is an authentication response.
//
// Encode, Decode and Length are inherited directly from QID.
type Rauth struct {
	QID
}

// Type implements message.Type.
func (*Rauth) Type() MsgType {
	return MsgRauth
}

// String implements fmt.Stringer.
func (r *Rauth) String() string {
	return fmt.Sprintf("Rauth{QID: %s}", r.QID)
}

// Tattach is an attach request.
type Tattach struct {
	// FID is the FID to be attached.
	FID FID

	// Auth is the embedded authentication request.
	//
	// See client.Attach for information regarding authentication.
	Auth Tauth
}

// Decode implements encoder.Decode.
func (t *Tattach) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Auth.Decode(b)
}

// Encode implements encoder.Encode.
func (t *Tattach) Encode(b *buffer) {
	b.WriteFID(t.FID)
	t.Auth.Encode(b)
}

// Type implements message.Type.
func (*Tattach) Type() MsgType {
	return MsgTattach
}

// String implements fmt.Stringer.
func (t *Tattach) String() string {
	return fmt.Sprintf("Tattach{FID: %d, AuthFID: %d, UserName: %s, AttachName: %s, UID: %d}", t.FID, t.Auth.AuthenticationFID, t.Auth.UserName, t.Auth.AttachName, t.Auth.UID)
}

// Rattach is an attach response.
type Rattach struct {
	QID
}

// Type implements message.Type.
func (*Rattach) Type() MsgType {
	return MsgRattach
}

// String implements fmt.Stringer.
func (r *Rattach) String() string {
	return fmt.Sprintf("Rattach{QID: %s}", r.QID)
}

// Tlopen is an open request.
type Tlopen struct {
	// FID is the FID to be opened.
	FID FID

	// Flags are the open flags.
	Flags OpenFlags
}

// Decode implements encoder.Decode.
func (t *Tlopen) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Flags = b.ReadOpenFlags()
}

// Encode implements encoder.Encode.
func (t *Tlopen) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteOpenFlags(t.Flags)
}

// Type implements message.Type.
func (*Tlopen) Type() MsgType {
	return MsgTlopen
}

// String implements fmt.Stringer.
func (t *Tlopen) String() string {
	return fmt.Sprintf("Tlopen{FID: %d, Flags: %v}", t.FID, t.Flags)
}

// Rlopen is a open response.
type Rlopen struct {
	// QID is the file's QID.
	QID QID

	// IoUnit is the recommended I/O unit.
	IoUnit uint32

	filePayload
}

// Decode implements encoder.Decode.
func (r *Rlopen) Decode(b *buffer) {
	r.QID.Decode(b)
	r.IoUnit = b.Read32()
}

// Encode implements encoder.Encode.
func (r *Rlopen) Encode(b *buffer) {
	r.QID.Encode(b)
	b.Write32(r.IoUnit)
}

// Type implements message.Type.
func (*Rlopen) Type() MsgType {
	return MsgRlopen
}

// String implements fmt.Stringer.
func (r *Rlopen) String() string {
	return fmt.Sprintf("Rlopen{QID: %s, IoUnit: %d, File: %v}", r.QID, r.IoUnit, r.File)
}

// Tlcreate is a create request.
type Tlcreate struct {
	// FID is the parent FID.
	//
	// This becomes the new file.
	FID FID

	// Name is the file name to create.
	Name string

	// Mode is the open mode (O_RDWR, etc.).
	//
	// Note that flags like O_TRUNC are ignored, as is O_EXCL. All
	// create operations are exclusive.
	OpenFlags OpenFlags

	// Permissions is the set of permission bits.
	Permissions FileMode

	// GID is the group ID to use for creating the file.
	GID GID
}

// Decode implements encoder.Decode.
func (t *Tlcreate) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Name = b.ReadString()
	t.OpenFlags = b.ReadOpenFlags()
	t.Permissions = b.ReadPermissions()
	t.GID = b.ReadGID()
}

// Encode implements encoder.Encode.
func (t *Tlcreate) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteString(t.Name)
	b.WriteOpenFlags(t.OpenFlags)
	b.WritePermissions(t.Permissions)
	b.WriteGID(t.GID)
}

// Type implements message.Type.
func (*Tlcreate) Type() MsgType {
	return MsgTlcreate
}

// String implements fmt.Stringer.
func (t *Tlcreate) String() string {
	return fmt.Sprintf("Tlcreate{FID: %d, Name: %s, OpenFlags: %s, Permissions: 0o%o, GID: %d}", t.FID, t.Name, t.OpenFlags, t.Permissions, t.GID)
}

// Rlcreate is a create response.
//
// The Encode, Decode, etc. methods are inherited from Rlopen.
type Rlcreate struct {
	Rlopen
}

// Type implements message.Type.
func (*Rlcreate) Type() MsgType {
	return MsgRlcreate
}

// String implements fmt.Stringer.
func (r *Rlcreate) String() string {
	return fmt.Sprintf("Rlcreate{QID: %s, IoUnit: %d, File: %v}", r.QID, r.IoUnit, r.File)
}

// Tsymlink is a symlink request.
type Tsymlink struct {
	// Directory is the directory FID.
	Directory FID

	// Name is the new in the directory.
	Name string

	// Target is the symlink target.
	Target string

	// GID is the owning group.
	GID GID
}

// Decode implements encoder.Decode.
func (t *Tsymlink) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Name = b.ReadString()
	t.Target = b.ReadString()
	t.GID = b.ReadGID()
}

// Encode implements encoder.Encode.
func (t *Tsymlink) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.WriteString(t.Name)
	b.WriteString(t.Target)
	b.WriteGID(t.GID)
}

// Type implements message.Type.
func (*Tsymlink) Type() MsgType {
	return MsgTsymlink
}

// String implements fmt.Stringer.
func (t *Tsymlink) String() string {
	return fmt.Sprintf("Tsymlink{DirectoryFID: %d, Name: %s, Target: %s, GID: %d}", t.Directory, t.Name, t.Target, t.GID)
}

// Rsymlink is a symlink response.
type Rsymlink struct {
	// QID is the new symlink's QID.
	QID QID
}

// Decode implements encoder.Decode.
func (r *Rsymlink) Decode(b *buffer) {
	r.QID.Decode(b)
}

// Encode implements encoder.Encode.
func (r *Rsymlink) Encode(b *buffer) {
	r.QID.Encode(b)
}

// Type implements message.Type.
func (*Rsymlink) Type() MsgType {
	return MsgRsymlink
}

// String implements fmt.Stringer.
func (r *Rsymlink) String() string {
	return fmt.Sprintf("Rsymlink{QID: %s}", r.QID)
}

// Tlink is a link request.
type Tlink struct {
	// Directory is the directory to contain the link.
	Directory FID

	// FID is the target.
	Target FID

	// Name is the new source name.
	Name string
}

// Decode implements encoder.Decode.
func (t *Tlink) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Target = b.ReadFID()
	t.Name = b.ReadString()
}

// Encode implements encoder.Encode.
func (t *Tlink) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.WriteFID(t.Target)
	b.WriteString(t.Name)
}

// Type implements message.Type.
func (*Tlink) Type() MsgType {
	return MsgTlink
}

// String implements fmt.Stringer.
func (t *Tlink) String() string {
	return fmt.Sprintf("Tlink{DirectoryFID: %d, TargetFID: %d, Name: %s}", t.Directory, t.Target, t.Name)
}

// Rlink is a link response.
type Rlink struct {
}

// Type implements message.Type.
func (*Rlink) Type() MsgType {
	return MsgRlink
}

// Decode implements encoder.Decode.
func (*Rlink) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rlink) Encode(b *buffer) {
}

// String implements fmt.Stringer.
func (r *Rlink) String() string {
	return fmt.Sprintf("Rlink{}")
}

// Trenameat is a rename request.
type Trenameat struct {
	// OldDirectory is the source directory.
	OldDirectory FID

	// OldName is the source file name.
	OldName string

	// NewDirectory is the target directory.
	NewDirectory FID

	// NewName is the new file name.
	NewName string
}

// Decode implements encoder.Decode.
func (t *Trenameat) Decode(b *buffer) {
	t.OldDirectory = b.ReadFID()
	t.OldName = b.ReadString()
	t.NewDirectory = b.ReadFID()
	t.NewName = b.ReadString()
}

// Encode implements encoder.Encode.
func (t *Trenameat) Encode(b *buffer) {
	b.WriteFID(t.OldDirectory)
	b.WriteString(t.OldName)
	b.WriteFID(t.NewDirectory)
	b.WriteString(t.NewName)
}

// Type implements message.Type.
func (*Trenameat) Type() MsgType {
	return MsgTrenameat
}

// String implements fmt.Stringer.
func (t *Trenameat) String() string {
	return fmt.Sprintf("TrenameAt{OldDirectoryFID: %d, OldName: %s, NewDirectoryFID: %d, NewName: %s}", t.OldDirectory, t.OldName, t.NewDirectory, t.NewName)
}

// Rrenameat is a rename response.
type Rrenameat struct {
}

// Decode implements encoder.Decode.
func (*Rrenameat) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rrenameat) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rrenameat) Type() MsgType {
	return MsgRrenameat
}

// String implements fmt.Stringer.
func (r *Rrenameat) String() string {
	return fmt.Sprintf("Rrenameat{}")
}

// Tunlinkat is an unlink request.
type Tunlinkat struct {
	// Directory is the originating directory.
	Directory FID

	// Name is the name of the entry to unlink.
	Name string

	// Flags are extra flags (e.g. O_DIRECTORY). These are not interpreted by p9.
	Flags uint32
}

// Decode implements encoder.Decode.
func (t *Tunlinkat) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Name = b.ReadString()
	t.Flags = b.Read32()
}

// Encode implements encoder.Encode.
func (t *Tunlinkat) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.WriteString(t.Name)
	b.Write32(t.Flags)
}

// Type implements message.Type.
func (*Tunlinkat) Type() MsgType {
	return MsgTunlinkat
}

// String implements fmt.Stringer.
func (t *Tunlinkat) String() string {
	return fmt.Sprintf("Tunlinkat{DirectoryFID: %d, Name: %s, Flags: 0x%X}", t.Directory, t.Name, t.Flags)
}

// Runlinkat is an unlink response.
type Runlinkat struct {
}

// Decode implements encoder.Decode.
func (*Runlinkat) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Runlinkat) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Runlinkat) Type() MsgType {
	return MsgRunlinkat
}

// String implements fmt.Stringer.
func (r *Runlinkat) String() string {
	return fmt.Sprintf("Runlinkat{}")
}

// Trename is a rename request.
//
// Note that this generally isn't used anymore, and ideally all rename calls
// should Trenameat below.
type Trename struct {
	// FID is the FID to rename.
	FID FID

	// Directory is the target directory.
	Directory FID

	// Name is the new file name.
	Name string
}

// Decode implements encoder.Decode.
func (t *Trename) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Directory = b.ReadFID()
	t.Name = b.ReadString()
}

// Encode implements encoder.Encode.
func (t *Trename) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteFID(t.Directory)
	b.WriteString(t.Name)
}

// Type implements message.Type.
func (*Trename) Type() MsgType {
	return MsgTrename
}

// String implements fmt.Stringer.
func (t *Trename) String() string {
	return fmt.Sprintf("Trename{FID: %d, DirectoryFID: %d, Name: %s}", t.FID, t.Directory, t.Name)
}

// Rrename is a rename response.
type Rrename struct {
}

// Decode implements encoder.Decode.
func (*Rrename) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rrename) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rrename) Type() MsgType {
	return MsgRrename
}

// String implements fmt.Stringer.
func (r *Rrename) String() string {
	return fmt.Sprintf("Rrename{}")
}

// Treadlink is a readlink request.
type Treadlink struct {
	// FID is the symlink.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Treadlink) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Treadlink) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Treadlink) Type() MsgType {
	return MsgTreadlink
}

// String implements fmt.Stringer.
func (t *Treadlink) String() string {
	return fmt.Sprintf("Treadlink{FID: %d}", t.FID)
}

// Rreadlink is a readlink response.
type Rreadlink struct {
	// Target is the symlink target.
	Target string
}

// Decode implements encoder.Decode.
func (r *Rreadlink) Decode(b *buffer) {
	r.Target = b.ReadString()
}

// Encode implements encoder.Encode.
func (r *Rreadlink) Encode(b *buffer) {
	b.WriteString(r.Target)
}

// Type implements message.Type.
func (*Rreadlink) Type() MsgType {
	return MsgRreadlink
}

// String implements fmt.Stringer.
func (r *Rreadlink) String() string {
	return fmt.Sprintf("Rreadlink{Target: %s}", r.Target)
}

// Tread is a read request.
type Tread struct {
	// FID is the FID to read.
	FID FID

	// Offset indicates the file offset.
	Offset uint64

	// Count indicates the number of bytes to read.
	Count uint32
}

// Decode implements encoder.Decode.
func (t *Tread) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Offset = b.Read64()
	t.Count = b.Read32()
}

// Encode implements encoder.Encode.
func (t *Tread) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.Write64(t.Offset)
	b.Write32(t.Count)
}

// Type implements message.Type.
func (*Tread) Type() MsgType {
	return MsgTread
}

// String implements fmt.Stringer.
func (t *Tread) String() string {
	return fmt.Sprintf("Tread{FID: %d, Offset: %d, Count: %d}", t.FID, t.Offset, t.Count)
}

// Rread is the response for a Tread.
type Rread struct {
	// Data is the resulting data.
	Data []byte
}

// Decode implements encoder.Decode.
//
// Data is automatically decoded via Payload.
func (r *Rread) Decode(b *buffer) {
	count := b.Read32()
	if count != uint32(len(r.Data)) {
		b.markOverrun()
	}
}

// Encode implements encoder.Encode.
//
// Data is automatically encoded via Payload.
func (r *Rread) Encode(b *buffer) {
	b.Write32(uint32(len(r.Data)))
}

// Type implements message.Type.
func (*Rread) Type() MsgType {
	return MsgRread
}

// FixedSize implements payloader.FixedSize.
func (*Rread) FixedSize() uint32 {
	return 4
}

// Payload implements payloader.Payload.
func (r *Rread) Payload() []byte {
	return r.Data
}

// SetPayload implements payloader.SetPayload.
func (r *Rread) SetPayload(p []byte) {
	r.Data = p
}

// String implements fmt.Stringer.
func (r *Rread) String() string {
	return fmt.Sprintf("Rread{len(Data): %d}", len(r.Data))
}

// Twrite is a write request.
type Twrite struct {
	// FID is the FID to read.
	FID FID

	// Offset indicates the file offset.
	Offset uint64

	// Data is the data to be written.
	Data []byte
}

// Decode implements encoder.Decode.
func (t *Twrite) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Offset = b.Read64()
	count := b.Read32()
	if count != uint32(len(t.Data)) {
		b.markOverrun()
	}
}

// Encode implements encoder.Encode.
//
// This uses the buffer payload to avoid a copy.
func (t *Twrite) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.Write64(t.Offset)
	b.Write32(uint32(len(t.Data)))
}

// Type implements message.Type.
func (*Twrite) Type() MsgType {
	return MsgTwrite
}

// FixedSize implements payloader.FixedSize.
func (*Twrite) FixedSize() uint32 {
	return 16
}

// Payload implements payloader.Payload.
func (t *Twrite) Payload() []byte {
	return t.Data
}

// SetPayload implements payloader.SetPayload.
func (t *Twrite) SetPayload(p []byte) {
	t.Data = p
}

// String implements fmt.Stringer.
func (t *Twrite) String() string {
	return fmt.Sprintf("Twrite{FID: %v, Offset %d, len(Data): %d}", t.FID, t.Offset, len(t.Data))
}

// Rwrite is the response for a Twrite.
type Rwrite struct {
	// Count indicates the number of bytes successfully written.
	Count uint32
}

// Decode implements encoder.Decode.
func (r *Rwrite) Decode(b *buffer) {
	r.Count = b.Read32()
}

// Encode implements encoder.Encode.
func (r *Rwrite) Encode(b *buffer) {
	b.Write32(r.Count)
}

// Type implements message.Type.
func (*Rwrite) Type() MsgType {
	return MsgRwrite
}

// String implements fmt.Stringer.
func (r *Rwrite) String() string {
	return fmt.Sprintf("Rwrite{Count: %d}", r.Count)
}

// Tmknod is a mknod request.
type Tmknod struct {
	// Directory is the parent directory.
	Directory FID

	// Name is the device name.
	Name string

	// Mode is the device mode and permissions.
	Mode FileMode

	// Major is the device major number.
	Major uint32

	// Minor is the device minor number.
	Minor uint32

	// GID is the device GID.
	GID GID
}

// Decode implements encoder.Decode.
func (t *Tmknod) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Name = b.ReadString()
	t.Mode = b.ReadFileMode()
	t.Major = b.Read32()
	t.Minor = b.Read32()
	t.GID = b.ReadGID()
}

// Encode implements encoder.Encode.
func (t *Tmknod) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.WriteString(t.Name)
	b.WriteFileMode(t.Mode)
	b.Write32(t.Major)
	b.Write32(t.Minor)
	b.WriteGID(t.GID)
}

// Type implements message.Type.
func (*Tmknod) Type() MsgType {
	return MsgTmknod
}

// String implements fmt.Stringer.
func (t *Tmknod) String() string {
	return fmt.Sprintf("Tmknod{DirectoryFID: %d, Name: %s, Mode: 0o%o, Major: %d, Minor: %d, GID: %d}", t.Directory, t.Name, t.Mode, t.Major, t.Minor, t.GID)
}

// Rmknod is a mknod response.
type Rmknod struct {
	// QID is the resulting QID.
	QID QID
}

// Decode implements encoder.Decode.
func (r *Rmknod) Decode(b *buffer) {
	r.QID.Decode(b)
}

// Encode implements encoder.Encode.
func (r *Rmknod) Encode(b *buffer) {
	r.QID.Encode(b)
}

// Type implements message.Type.
func (*Rmknod) Type() MsgType {
	return MsgRmknod
}

// String implements fmt.Stringer.
func (r *Rmknod) String() string {
	return fmt.Sprintf("Rmknod{QID: %s}", r.QID)
}

// Tmkdir is a mkdir request.
type Tmkdir struct {
	// Directory is the parent directory.
	Directory FID

	// Name is the new directory name.
	Name string

	// Permissions is the set of permission bits.
	Permissions FileMode

	// GID is the owning group.
	GID GID
}

// Decode implements encoder.Decode.
func (t *Tmkdir) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Name = b.ReadString()
	t.Permissions = b.ReadPermissions()
	t.GID = b.ReadGID()
}

// Encode implements encoder.Encode.
func (t *Tmkdir) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.WriteString(t.Name)
	b.WritePermissions(t.Permissions)
	b.WriteGID(t.GID)
}

// Type implements message.Type.
func (*Tmkdir) Type() MsgType {
	return MsgTmkdir
}

// String implements fmt.Stringer.
func (t *Tmkdir) String() string {
	return fmt.Sprintf("Tmkdir{DirectoryFID: %d, Name: %s, Permissions: 0o%o, GID: %d}", t.Directory, t.Name, t.Permissions, t.GID)
}

// Rmkdir is a mkdir response.
type Rmkdir struct {
	// QID is the resulting QID.
	QID QID
}

// Decode implements encoder.Decode.
func (r *Rmkdir) Decode(b *buffer) {
	r.QID.Decode(b)
}

// Encode implements encoder.Encode.
func (r *Rmkdir) Encode(b *buffer) {
	r.QID.Encode(b)
}

// Type implements message.Type.
func (*Rmkdir) Type() MsgType {
	return MsgRmkdir
}

// String implements fmt.Stringer.
func (r *Rmkdir) String() string {
	return fmt.Sprintf("Rmkdir{QID: %s}", r.QID)
}

// Tgetattr is a getattr request.
type Tgetattr struct {
	// FID is the FID to get attributes for.
	FID FID

	// AttrMask is the set of attributes to get.
	AttrMask AttrMask
}

// Decode implements encoder.Decode.
func (t *Tgetattr) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.AttrMask.Decode(b)
}

// Encode implements encoder.Encode.
func (t *Tgetattr) Encode(b *buffer) {
	b.WriteFID(t.FID)
	t.AttrMask.Encode(b)
}

// Type implements message.Type.
func (*Tgetattr) Type() MsgType {
	return MsgTgetattr
}

// String implements fmt.Stringer.
func (t *Tgetattr) String() string {
	return fmt.Sprintf("Tgetattr{FID: %d, AttrMask: %s}", t.FID, t.AttrMask)
}

// Rgetattr is a getattr response.
type Rgetattr struct {
	// Valid indicates which fields are valid.
	Valid AttrMask

	// QID is the QID for this file.
	QID

	// Attr is the set of attributes.
	Attr Attr
}

// Decode implements encoder.Decode.
func (r *Rgetattr) Decode(b *buffer) {
	r.Valid.Decode(b)
	r.QID.Decode(b)
	r.Attr.Decode(b)
}

// Encode implements encoder.Encode.
func (r *Rgetattr) Encode(b *buffer) {
	r.Valid.Encode(b)
	r.QID.Encode(b)
	r.Attr.Encode(b)
}

// Type implements message.Type.
func (*Rgetattr) Type() MsgType {
	return MsgRgetattr
}

// String implements fmt.Stringer.
func (r *Rgetattr) String() string {
	return fmt.Sprintf("Rgetattr{Valid: %v, QID: %s, Attr: %s}", r.Valid, r.QID, r.Attr)
}

// Tsetattr is a setattr request.
type Tsetattr struct {
	// FID is the FID to change.
	FID FID

	// Valid is the set of bits which will be used.
	Valid SetAttrMask

	// SetAttr is the set request.
	SetAttr SetAttr
}

// Decode implements encoder.Decode.
func (t *Tsetattr) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Valid.Decode(b)
	t.SetAttr.Decode(b)
}

// Encode implements encoder.Encode.
func (t *Tsetattr) Encode(b *buffer) {
	b.WriteFID(t.FID)
	t.Valid.Encode(b)
	t.SetAttr.Encode(b)
}

// Type implements message.Type.
func (*Tsetattr) Type() MsgType {
	return MsgTsetattr
}

// String implements fmt.Stringer.
func (t *Tsetattr) String() string {
	return fmt.Sprintf("Tsetattr{FID: %d, Valid: %v, SetAttr: %s}", t.FID, t.Valid, t.SetAttr)
}

// Rsetattr is a setattr response.
type Rsetattr struct {
}

// Decode implements encoder.Decode.
func (*Rsetattr) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rsetattr) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rsetattr) Type() MsgType {
	return MsgRsetattr
}

// String implements fmt.Stringer.
func (r *Rsetattr) String() string {
	return fmt.Sprintf("Rsetattr{}")
}

// Tallocate is an allocate request. This is an extension to 9P protocol, not
// present in the 9P2000.L standard.
type Tallocate struct {
	FID    FID
	Mode   AllocateMode
	Offset uint64
	Length uint64
}

// Decode implements encoder.Decode.
func (t *Tallocate) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Mode.Decode(b)
	t.Offset = b.Read64()
	t.Length = b.Read64()
}

// Encode implements encoder.Encode.
func (t *Tallocate) Encode(b *buffer) {
	b.WriteFID(t.FID)
	t.Mode.Encode(b)
	b.Write64(t.Offset)
	b.Write64(t.Length)
}

// Type implements message.Type.
func (*Tallocate) Type() MsgType {
	return MsgTallocate
}

// String implements fmt.Stringer.
func (t *Tallocate) String() string {
	return fmt.Sprintf("Tallocate{FID: %d, Offset: %d, Length: %d}", t.FID, t.Offset, t.Length)
}

// Rallocate is an allocate response.
type Rallocate struct {
}

// Decode implements encoder.Decode.
func (*Rallocate) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rallocate) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rallocate) Type() MsgType {
	return MsgRallocate
}

// String implements fmt.Stringer.
func (r *Rallocate) String() string {
	return fmt.Sprintf("Rallocate{}")
}

// Txattrwalk walks extended attributes.
type Txattrwalk struct {
	// FID is the FID to check for attributes.
	FID FID

	// NewFID is the new FID associated with the attributes.
	NewFID FID

	// Name is the attribute name.
	Name string
}

// Decode implements encoder.Decode.
func (t *Txattrwalk) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.NewFID = b.ReadFID()
	t.Name = b.ReadString()
}

// Encode implements encoder.Encode.
func (t *Txattrwalk) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteFID(t.NewFID)
	b.WriteString(t.Name)
}

// Type implements message.Type.
func (*Txattrwalk) Type() MsgType {
	return MsgTxattrwalk
}

// String implements fmt.Stringer.
func (t *Txattrwalk) String() string {
	return fmt.Sprintf("Txattrwalk{FID: %d, NewFID: %d, Name: %s}", t.FID, t.NewFID, t.Name)
}

// Rxattrwalk is a xattrwalk response.
type Rxattrwalk struct {
	// Size is the size of the extended attribute.
	Size uint64
}

// Decode implements encoder.Decode.
func (r *Rxattrwalk) Decode(b *buffer) {
	r.Size = b.Read64()
}

// Encode implements encoder.Encode.
func (r *Rxattrwalk) Encode(b *buffer) {
	b.Write64(r.Size)
}

// Type implements message.Type.
func (*Rxattrwalk) Type() MsgType {
	return MsgRxattrwalk
}

// String implements fmt.Stringer.
func (r *Rxattrwalk) String() string {
	return fmt.Sprintf("Rxattrwalk{Size: %d}", r.Size)
}

// Txattrcreate prepare to set extended attributes.
type Txattrcreate struct {
	// FID is input/output parameter, it identifies the file on which
	// extended attributes will be set but after successful Rxattrcreate
	// it is used to write the extended attribute value.
	FID FID

	// Name is the attribute name.
	Name string

	// Size of the attribute value. When the FID is clunked it has to match
	// the number of bytes written to the FID.
	AttrSize uint64

	// Linux setxattr(2) flags.
	Flags uint32
}

// Decode implements encoder.Decode.
func (t *Txattrcreate) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Name = b.ReadString()
	t.AttrSize = b.Read64()
	t.Flags = b.Read32()
}

// Encode implements encoder.Encode.
func (t *Txattrcreate) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteString(t.Name)
	b.Write64(t.AttrSize)
	b.Write32(t.Flags)
}

// Type implements message.Type.
func (*Txattrcreate) Type() MsgType {
	return MsgTxattrcreate
}

// String implements fmt.Stringer.
func (t *Txattrcreate) String() string {
	return fmt.Sprintf("Txattrcreate{FID: %d, Name: %s, AttrSize: %d, Flags: %d}", t.FID, t.Name, t.AttrSize, t.Flags)
}

// Rxattrcreate is a xattrcreate response.
type Rxattrcreate struct {
}

// Decode implements encoder.Decode.
func (r *Rxattrcreate) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (r *Rxattrcreate) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rxattrcreate) Type() MsgType {
	return MsgRxattrcreate
}

// String implements fmt.Stringer.
func (r *Rxattrcreate) String() string {
	return fmt.Sprintf("Rxattrcreate{}")
}

// Treaddir is a readdir request.
type Treaddir struct {
	// Directory is the directory FID to read.
	Directory FID

	// Offset is the offset to read at.
	Offset uint64

	// Count is the number of bytes to read.
	Count uint32
}

// Decode implements encoder.Decode.
func (t *Treaddir) Decode(b *buffer) {
	t.Directory = b.ReadFID()
	t.Offset = b.Read64()
	t.Count = b.Read32()
}

// Encode implements encoder.Encode.
func (t *Treaddir) Encode(b *buffer) {
	b.WriteFID(t.Directory)
	b.Write64(t.Offset)
	b.Write32(t.Count)
}

// Type implements message.Type.
func (*Treaddir) Type() MsgType {
	return MsgTreaddir
}

// String implements fmt.Stringer.
func (t *Treaddir) String() string {
	return fmt.Sprintf("Treaddir{DirectoryFID: %d, Offset: %d, Count: %d}", t.Directory, t.Offset, t.Count)
}

// Rreaddir is a readdir response.
type Rreaddir struct {
	// Count is the byte limit.
	//
	// This should always be set from the Treaddir request.
	Count uint32

	// Entries are the resulting entries.
	//
	// This may be constructed in decode.
	Entries []Dirent

	// payload is the encoded payload.
	//
	// This is constructed by encode.
	payload []byte
}

// Decode implements encoder.Decode.
func (r *Rreaddir) Decode(b *buffer) {
	r.Count = b.Read32()
	entriesBuf := buffer{data: r.payload}
	r.Entries = r.Entries[:0]
	for {
		var d Dirent
		d.Decode(&entriesBuf)
		if entriesBuf.isOverrun() {
			// Couldn't decode a complete entry.
			break
		}
		r.Entries = append(r.Entries, d)
	}
}

// Encode implements encoder.Encode.
func (r *Rreaddir) Encode(b *buffer) {
	entriesBuf := buffer{}
	for _, d := range r.Entries {
		d.Encode(&entriesBuf)
		if len(entriesBuf.data) >= int(r.Count) {
			break
		}
	}
	if len(entriesBuf.data) < int(r.Count) {
		r.Count = uint32(len(entriesBuf.data))
		r.payload = entriesBuf.data
	} else {
		r.payload = entriesBuf.data[:r.Count]
	}
	b.Write32(uint32(r.Count))
}

// Type implements message.Type.
func (*Rreaddir) Type() MsgType {
	return MsgRreaddir
}

// FixedSize implements payloader.FixedSize.
func (*Rreaddir) FixedSize() uint32 {
	return 4
}

// Payload implements payloader.Payload.
func (r *Rreaddir) Payload() []byte {
	return r.payload
}

// SetPayload implements payloader.SetPayload.
func (r *Rreaddir) SetPayload(p []byte) {
	r.payload = p
}

// String implements fmt.Stringer.
func (r *Rreaddir) String() string {
	return fmt.Sprintf("Rreaddir{Count: %d, Entries: %s}", r.Count, r.Entries)
}

// Tfsync is an fsync request.
type Tfsync struct {
	// FID is the fid to sync.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Tfsync) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Tfsync) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Tfsync) Type() MsgType {
	return MsgTfsync
}

// String implements fmt.Stringer.
func (t *Tfsync) String() string {
	return fmt.Sprintf("Tfsync{FID: %d}", t.FID)
}

// Rfsync is an fsync response.
type Rfsync struct {
}

// Decode implements encoder.Decode.
func (*Rfsync) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rfsync) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rfsync) Type() MsgType {
	return MsgRfsync
}

// String implements fmt.Stringer.
func (r *Rfsync) String() string {
	return fmt.Sprintf("Rfsync{}")
}

// Tstatfs is a stat request.
type Tstatfs struct {
	// FID is the root.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Tstatfs) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Tstatfs) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Tstatfs) Type() MsgType {
	return MsgTstatfs
}

// String implements fmt.Stringer.
func (t *Tstatfs) String() string {
	return fmt.Sprintf("Tstatfs{FID: %d}", t.FID)
}

// Rstatfs is the response for a Tstatfs.
type Rstatfs struct {
	// FSStat is the stat result.
	FSStat FSStat
}

// Decode implements encoder.Decode.
func (r *Rstatfs) Decode(b *buffer) {
	r.FSStat.Decode(b)
}

// Encode implements encoder.Encode.
func (r *Rstatfs) Encode(b *buffer) {
	r.FSStat.Encode(b)
}

// Type implements message.Type.
func (*Rstatfs) Type() MsgType {
	return MsgRstatfs
}

// String implements fmt.Stringer.
func (r *Rstatfs) String() string {
	return fmt.Sprintf("Rstatfs{FSStat: %v}", r.FSStat)
}

// Tflushf is a flush file request, not to be confused with Tflush.
type Tflushf struct {
	// FID is the FID to be flushed.
	FID FID
}

// Decode implements encoder.Decode.
func (t *Tflushf) Decode(b *buffer) {
	t.FID = b.ReadFID()
}

// Encode implements encoder.Encode.
func (t *Tflushf) Encode(b *buffer) {
	b.WriteFID(t.FID)
}

// Type implements message.Type.
func (*Tflushf) Type() MsgType {
	return MsgTflushf
}

// String implements fmt.Stringer.
func (t *Tflushf) String() string {
	return fmt.Sprintf("Tflushf{FID: %d}", t.FID)
}

// Rflushf is a flush file response.
type Rflushf struct {
}

// Decode implements encoder.Decode.
func (*Rflushf) Decode(b *buffer) {
}

// Encode implements encoder.Encode.
func (*Rflushf) Encode(b *buffer) {
}

// Type implements message.Type.
func (*Rflushf) Type() MsgType {
	return MsgRflushf
}

// String implements fmt.Stringer.
func (*Rflushf) String() string {
	return fmt.Sprintf("Rflushf{}")
}

// Twalkgetattr is a walk request.
type Twalkgetattr struct {
	// FID is the FID to be walked.
	FID FID

	// NewFID is the resulting FID.
	NewFID FID

	// Names are the set of names to be walked.
	Names []string
}

// Decode implements encoder.Decode.
func (t *Twalkgetattr) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.NewFID = b.ReadFID()
	n := b.Read16()
	t.Names = t.Names[:0]
	for i := 0; i < int(n); i++ {
		t.Names = append(t.Names, b.ReadString())
	}
}

// Encode implements encoder.Encode.
func (t *Twalkgetattr) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteFID(t.NewFID)
	b.Write16(uint16(len(t.Names)))
	for _, name := range t.Names {
		b.WriteString(name)
	}
}

// Type implements message.Type.
func (*Twalkgetattr) Type() MsgType {
	return MsgTwalkgetattr
}

// String implements fmt.Stringer.
func (t *Twalkgetattr) String() string {
	return fmt.Sprintf("Twalkgetattr{FID: %d, NewFID: %d, Names: %v}", t.FID, t.NewFID, t.Names)
}

// Rwalkgetattr is a walk response.
type Rwalkgetattr struct {
	// Valid indicates which fields are valid in the Attr below.
	Valid AttrMask

	// Attr is the set of attributes for the last QID (the file walked to).
	Attr Attr

	// QIDs are the set of QIDs returned.
	QIDs []QID
}

// Decode implements encoder.Decode.
func (r *Rwalkgetattr) Decode(b *buffer) {
	r.Valid.Decode(b)
	r.Attr.Decode(b)
	n := b.Read16()
	r.QIDs = r.QIDs[:0]
	for i := 0; i < int(n); i++ {
		var q QID
		q.Decode(b)
		r.QIDs = append(r.QIDs, q)
	}
}

// Encode implements encoder.Encode.
func (r *Rwalkgetattr) Encode(b *buffer) {
	r.Valid.Encode(b)
	r.Attr.Encode(b)
	b.Write16(uint16(len(r.QIDs)))
	for _, q := range r.QIDs {
		q.Encode(b)
	}
}

// Type implements message.Type.
func (*Rwalkgetattr) Type() MsgType {
	return MsgRwalkgetattr
}

// String implements fmt.Stringer.
func (r *Rwalkgetattr) String() string {
	return fmt.Sprintf("Rwalkgetattr{Valid: %s, Attr: %s, QIDs: %v}", r.Valid, r.Attr, r.QIDs)
}

// Tucreate is a Tlcreate message that includes a UID.
type Tucreate struct {
	Tlcreate

	// UID is the UID to use as the effective UID in creation messages.
	UID UID
}

// Decode implements encoder.Decode.
func (t *Tucreate) Decode(b *buffer) {
	t.Tlcreate.Decode(b)
	t.UID = b.ReadUID()
}

// Encode implements encoder.Encode.
func (t *Tucreate) Encode(b *buffer) {
	t.Tlcreate.Encode(b)
	b.WriteUID(t.UID)
}

// Type implements message.Type.
func (t *Tucreate) Type() MsgType {
	return MsgTucreate
}

// String implements fmt.Stringer.
func (t *Tucreate) String() string {
	return fmt.Sprintf("Tucreate{Tlcreate: %v, UID: %d}", &t.Tlcreate, t.UID)
}

// Rucreate is a file creation response.
type Rucreate struct {
	Rlcreate
}

// Type implements message.Type.
func (*Rucreate) Type() MsgType {
	return MsgRucreate
}

// String implements fmt.Stringer.
func (r *Rucreate) String() string {
	return fmt.Sprintf("Rucreate{%v}", &r.Rlcreate)
}

// Tumkdir is a Tmkdir message that includes a UID.
type Tumkdir struct {
	Tmkdir

	// UID is the UID to use as the effective UID in creation messages.
	UID UID
}

// Decode implements encoder.Decode.
func (t *Tumkdir) Decode(b *buffer) {
	t.Tmkdir.Decode(b)
	t.UID = b.ReadUID()
}

// Encode implements encoder.Encode.
func (t *Tumkdir) Encode(b *buffer) {
	t.Tmkdir.Encode(b)
	b.WriteUID(t.UID)
}

// Type implements message.Type.
func (t *Tumkdir) Type() MsgType {
	return MsgTumkdir
}

// String implements fmt.Stringer.
func (t *Tumkdir) String() string {
	return fmt.Sprintf("Tumkdir{Tmkdir: %v, UID: %d}", &t.Tmkdir, t.UID)
}

// Rumkdir is a umkdir response.
type Rumkdir struct {
	Rmkdir
}

// Type implements message.Type.
func (*Rumkdir) Type() MsgType {
	return MsgRumkdir
}

// String implements fmt.Stringer.
func (r *Rumkdir) String() string {
	return fmt.Sprintf("Rumkdir{%v}", &r.Rmkdir)
}

// Tumknod is a Tmknod message that includes a UID.
type Tumknod struct {
	Tmknod

	// UID is the UID to use as the effective UID in creation messages.
	UID UID
}

// Decode implements encoder.Decode.
func (t *Tumknod) Decode(b *buffer) {
	t.Tmknod.Decode(b)
	t.UID = b.ReadUID()
}

// Encode implements encoder.Encode.
func (t *Tumknod) Encode(b *buffer) {
	t.Tmknod.Encode(b)
	b.WriteUID(t.UID)
}

// Type implements message.Type.
func (t *Tumknod) Type() MsgType {
	return MsgTumknod
}

// String implements fmt.Stringer.
func (t *Tumknod) String() string {
	return fmt.Sprintf("Tumknod{Tmknod: %v, UID: %d}", &t.Tmknod, t.UID)
}

// Rumknod is a umknod response.
type Rumknod struct {
	Rmknod
}

// Type implements message.Type.
func (*Rumknod) Type() MsgType {
	return MsgRumknod
}

// String implements fmt.Stringer.
func (r *Rumknod) String() string {
	return fmt.Sprintf("Rumknod{%v}", &r.Rmknod)
}

// Tusymlink is a Tsymlink message that includes a UID.
type Tusymlink struct {
	Tsymlink

	// UID is the UID to use as the effective UID in creation messages.
	UID UID
}

// Decode implements encoder.Decode.
func (t *Tusymlink) Decode(b *buffer) {
	t.Tsymlink.Decode(b)
	t.UID = b.ReadUID()
}

// Encode implements encoder.Encode.
func (t *Tusymlink) Encode(b *buffer) {
	t.Tsymlink.Encode(b)
	b.WriteUID(t.UID)
}

// Type implements message.Type.
func (t *Tusymlink) Type() MsgType {
	return MsgTusymlink
}

// String implements fmt.Stringer.
func (t *Tusymlink) String() string {
	return fmt.Sprintf("Tusymlink{Tsymlink: %v, UID: %d}", &t.Tsymlink, t.UID)
}

// Rusymlink is a usymlink response.
type Rusymlink struct {
	Rsymlink
}

// Type implements message.Type.
func (*Rusymlink) Type() MsgType {
	return MsgRusymlink
}

// String implements fmt.Stringer.
func (r *Rusymlink) String() string {
	return fmt.Sprintf("Rusymlink{%v}", &r.Rsymlink)
}

// Tlconnect is a connect request.
type Tlconnect struct {
	// FID is the FID to be connected.
	FID FID

	// Flags are the connect flags.
	Flags ConnectFlags
}

// Decode implements encoder.Decode.
func (t *Tlconnect) Decode(b *buffer) {
	t.FID = b.ReadFID()
	t.Flags = b.ReadConnectFlags()
}

// Encode implements encoder.Encode.
func (t *Tlconnect) Encode(b *buffer) {
	b.WriteFID(t.FID)
	b.WriteConnectFlags(t.Flags)
}

// Type implements message.Type.
func (*Tlconnect) Type() MsgType {
	return MsgTlconnect
}

// String implements fmt.Stringer.
func (t *Tlconnect) String() string {
	return fmt.Sprintf("Tlconnect{FID: %d, Flags: %v}", t.FID, t.Flags)
}

// Rlconnect is a connect response.
type Rlconnect struct {
	filePayload
}

// Decode implements encoder.Decode.
func (r *Rlconnect) Decode(*buffer) {}

// Encode implements encoder.Encode.
func (r *Rlconnect) Encode(*buffer) {}

// Type implements message.Type.
func (*Rlconnect) Type() MsgType {
	return MsgRlconnect
}

// String implements fmt.Stringer.
func (r *Rlconnect) String() string {
	return fmt.Sprintf("Rlconnect{File: %v}", r.File)
}

// Tchannel creates a new channel.
type Tchannel struct {
	// ID is the channel ID.
	ID uint32

	// Control is 0 if the Rchannel response should provide the flipcall
	// component of the channel, and 1 if the Rchannel response should
	// provide the fdchannel component of the channel.
	Control uint32
}

// Decode implements encoder.Decode.
func (t *Tchannel) Decode(b *buffer) {
	t.ID = b.Read32()
	t.Control = b.Read32()
}

// Encode implements encoder.Encode.
func (t *Tchannel) Encode(b *buffer) {
	b.Write32(t.ID)
	b.Write32(t.Control)
}

// Type implements message.Type.
func (*Tchannel) Type() MsgType {
	return MsgTchannel
}

// String implements fmt.Stringer.
func (t *Tchannel) String() string {
	return fmt.Sprintf("Tchannel{ID: %d, Control: %d}", t.ID, t.Control)
}

// Rchannel is the channel response.
type Rchannel struct {
	Offset uint64
	Length uint64
	filePayload
}

// Decode implements encoder.Decode.
func (r *Rchannel) Decode(b *buffer) {
	r.Offset = b.Read64()
	r.Length = b.Read64()
}

// Encode implements encoder.Encode.
func (r *Rchannel) Encode(b *buffer) {
	b.Write64(r.Offset)
	b.Write64(r.Length)
}

// Type implements message.Type.
func (*Rchannel) Type() MsgType {
	return MsgRchannel
}

// String implements fmt.Stringer.
func (r *Rchannel) String() string {
	return fmt.Sprintf("Rchannel{Offset: %d, Length: %d}", r.Offset, r.Length)
}

const maxCacheSize = 3

// msgFactory is used to reduce allocations by caching messages for reuse.
type msgFactory struct {
	create func() message
	cache  chan message
}

// msgRegistry indexes all message factories by type.
var msgRegistry registry

type registry struct {
	factories [math.MaxUint8]msgFactory

	// largestFixedSize is computed so that given some message size M, you can
	// compute the maximum payload size (e.g. for Twrite, Rread) with
	// M-largestFixedSize. You could do this individual on a per-message basis,
	// but it's easier to compute a single maximum safe payload.
	largestFixedSize uint32
}

// get returns a new message by type.
//
// An error is returned in the case of an unknown message.
//
// This takes, and ignores, a message tag so that it may be used directly as a
// lookupTagAndType function for recv (by design).
func (r *registry) get(_ Tag, t MsgType) (message, error) {
	entry := &r.factories[t]
	if entry.create == nil {
		return nil, &ErrInvalidMsgType{t}
	}

	select {
	case msg := <-entry.cache:
		return msg, nil
	default:
		return entry.create(), nil
	}
}

func (r *registry) put(msg message) {
	if p, ok := msg.(payloader); ok {
		p.SetPayload(nil)
	}
	if f, ok := msg.(filer); ok {
		f.SetFilePayload(nil)
	}

	entry := &r.factories[msg.Type()]
	select {
	case entry.cache <- msg:
	default:
	}
}

// register registers the given message type.
//
// This may cause panic on failure and should only be used from init.
func (r *registry) register(t MsgType, fn func() message) {
	if int(t) >= len(r.factories) {
		panic(fmt.Sprintf("message type %d is too large. It must be smaller than %d", t, len(r.factories)))
	}
	if r.factories[t].create != nil {
		panic(fmt.Sprintf("duplicate message type %d: first is %T, second is %T", t, r.factories[t].create(), fn()))
	}
	r.factories[t] = msgFactory{
		create: fn,
		cache:  make(chan message, maxCacheSize),
	}

	if size := calculateSize(fn()); size > r.largestFixedSize {
		r.largestFixedSize = size
	}
}

func calculateSize(m message) uint32 {
	if p, ok := m.(payloader); ok {
		return p.FixedSize()
	}
	var dataBuf buffer
	m.Encode(&dataBuf)
	return uint32(len(dataBuf.data))
}

func init() {
	msgRegistry.register(MsgRlerror, func() message { return &Rlerror{} })
	msgRegistry.register(MsgTstatfs, func() message { return &Tstatfs{} })
	msgRegistry.register(MsgRstatfs, func() message { return &Rstatfs{} })
	msgRegistry.register(MsgTlopen, func() message { return &Tlopen{} })
	msgRegistry.register(MsgRlopen, func() message { return &Rlopen{} })
	msgRegistry.register(MsgTlcreate, func() message { return &Tlcreate{} })
	msgRegistry.register(MsgRlcreate, func() message { return &Rlcreate{} })
	msgRegistry.register(MsgTsymlink, func() message { return &Tsymlink{} })
	msgRegistry.register(MsgRsymlink, func() message { return &Rsymlink{} })
	msgRegistry.register(MsgTmknod, func() message { return &Tmknod{} })
	msgRegistry.register(MsgRmknod, func() message { return &Rmknod{} })
	msgRegistry.register(MsgTrename, func() message { return &Trename{} })
	msgRegistry.register(MsgRrename, func() message { return &Rrename{} })
	msgRegistry.register(MsgTreadlink, func() message { return &Treadlink{} })
	msgRegistry.register(MsgRreadlink, func() message { return &Rreadlink{} })
	msgRegistry.register(MsgTgetattr, func() message { return &Tgetattr{} })
	msgRegistry.register(MsgRgetattr, func() message { return &Rgetattr{} })
	msgRegistry.register(MsgTsetattr, func() message { return &Tsetattr{} })
	msgRegistry.register(MsgRsetattr, func() message { return &Rsetattr{} })
	msgRegistry.register(MsgTxattrwalk, func() message { return &Txattrwalk{} })
	msgRegistry.register(MsgRxattrwalk, func() message { return &Rxattrwalk{} })
	msgRegistry.register(MsgTxattrcreate, func() message { return &Txattrcreate{} })
	msgRegistry.register(MsgRxattrcreate, func() message { return &Rxattrcreate{} })
	msgRegistry.register(MsgTreaddir, func() message { return &Treaddir{} })
	msgRegistry.register(MsgRreaddir, func() message { return &Rreaddir{} })
	msgRegistry.register(MsgTfsync, func() message { return &Tfsync{} })
	msgRegistry.register(MsgRfsync, func() message { return &Rfsync{} })
	msgRegistry.register(MsgTlink, func() message { return &Tlink{} })
	msgRegistry.register(MsgRlink, func() message { return &Rlink{} })
	msgRegistry.register(MsgTmkdir, func() message { return &Tmkdir{} })
	msgRegistry.register(MsgRmkdir, func() message { return &Rmkdir{} })
	msgRegistry.register(MsgTrenameat, func() message { return &Trenameat{} })
	msgRegistry.register(MsgRrenameat, func() message { return &Rrenameat{} })
	msgRegistry.register(MsgTunlinkat, func() message { return &Tunlinkat{} })
	msgRegistry.register(MsgRunlinkat, func() message { return &Runlinkat{} })
	msgRegistry.register(MsgTversion, func() message { return &Tversion{} })
	msgRegistry.register(MsgRversion, func() message { return &Rversion{} })
	msgRegistry.register(MsgTauth, func() message { return &Tauth{} })
	msgRegistry.register(MsgRauth, func() message { return &Rauth{} })
	msgRegistry.register(MsgTattach, func() message { return &Tattach{} })
	msgRegistry.register(MsgRattach, func() message { return &Rattach{} })
	msgRegistry.register(MsgTflush, func() message { return &Tflush{} })
	msgRegistry.register(MsgRflush, func() message { return &Rflush{} })
	msgRegistry.register(MsgTwalk, func() message { return &Twalk{} })
	msgRegistry.register(MsgRwalk, func() message { return &Rwalk{} })
	msgRegistry.register(MsgTread, func() message { return &Tread{} })
	msgRegistry.register(MsgRread, func() message { return &Rread{} })
	msgRegistry.register(MsgTwrite, func() message { return &Twrite{} })
	msgRegistry.register(MsgRwrite, func() message { return &Rwrite{} })
	msgRegistry.register(MsgTclunk, func() message { return &Tclunk{} })
	msgRegistry.register(MsgRclunk, func() message { return &Rclunk{} })
	msgRegistry.register(MsgTremove, func() message { return &Tremove{} })
	msgRegistry.register(MsgRremove, func() message { return &Rremove{} })
	msgRegistry.register(MsgTflushf, func() message { return &Tflushf{} })
	msgRegistry.register(MsgRflushf, func() message { return &Rflushf{} })
	msgRegistry.register(MsgTwalkgetattr, func() message { return &Twalkgetattr{} })
	msgRegistry.register(MsgRwalkgetattr, func() message { return &Rwalkgetattr{} })
	msgRegistry.register(MsgTucreate, func() message { return &Tucreate{} })
	msgRegistry.register(MsgRucreate, func() message { return &Rucreate{} })
	msgRegistry.register(MsgTumkdir, func() message { return &Tumkdir{} })
	msgRegistry.register(MsgRumkdir, func() message { return &Rumkdir{} })
	msgRegistry.register(MsgTumknod, func() message { return &Tumknod{} })
	msgRegistry.register(MsgRumknod, func() message { return &Rumknod{} })
	msgRegistry.register(MsgTusymlink, func() message { return &Tusymlink{} })
	msgRegistry.register(MsgRusymlink, func() message { return &Rusymlink{} })
	msgRegistry.register(MsgTlconnect, func() message { return &Tlconnect{} })
	msgRegistry.register(MsgRlconnect, func() message { return &Rlconnect{} })
	msgRegistry.register(MsgTallocate, func() message { return &Tallocate{} })
	msgRegistry.register(MsgRallocate, func() message { return &Rallocate{} })
	msgRegistry.register(MsgTchannel, func() message { return &Tchannel{} })
	msgRegistry.register(MsgRchannel, func() message { return &Rchannel{} })
}
