// Copyright 2018 Google LLC
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

package proc

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// An idMapSeqSource is a seqfile.SeqSource that returns UID or GID mappings
// from a task's user namespace.
//
// +stateify savable
type idMapSeqSource struct {
	t    *kernel.Task
	gids bool
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (imss *idMapSeqSource) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (imss *idMapSeqSource) ReadSeqFileData(ctx context.Context, handle seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	var start int
	if handle != nil {
		start = handle.(*idMapSeqHandle).value
	}
	var entries []auth.IDMapEntry
	if imss.gids {
		entries = imss.t.UserNamespace().GIDMap()
	} else {
		entries = imss.t.UserNamespace().UIDMap()
	}
	var data []seqfile.SeqData
	i := 1
	for _, e := range entries {
		if i > start {
			data = append(data, seqfile.SeqData{
				Buf:    idMapLineFromEntry(e),
				Handle: &idMapSeqHandle{i},
			})
		}
		i++
	}
	return data, 0
}

// TODO: Fix issue requiring idMapSeqHandle wrapping an int.
//
// +stateify savable
type idMapSeqHandle struct {
	value int
}

// +stateify savable
type idMapSeqFile struct {
	seqfile.SeqFile
}

// newUIDMap returns a new uid_map file.
func newUIDMap(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newIDMap(t, msrc, false /* gids */)
}

// newGIDMap returns a new gid_map file.
func newGIDMap(t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	return newIDMap(t, msrc, true /* gids */)
}

func newIDMap(t *kernel.Task, msrc *fs.MountSource, gids bool) *fs.Inode {
	imsf := &idMapSeqFile{seqfile.SeqFile{SeqSource: &idMapSeqSource{
		t:    t,
		gids: gids,
	}}}
	imsf.InitEntry(t, fs.RootOwner, fs.FilePermsFromMode(0644))
	return newFile(imsf, msrc, fs.SpecialFile, t)
}

func (imsf *idMapSeqFile) source() *idMapSeqSource {
	return imsf.SeqFile.SeqSource.(*idMapSeqSource)
}

// "There is an (arbitrary) limit on the number of lines in the file. As at
// Linux 3.18, the limit is five lines." - user_namespaces(7)
const maxIDMapLines = 5

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev.
func (imsf *idMapSeqFile) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// "In addition, the number of bytes written to the file must be less than
	// the system page size, and the write must be performed at the start of
	// the file ..." - user_namespaces(7)
	srclen := src.NumBytes()
	if srclen >= usermem.PageSize || offset != 0 {
		return 0, syserror.EINVAL
	}
	b := make([]byte, srclen)
	if _, err := src.CopyIn(ctx, b); err != nil {
		return 0, err
	}
	lines := bytes.SplitN(bytes.TrimSpace(b), []byte("\n"), maxIDMapLines+1)
	if len(lines) > maxIDMapLines {
		return 0, syserror.EINVAL
	}
	entries := make([]auth.IDMapEntry, len(lines))
	for i, l := range lines {
		e, err := idMapEntryFromLine(string(l))
		if err != nil {
			return 0, syserror.EINVAL
		}
		entries[i] = e
	}
	t := imsf.source().t
	var err error
	if imsf.source().gids {
		err = t.UserNamespace().SetGIDMap(ctx, entries)
	} else {
		err = t.UserNamespace().SetUIDMap(ctx, entries)
	}
	if err != nil {
		return 0, err
	}
	return int64(len(b)), nil
}

func idMapLineFromEntry(e auth.IDMapEntry) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%10d %10d %10d\n", e.FirstID, e.FirstParentID, e.Length)
	return b.Bytes()
}

func idMapEntryFromLine(line string) (auth.IDMapEntry, error) {
	var e auth.IDMapEntry
	_, err := fmt.Sscan(line, &e.FirstID, &e.FirstParentID, &e.Length)
	return e, err
}
