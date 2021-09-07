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

package proc

import (
	"fmt"
	"io"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

// mmapMinAddrData backs /proc/sys/vm/mmap_min_addr.
//
// +stateify savable
type mmapMinAddrData struct {
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*mmapMinAddrData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (d *mmapMinAddrData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}
	return []seqfile.SeqData{
		{
			Buf:    []byte(fmt.Sprintf("%d\n", d.k.Platform.MinUserAddress())),
			Handle: (*mmapMinAddrData)(nil),
		},
	}, 0
}

// +stateify savable
type overcommitMemory struct{}

func (*overcommitMemory) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.
func (*overcommitMemory) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}
	return []seqfile.SeqData{
		{
			Buf:    []byte("0\n"),
			Handle: (*overcommitMemory)(nil),
		},
	}, 0
}

// +stateify savable
type maxMapCount struct{}

// NeedsUpdate implements seqfile.SeqSource.
func (*maxMapCount) NeedsUpdate(int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.
func (*maxMapCount) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}
	return []seqfile.SeqData{
		{
			Buf:    []byte("2147483647\n"),
			Handle: (*maxMapCount)(nil),
		},
	}, 0
}

func (p *proc) newKernelDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	h := hostname{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
	}

	children := map[string]*fs.Inode{
		"hostname": newProcInode(ctx, &h, msrc, fs.SpecialFile, nil),
		"sem":      newStaticProcInode(ctx, msrc, []byte(fmt.Sprintf("%d\t%d\t%d\t%d\n", linux.SEMMSL, linux.SEMMNS, linux.SEMOPM, linux.SEMMNI))),
		"shmall":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMALL, 10))),
		"shmmax":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMAX, 10))),
		"shmmni":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMNI, 10))),
		"msgmni":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.MSGMNI, 10))),
		"msgmax":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.MSGMAX, 10))),
		"msgmnb":   newStaticProcInode(ctx, msrc, []byte(strconv.FormatUint(linux.MSGMNB, 10))),
	}

	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newVMDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	children := map[string]*fs.Inode{
		"max_map_count":     seqfile.NewSeqFileInode(ctx, &maxMapCount{}, msrc),
		"mmap_min_addr":     seqfile.NewSeqFileInode(ctx, &mmapMinAddrData{p.k}, msrc),
		"overcommit_memory": seqfile.NewSeqFileInode(ctx, &overcommitMemory{}, msrc),
	}
	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	children := map[string]*fs.Inode{
		"kernel": p.newKernelDir(ctx, msrc),
		"net":    p.newSysNetDir(ctx, msrc),
		"vm":     p.newVMDir(ctx, msrc),
	}

	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

// hostname is the inode for a file containing the system hostname.
//
// +stateify savable
type hostname struct {
	fsutil.SimpleFileInode
}

// GetFile implements fs.InodeOperations.GetFile.
func (h *hostname) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &hostnameFile{}), nil
}

var _ fs.InodeOperations = (*hostname)(nil)

// +stateify savable
type hostnameFile struct {
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

// Read implements fs.FileOperations.Read.
func (hf *hostnameFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	contents := []byte(utsns.HostName() + "\n")
	if offset >= int64(len(contents)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err

}

var _ fs.FileOperations = (*hostnameFile)(nil)

// LINT.ThenChange(../../fsimpl/proc/tasks_sys.go)
