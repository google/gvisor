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

package proc

import (
	"fmt"
	"io"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// hostname is a file containing the system hostname.
//
// +stateify savable
type hostname struct {
	ramfs.Entry
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (hostname) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	contents := []byte(utsns.HostName() + "\n")

	if offset >= int64(len(contents)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err
}

func (p *proc) newHostname(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	h := &hostname{}
	h.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))
	return newFile(h, msrc, fs.SpecialFile, nil)
}

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

func (p *proc) newKernelDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	d.AddChild(ctx, "hostname", p.newHostname(ctx, msrc))

	d.AddChild(ctx, "shmmax", p.newStubProcFSFile(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMAX, 10))))
	d.AddChild(ctx, "shmall", p.newStubProcFSFile(ctx, msrc, []byte(strconv.FormatUint(linux.SHMALL, 10))))
	d.AddChild(ctx, "shmmni", p.newStubProcFSFile(ctx, msrc, []byte(strconv.FormatUint(linux.SHMMNI, 10))))
	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newVMDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	d.AddChild(ctx, "mmap_min_addr", seqfile.NewSeqFileInode(ctx, &mmapMinAddrData{p.k}, msrc))
	d.AddChild(ctx, "overcommit_memory", seqfile.NewSeqFileInode(ctx, &overcommitMemory{}, msrc))
	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	d.AddChild(ctx, "kernel", p.newKernelDir(ctx, msrc))
	d.AddChild(ctx, "vm", p.newVMDir(ctx, msrc))

	// If we're using rpcinet we will let it manage /proc/sys/net.
	if _, ok := p.k.NetworkStack().(*rpcinet.Stack); ok {
		d.AddChild(ctx, "net", newRPCInetProcSysNet(ctx, msrc))
	} else {
		d.AddChild(ctx, "net", p.newSysNetDir(ctx, msrc))
	}

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}
