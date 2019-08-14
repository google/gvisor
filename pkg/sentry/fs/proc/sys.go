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

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/rpcinet"
)

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

func (p *proc) newVMDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	children := map[string]*fs.Inode{
		"mmap_min_addr":     seqfile.NewSeqFileInode(ctx, &mmapMinAddrData{p.k}, msrc),
		"overcommit_memory": seqfile.NewSeqFileInode(ctx, &overcommitMemory{}, msrc),
	}
	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	children := map[string]*fs.Inode{
		"kernel": p.newKernelDir(ctx, msrc),
		"vm":     p.newVMDir(ctx, msrc),
	}

	// If we're using rpcinet we will let it manage /proc/sys/net.
	if _, ok := p.k.NetworkStack().(*rpcinet.Stack); ok {
		children["net"] = newRPCInetProcSysNet(ctx, msrc)
	} else {
		children["net"] = p.newSysNetDir(ctx, msrc)
	}

	d := ramfs.NewDir(ctx, children, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}
