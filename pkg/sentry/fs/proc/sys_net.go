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
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tcpMemDir int

const (
	tcpRMem tcpMemDir = iota
	tcpWMem
)

// tcpMemInode is used to read/write the size of netstack tcp buffers.
//
// TODO(b/121381035): If we have multiple proc mounts, concurrent writes can
// leave netstack and the proc files in an inconsistent state. Since we set the
// buffer size from these proc files on restore, we may also race and end up in
// an inconsistent state on restore.
//
// +stateify savable
type tcpMemInode struct {
	fsutil.SimpleFileInode
	dir tcpMemDir
	s   inet.Stack `state:"wait"`

	// size stores the tcp buffer size during save, and sets the buffer
	// size in netstack in restore. We must save/restore this here, since
	// netstack itself is stateless.
	size inet.TCPBufferSize

	// mu protects against concurrent reads/writes to files based on this
	// inode.
	mu sync.Mutex `state:"nosave"`
}

var _ fs.InodeOperations = (*tcpMemInode)(nil)

func newTCPMemInode(ctx context.Context, msrc *fs.MountSource, s inet.Stack, dir tcpMemDir) *fs.Inode {
	tm := &tcpMemInode{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		s:               s,
		dir:             dir,
	}
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	msrc.IncRef()
	return fs.NewInode(ctx, tm, msrc, sattr)
}

// GetFile implements fs.InodeOperations.GetFile.
func (m *tcpMemInode) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	return fs.NewFile(ctx, dirent, flags, &tcpMemFile{tcpMemInode: m}), nil
}

// +stateify savable
type tcpMemFile struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	tcpMemInode *tcpMemInode
}

var _ fs.FileOperations = (*tcpMemFile)(nil)

// Read implements fs.FileOperations.Read.
func (f *tcpMemFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, io.EOF
	}
	f.tcpMemInode.mu.Lock()
	defer f.tcpMemInode.mu.Unlock()

	size, err := readSize(f.tcpMemInode.dir, f.tcpMemInode.s)
	if err != nil {
		return 0, err
	}
	s := fmt.Sprintf("%d\t%d\t%d\n", size.Min, size.Default, size.Max)
	n, err := dst.CopyOut(ctx, []byte(s))
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
func (f *tcpMemFile) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	f.tcpMemInode.mu.Lock()
	defer f.tcpMemInode.mu.Unlock()

	src = src.TakeFirst(usermem.PageSize - 1)
	size, err := readSize(f.tcpMemInode.dir, f.tcpMemInode.s)
	if err != nil {
		return 0, err
	}
	buf := []int32{int32(size.Min), int32(size.Default), int32(size.Max)}
	n, cperr := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, buf, src.Opts)
	newSize := inet.TCPBufferSize{
		Min:     int(buf[0]),
		Default: int(buf[1]),
		Max:     int(buf[2]),
	}
	if err := writeSize(f.tcpMemInode.dir, f.tcpMemInode.s, newSize); err != nil {
		return n, err
	}
	return n, cperr
}

func readSize(dirType tcpMemDir, s inet.Stack) (inet.TCPBufferSize, error) {
	switch dirType {
	case tcpRMem:
		return s.TCPReceiveBufferSize()
	case tcpWMem:
		return s.TCPSendBufferSize()
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", dirType))
	}
}

func writeSize(dirType tcpMemDir, s inet.Stack, size inet.TCPBufferSize) error {
	switch dirType {
	case tcpRMem:
		return s.SetTCPReceiveBufferSize(size)
	case tcpWMem:
		return s.SetTCPSendBufferSize(size)
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", dirType))
	}
}

// +stateify savable
type tcpSack struct {
	stack   inet.Stack `state:"wait"`
	enabled *bool
	fsutil.SimpleFileInode
}

func newTCPSackInode(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	ts := &tcpSack{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		stack:           s,
	}
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	msrc.IncRef()
	return fs.NewInode(ctx, ts, msrc, sattr)
}

// GetFile implements fs.InodeOperations.GetFile.
func (s *tcpSack) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	flags.Pwrite = true
	return fs.NewFile(ctx, dirent, flags, &tcpSackFile{
		tcpSack: s,
		stack:   s.stack,
	}), nil
}

// +stateify savable
type tcpSackFile struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	tcpSack *tcpSack

	stack inet.Stack `state:"wait"`
}

// Read implements fs.FileOperations.Read.
func (f *tcpSackFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, io.EOF
	}

	if f.tcpSack.enabled == nil {
		sack, err := f.stack.TCPSACKEnabled()
		if err != nil {
			return 0, err
		}
		f.tcpSack.enabled = &sack
	}

	val := "0\n"
	if *f.tcpSack.enabled {
		// Technically, this is not quite compatible with Linux. Linux
		// stores these as an integer, so if you write "2" into
		// tcp_sack, you should get 2 back. Tough luck.
		val = "1\n"
	}
	n, err := dst.CopyOut(ctx, []byte(val))
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
func (f *tcpSackFile) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return n, err
	}
	if f.tcpSack.enabled == nil {
		f.tcpSack.enabled = new(bool)
	}
	*f.tcpSack.enabled = v != 0
	return n, f.tcpSack.stack.SetTCPSACKEnabled(*f.tcpSack.enabled)
}

func (p *proc) newSysNetCore(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	// The following files are simple stubs until they are implemented in
	// netstack, most of these files are configuration related. We use the
	// value closest to the actual netstack behavior or any empty file,
	// all of these files will have mode 0444 (read-only for all users).
	contents := map[string]*fs.Inode{
		"default_qdisc": newStaticProcInode(ctx, msrc, []byte("pfifo_fast")),
		"message_burst": newStaticProcInode(ctx, msrc, []byte("10")),
		"message_cost":  newStaticProcInode(ctx, msrc, []byte("5")),
		"optmem_max":    newStaticProcInode(ctx, msrc, []byte("0")),
		"rmem_default":  newStaticProcInode(ctx, msrc, []byte("212992")),
		"rmem_max":      newStaticProcInode(ctx, msrc, []byte("212992")),
		"somaxconn":     newStaticProcInode(ctx, msrc, []byte("128")),
		"wmem_default":  newStaticProcInode(ctx, msrc, []byte("212992")),
		"wmem_max":      newStaticProcInode(ctx, msrc, []byte("212992")),
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysNetIPv4Dir(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	contents := map[string]*fs.Inode{
		// Add tcp_sack.
		"tcp_sack": newTCPSackInode(ctx, msrc, s),

		// The following files are simple stubs until they are
		// implemented in netstack, most of these files are
		// configuration related. We use the value closest to the
		// actual netstack behavior or any empty file, all of these
		// files will have mode 0444 (read-only for all users).
		"ip_local_port_range":     newStaticProcInode(ctx, msrc, []byte("16000   65535")),
		"ip_local_reserved_ports": newStaticProcInode(ctx, msrc, []byte("")),
		"ipfrag_time":             newStaticProcInode(ctx, msrc, []byte("30")),
		"ip_nonlocal_bind":        newStaticProcInode(ctx, msrc, []byte("0")),
		"ip_no_pmtu_disc":         newStaticProcInode(ctx, msrc, []byte("1")),

		// tcp_allowed_congestion_control tell the user what they are
		// able to do as an unprivledged process so we leave it empty.
		"tcp_allowed_congestion_control":   newStaticProcInode(ctx, msrc, []byte("")),
		"tcp_available_congestion_control": newStaticProcInode(ctx, msrc, []byte("reno")),
		"tcp_congestion_control":           newStaticProcInode(ctx, msrc, []byte("reno")),

		// Many of the following stub files are features netstack
		// doesn't support. The unsupported features return "0" to
		// indicate they are disabled.
		"tcp_base_mss":              newStaticProcInode(ctx, msrc, []byte("1280")),
		"tcp_dsack":                 newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_early_retrans":         newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_fack":                  newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_fastopen":              newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_fastopen_key":          newStaticProcInode(ctx, msrc, []byte("")),
		"tcp_invalid_ratelimit":     newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_keepalive_intvl":       newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_keepalive_probes":      newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_keepalive_time":        newStaticProcInode(ctx, msrc, []byte("7200")),
		"tcp_mtu_probing":           newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_no_metrics_save":       newStaticProcInode(ctx, msrc, []byte("1")),
		"tcp_probe_interval":        newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_probe_threshold":       newStaticProcInode(ctx, msrc, []byte("0")),
		"tcp_retries1":              newStaticProcInode(ctx, msrc, []byte("3")),
		"tcp_retries2":              newStaticProcInode(ctx, msrc, []byte("15")),
		"tcp_rfc1337":               newStaticProcInode(ctx, msrc, []byte("1")),
		"tcp_slow_start_after_idle": newStaticProcInode(ctx, msrc, []byte("1")),
		"tcp_synack_retries":        newStaticProcInode(ctx, msrc, []byte("5")),
		"tcp_syn_retries":           newStaticProcInode(ctx, msrc, []byte("3")),
		"tcp_timestamps":            newStaticProcInode(ctx, msrc, []byte("1")),
	}

	// Add tcp_rmem.
	if _, err := s.TCPReceiveBufferSize(); err == nil {
		contents["tcp_rmem"] = newTCPMemInode(ctx, msrc, s, tcpRMem)
	}

	// Add tcp_wmem.
	if _, err := s.TCPSendBufferSize(); err == nil {
		contents["tcp_wmem"] = newTCPMemInode(ctx, msrc, s, tcpWMem)
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysNetDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	var contents map[string]*fs.Inode
	if s := p.k.NetworkStack(); s != nil {
		contents = map[string]*fs.Inode{
			"ipv4": p.newSysNetIPv4Dir(ctx, msrc, s),
			"core": p.newSysNetCore(ctx, msrc, s),
		}
	}
	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, nil)
}
