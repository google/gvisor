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

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type tcpMemDir int

const (
	tcpRMem tcpMemDir = iota
	tcpWMem
)

type tcpMem struct {
	ramfs.Entry
	s    inet.Stack
	size inet.TCPBufferSize
	dir  tcpMemDir
}

func newTCPMem(s inet.Stack, size inet.TCPBufferSize, dir tcpMemDir) *tcpMem {
	return &tcpMem{s: s, size: size, dir: dir}
}

func newTCPMemInode(ctx context.Context, msrc *fs.MountSource, s inet.Stack, size inet.TCPBufferSize, dir tcpMemDir) *fs.Inode {
	tm := newTCPMem(s, size, dir)
	tm.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0644))
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	return fs.NewInode(tm, msrc, sattr)
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (m *tcpMem) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, io.EOF
	}
	s := fmt.Sprintf("%d\t%d\t%d\n", m.size.Min, m.size.Default, m.size.Max)
	n, err := dst.CopyOut(ctx, []byte(s))
	return int64(n), err
}

// Truncate implements fs.InodeOperations.Truncate.
func (*tcpMem) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev.
func (m *tcpMem) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	src = src.TakeFirst(usermem.PageSize - 1)

	buf := []int32{int32(m.size.Min), int32(m.size.Default), int32(m.size.Max)}
	n, cperr := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, buf, src.Opts)
	size := inet.TCPBufferSize{
		Min:     int(buf[0]),
		Default: int(buf[1]),
		Max:     int(buf[2]),
	}
	var err error
	switch m.dir {
	case tcpRMem:
		err = m.s.SetTCPReceiveBufferSize(size)
	case tcpWMem:
		err = m.s.SetTCPSendBufferSize(size)
	default:
		panic(fmt.Sprintf("unknown tcpMem.dir: %v", m.dir))
	}
	if err != nil {
		return n, err
	}
	return n, cperr
}

type tcpSack struct {
	ramfs.Entry
	s inet.Stack `state:"nosave"` // S/R-FIXME
}

func newTCPSackInode(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	ts := &tcpSack{s: s}
	ts.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0644))
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.SpecialFile,
	}
	return fs.NewInode(ts, msrc, sattr)
}

func (s *tcpSack) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, io.EOF
	}

	sack, err := s.s.TCPSACKEnabled()
	if err != nil {
		return 0, err
	}

	val := "0\n"
	if sack {
		// Technically, this is not quite compatible with Linux. Linux
		// stores these as an integer, so if you write "2" into
		// tcp_sack, you should get 2 back. Tough luck.
		val = "1\n"
	}
	n, err := dst.CopyOut(ctx, []byte(val))
	return int64(n), err
}

// Truncate implements fs.InodeOperations.Truncate.
func (*tcpSack) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev.
func (s *tcpSack) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return n, err
	}
	return n, s.s.SetTCPSACKEnabled(v != 0)
}

func newSysNetIPv4Dir(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))

	// Add tcp_rmem.
	if rs, err := s.TCPReceiveBufferSize(); err == nil {
		d.AddChild(ctx, "tcp_rmem", newTCPMemInode(ctx, msrc, s, rs, tcpRMem))
	}

	// Add tcp_wmem.
	if ss, err := s.TCPSendBufferSize(); err == nil {
		d.AddChild(ctx, "tcp_wmem", newTCPMemInode(ctx, msrc, s, ss, tcpWMem))
	}

	// Add tcp_sack.
	d.AddChild(ctx, "tcp_sack", newTCPSackInode(ctx, msrc, s))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysNetDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	if s := p.k.NetworkStack(); s != nil {
		d.AddChild(ctx, "ipv4", newSysNetIPv4Dir(ctx, msrc, s))
	}
	return newFile(d, msrc, fs.SpecialDirectory, nil)
}
