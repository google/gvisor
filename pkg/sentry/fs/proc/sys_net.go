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

// +stateify savable
type tcpMem struct {
	ramfs.Entry
	s    inet.Stack `state:"wait"`
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
	m.size = inet.TCPBufferSize{
		Min:     int(buf[0]),
		Default: int(buf[1]),
		Max:     int(buf[2]),
	}
	if err := m.writeSize(); err != nil {
		return n, err
	}
	return n, cperr
}

func (m *tcpMem) writeSize() error {
	switch m.dir {
	case tcpRMem:
		return m.s.SetTCPReceiveBufferSize(m.size)
	case tcpWMem:
		return m.s.SetTCPSendBufferSize(m.size)
	default:
		panic(fmt.Sprintf("unknown tcpMem.dir: %v", m.dir))
	}
}

// +stateify savable
type tcpSack struct {
	ramfs.Entry
	s       inet.Stack `state:"wait"`
	enabled *bool
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

	if s.enabled == nil {
		sack, err := s.s.TCPSACKEnabled()
		if err != nil {
			return 0, err
		}
		s.enabled = &sack
	}

	val := "0\n"
	if *s.enabled {
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
	if s.enabled == nil {
		s.enabled = new(bool)
	}
	*s.enabled = v != 0
	return n, s.s.SetTCPSACKEnabled(*s.enabled)
}

func (p *proc) newSysNetCore(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))

	// The following files are simple stubs until they are implemented in
	// netstack, most of these files are configuration related. We use the
	// value closest to the actual netstack behavior or any empty file,
	// all of these files will have mode 0444 (read-only for all users).
	d.AddChild(ctx, "default_qdisc", p.newStubProcFSFile(ctx, msrc, []byte("pfifo_fast")))
	d.AddChild(ctx, "message_burst", p.newStubProcFSFile(ctx, msrc, []byte("10")))
	d.AddChild(ctx, "message_cost", p.newStubProcFSFile(ctx, msrc, []byte("5")))
	d.AddChild(ctx, "optmem_max", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "rmem_default", p.newStubProcFSFile(ctx, msrc, []byte("212992")))
	d.AddChild(ctx, "rmem_max", p.newStubProcFSFile(ctx, msrc, []byte("212992")))
	d.AddChild(ctx, "somaxconn", p.newStubProcFSFile(ctx, msrc, []byte("128")))
	d.AddChild(ctx, "wmem_default", p.newStubProcFSFile(ctx, msrc, []byte("212992")))
	d.AddChild(ctx, "wmem_max", p.newStubProcFSFile(ctx, msrc, []byte("212992")))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysNetIPv4Dir(ctx context.Context, msrc *fs.MountSource, s inet.Stack) *fs.Inode {
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

	// The following files are simple stubs until they are implemented in
	// netstack, most of these files are configuration related. We use the
	// value closest to the actual netstack behavior or any empty file,
	// all of these files will have mode 0444 (read-only for all users).
	d.AddChild(ctx, "ip_local_port_range", p.newStubProcFSFile(ctx, msrc, []byte("16000   65535")))
	d.AddChild(ctx, "ip_local_reserved_ports", p.newStubProcFSFile(ctx, msrc, []byte("")))
	d.AddChild(ctx, "ipfrag_time", p.newStubProcFSFile(ctx, msrc, []byte("30")))
	d.AddChild(ctx, "ip_nonlocal_bind", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "ip_no_pmtu_disc", p.newStubProcFSFile(ctx, msrc, []byte("1")))

	// tcp_allowed_congestion_control tell the user what they are able to do as an
	// unprivledged process so we leave it empty.
	d.AddChild(ctx, "tcp_allowed_congestion_control", p.newStubProcFSFile(ctx, msrc, []byte("")))
	d.AddChild(ctx, "tcp_available_congestion_control", p.newStubProcFSFile(ctx, msrc, []byte("reno")))
	d.AddChild(ctx, "tcp_congestion_control", p.newStubProcFSFile(ctx, msrc, []byte("reno")))

	// Many of the following stub files are features netstack doesn't support
	// and are therefore "0" for disabled.
	d.AddChild(ctx, "tcp_base_mss", p.newStubProcFSFile(ctx, msrc, []byte("1280")))
	d.AddChild(ctx, "tcp_dsack", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_early_retrans", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_fack", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_fastopen", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_fastopen_key", p.newStubProcFSFile(ctx, msrc, []byte("")))
	d.AddChild(ctx, "tcp_invalid_ratelimit", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_keepalive_intvl", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_keepalive_probes", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_keepalive_time", p.newStubProcFSFile(ctx, msrc, []byte("7200")))
	d.AddChild(ctx, "tcp_mtu_probing", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_no_metrics_save", p.newStubProcFSFile(ctx, msrc, []byte("1")))
	d.AddChild(ctx, "tcp_probe_interval", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_probe_threshold", p.newStubProcFSFile(ctx, msrc, []byte("0")))
	d.AddChild(ctx, "tcp_retries1", p.newStubProcFSFile(ctx, msrc, []byte("3")))
	d.AddChild(ctx, "tcp_retries2", p.newStubProcFSFile(ctx, msrc, []byte("15")))
	d.AddChild(ctx, "tcp_rfc1337", p.newStubProcFSFile(ctx, msrc, []byte("1")))
	d.AddChild(ctx, "tcp_slow_start_after_idle", p.newStubProcFSFile(ctx, msrc, []byte("1")))
	d.AddChild(ctx, "tcp_synack_retries", p.newStubProcFSFile(ctx, msrc, []byte("5")))
	d.AddChild(ctx, "tcp_syn_retries", p.newStubProcFSFile(ctx, msrc, []byte("3")))
	d.AddChild(ctx, "tcp_timestamps", p.newStubProcFSFile(ctx, msrc, []byte("1")))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

func (p *proc) newSysNetDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	if s := p.k.NetworkStack(); s != nil {
		d.AddChild(ctx, "ipv4", p.newSysNetIPv4Dir(ctx, msrc, s))
		d.AddChild(ctx, "core", p.newSysNetCore(ctx, msrc, s))
	}
	return newFile(d, msrc, fs.SpecialDirectory, nil)
}
