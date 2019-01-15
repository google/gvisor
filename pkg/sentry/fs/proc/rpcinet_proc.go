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
	"io"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// rpcInetInode implments fs.InodeOperations.
type rpcInetInode struct {
	fsutil.SimpleFileInode

	// filepath is the full path of this rpcInetInode.
	filepath string

	k *kernel.Kernel
}

func newRPCInetInode(ctx context.Context, msrc *fs.MountSource, filepath string, mode linux.FileMode) *fs.Inode {
	f := &rpcInetInode{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(mode), linux.PROC_SUPER_MAGIC),
		filepath:        filepath,
		k:               kernel.KernelFromContext(ctx),
	}
	return newProcInode(f, msrc, fs.SpecialFile, nil)
}

// GetFile implements fs.InodeOperations.GetFile.
func (i *rpcInetInode) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	flags.Pwrite = true
	fops := &rpcInetFile{
		inode: i,
	}
	return fs.NewFile(ctx, dirent, flags, fops), nil
}

// rpcInetFile implements fs.FileOperations as RPCs.
type rpcInetFile struct {
	waiter.AlwaysReady       `state:"nosave"`
	fsutil.FileGenericSeek   `state:"nosave"`
	fsutil.FileNoIoctl       `state:"nosave"`
	fsutil.FileNoMMap        `state:"nosave"`
	fsutil.FileNoopFlush     `state:"nosave"`
	fsutil.FileNoopFsync     `state:"nosave"`
	fsutil.FileNoopRelease   `state:"nosave"`
	fsutil.FileNotDirReaddir `state:"nosave"`

	inode *rpcInetInode
}

// Read implements fs.FileOperations.Read.
//
// This method can panic if an rpcInetInode was created without an rpcinet
// stack.
func (f *rpcInetFile) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	s, ok := f.inode.k.NetworkStack().(*rpcinet.Stack)
	if !ok {
		panic("Network stack is not a rpcinet.")
	}

	contents, se := s.RPCReadFile(f.inode.filepath)
	if se != nil || offset >= int64(len(contents)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err
}

// Write implements fs.FileOperations.Write.
//
// This method can panic if an rpcInetInode was created without an rpcInet
// stack.
func (f *rpcInetFile) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	s, ok := f.inode.k.NetworkStack().(*rpcinet.Stack)
	if !ok {
		panic("Network stack is not a rpcinet.")
	}

	if src.NumBytes() == 0 {
		return 0, nil
	}

	b := make([]byte, src.NumBytes(), src.NumBytes())
	n, err := src.CopyIn(ctx, b)
	if err != nil {
		return int64(n), err
	}

	written, se := s.RPCWriteFile(f.inode.filepath, b)
	return int64(written), se.ToError()
}

// newRPCInetProcNet will build an inode for /proc/net.
func newRPCInetProcNet(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	contents := map[string]*fs.Inode{
		"arp":        newRPCInetInode(ctx, msrc, "/proc/net/arp", 0444),
		"dev":        newRPCInetInode(ctx, msrc, "/proc/net/dev", 0444),
		"if_inet6":   newRPCInetInode(ctx, msrc, "/proc/net/if_inet6", 0444),
		"ipv6_route": newRPCInetInode(ctx, msrc, "/proc/net/ipv6_route", 0444),
		"netlink":    newRPCInetInode(ctx, msrc, "/proc/net/netlink", 0444),
		"netstat":    newRPCInetInode(ctx, msrc, "/proc/net/netstat", 0444),
		"packet":     newRPCInetInode(ctx, msrc, "/proc/net/packet", 0444),
		"protocols":  newRPCInetInode(ctx, msrc, "/proc/net/protocols", 0444),
		"psched":     newRPCInetInode(ctx, msrc, "/proc/net/psched", 0444),
		"ptype":      newRPCInetInode(ctx, msrc, "/proc/net/ptype", 0444),
		"route":      newRPCInetInode(ctx, msrc, "/proc/net/route", 0444),
		"tcp":        newRPCInetInode(ctx, msrc, "/proc/net/tcp", 0444),
		"tcp6":       newRPCInetInode(ctx, msrc, "/proc/net/tcp6", 0444),
		"udp":        newRPCInetInode(ctx, msrc, "/proc/net/udp", 0444),
		"udp6":       newRPCInetInode(ctx, msrc, "/proc/net/udp6", 0444),
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetProcSysNet will build an inode for /proc/sys/net.
func newRPCInetProcSysNet(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	contents := map[string]*fs.Inode{
		"ipv4": newRPCInetSysNetIPv4Dir(ctx, msrc),
		"core": newRPCInetSysNetCore(ctx, msrc),
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetSysNetCore builds the /proc/sys/net/core directory.
func newRPCInetSysNetCore(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	contents := map[string]*fs.Inode{
		"default_qdisc": newRPCInetInode(ctx, msrc, "/proc/sys/net/core/default_qdisc", 0444),
		"message_burst": newRPCInetInode(ctx, msrc, "/proc/sys/net/core/message_burst", 0444),
		"message_cost":  newRPCInetInode(ctx, msrc, "/proc/sys/net/core/message_cost", 0444),
		"optmem_max":    newRPCInetInode(ctx, msrc, "/proc/sys/net/core/optmem_max", 0444),
		"rmem_default":  newRPCInetInode(ctx, msrc, "/proc/sys/net/core/rmem_default", 0444),
		"rmem_max":      newRPCInetInode(ctx, msrc, "/proc/sys/net/core/rmem_max", 0444),
		"somaxconn":     newRPCInetInode(ctx, msrc, "/proc/sys/net/core/somaxconn", 0444),
		"wmem_default":  newRPCInetInode(ctx, msrc, "/proc/sys/net/core/wmem_default", 0444),
		"wmem_max":      newRPCInetInode(ctx, msrc, "/proc/sys/net/core/wmem_max", 0444),
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetSysNetIPv4Dir builds the /proc/sys/net/ipv4 directory.
func newRPCInetSysNetIPv4Dir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	contents := map[string]*fs.Inode{
		"ip_local_port_range":              newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/ip_local_port_range", 0444),
		"ip_local_reserved_ports":          newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/ip_local_reserved_ports", 0444),
		"ipfrag_time":                      newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/ipfrag_time", 0444),
		"ip_nonlocal_bind":                 newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/ip_nonlocal_bind", 0444),
		"ip_no_pmtu_disc":                  newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/ip_no_pmtu_disc", 0444),
		"tcp_allowed_congestion_control":   newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_allowed_congestion_control", 0444),
		"tcp_available_congestion_control": newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_available_congestion_control", 0444),
		"tcp_base_mss":                     newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_base_mss", 0444),
		"tcp_congestion_control":           newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_congestion_control", 0644),
		"tcp_dsack":                        newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_dsack", 0644),
		"tcp_early_retrans":                newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_early_retrans", 0644),
		"tcp_fack":                         newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_fack", 0644),
		"tcp_fastopen":                     newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_fastopen", 0644),
		"tcp_fastopen_key":                 newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_fastopen_key", 0444),
		"tcp_fin_timeout":                  newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_fin_timeout", 0644),
		"tcp_invalid_ratelimit":            newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_invalid_ratelimit", 0444),
		"tcp_keepalive_intvl":              newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_intvl", 0644),
		"tcp_keepalive_probes":             newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_probes", 0644),
		"tcp_keepalive_time":               newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_time", 0644),
		"tcp_mem":                          newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_mem", 0444),
		"tcp_mtu_probing":                  newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_mtu_probing", 0644),
		"tcp_no_metrics_save":              newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_no_metrics_save", 0444),
		"tcp_probe_interval":               newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_probe_interval", 0444),
		"tcp_probe_threshold":              newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_probe_threshold", 0444),
		"tcp_retries1":                     newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_retries1", 0644),
		"tcp_retries2":                     newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_retries2", 0644),
		"tcp_rfc1337":                      newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_rfc1337", 0444),
		"tcp_rmem":                         newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_rmem", 0444),
		"tcp_sack":                         newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_sack", 0644),
		"tcp_slow_start_after_idle":        newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_slow_start_after_idle", 0644),
		"tcp_synack_retries":               newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_synack_retries", 0644),
		"tcp_syn_retries":                  newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_syn_retries", 0644),
		"tcp_timestamps":                   newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_timestamps", 0644),
		"tcp_wmem":                         newRPCInetInode(ctx, msrc, "/proc/sys/net/ipv4/tcp_wmem", 0444),
	}

	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(d, msrc, fs.SpecialDirectory, nil)
}
