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
	"io"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// rpcinetFile implments fs.InodeOperations as RPCs.
type rpcinetFile struct {
	ramfs.Entry

	// filepath is the full path of this rpcinetFile.
	filepath string

	k *kernel.Kernel
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
// This method can panic if an rpcinetFile was created without an rpcinet
// stack.
func (r rpcinetFile) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	s, ok := r.k.NetworkStack().(*rpcinet.Stack)
	if !ok {
		panic("Network stack is not a rpcinet.")
	}

	contents, se := s.RPCReadFile(r.filepath)
	if se != nil || offset >= int64(len(contents)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err
}

// Truncate implements fs.InodeOperations.Truncate.
func (r rpcinetFile) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev.
// This method can panic if an rpcinetFile was created without an rpcinet
// stack.
func (r rpcinetFile) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	s, ok := r.k.NetworkStack().(*rpcinet.Stack)
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

	written, se := s.RPCWriteFile(r.filepath, b)
	return int64(written), se.ToError()
}

func newRPCProcFSFile(ctx context.Context, msrc *fs.MountSource, filepath string, mode linux.FileMode) *fs.Inode {
	f := &rpcinetFile{
		filepath: filepath,
		k:        kernel.KernelFromContext(ctx),
	}
	f.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(mode))

	fi := newFile(f, msrc, fs.SpecialFile, nil)
	return fi
}

// newRPCInetProcNet will build an inode for /proc/net.
func newRPCInetProcNet(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))

	// Add all the files we want to forward for /proc/net.
	d.AddChild(ctx, "arp", newRPCProcFSFile(ctx, msrc, "/proc/net/arp", 0444))
	d.AddChild(ctx, "dev", newRPCProcFSFile(ctx, msrc, "/proc/net/dev", 0444))
	d.AddChild(ctx, "if_inet6", newRPCProcFSFile(ctx, msrc, "/proc/net/if_inet6", 0444))
	d.AddChild(ctx, "ipv6_route", newRPCProcFSFile(ctx, msrc, "/proc/net/ipv6_route", 0444))
	d.AddChild(ctx, "netlink", newRPCProcFSFile(ctx, msrc, "/proc/net/netlink", 0444))
	d.AddChild(ctx, "netstat", newRPCProcFSFile(ctx, msrc, "/proc/net/netstat", 0444))
	d.AddChild(ctx, "packet", newRPCProcFSFile(ctx, msrc, "/proc/net/packet", 0444))
	d.AddChild(ctx, "protocols", newRPCProcFSFile(ctx, msrc, "/proc/net/protocols", 0444))
	d.AddChild(ctx, "psched", newRPCProcFSFile(ctx, msrc, "/proc/net/psched", 0444))
	d.AddChild(ctx, "ptype", newRPCProcFSFile(ctx, msrc, "/proc/net/ptype", 0444))
	d.AddChild(ctx, "route", newRPCProcFSFile(ctx, msrc, "/proc/net/route", 0444))
	d.AddChild(ctx, "tcp", newRPCProcFSFile(ctx, msrc, "/proc/net/tcp", 0444))
	d.AddChild(ctx, "tcp6", newRPCProcFSFile(ctx, msrc, "/proc/net/tcp6", 0444))
	d.AddChild(ctx, "udp", newRPCProcFSFile(ctx, msrc, "/proc/net/udp", 0444))
	d.AddChild(ctx, "udp6", newRPCProcFSFile(ctx, msrc, "/proc/net/udp6", 0444))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetProcSysNet will build an inode for /proc/sys/net.
func newRPCInetProcSysNet(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	d.AddChild(ctx, "ipv4", newRPCInetSysNetIPv4Dir(ctx, msrc))
	d.AddChild(ctx, "core", newRPCInetSysNetCore(ctx, msrc))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetSysNetCore builds the /proc/sys/net/core directory.
func newRPCInetSysNetCore(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))

	// Add all the files we want to forward over RPC for /proc/sys/net/core
	d.AddChild(ctx, "default_qdisc", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/default_qdisc", 0444))
	d.AddChild(ctx, "message_burst", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/message_burst", 0444))
	d.AddChild(ctx, "message_cost", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/message_cost", 0444))
	d.AddChild(ctx, "optmem_max", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/optmem_max", 0444))
	d.AddChild(ctx, "rmem_default", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/rmem_default", 0444))
	d.AddChild(ctx, "rmem_max", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/rmem_max", 0444))
	d.AddChild(ctx, "somaxconn", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/somaxconn", 0444))
	d.AddChild(ctx, "wmem_default", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/wmem_default", 0444))
	d.AddChild(ctx, "wmem_max", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/core/wmem_max", 0444))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

// newRPCInetSysNetIPv4Dir builds the /proc/sys/net/ipv4 directory.
func newRPCInetSysNetIPv4Dir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))

	// Add all the files we want to forward over RPC for /proc/sys/net/ipv4.
	d.AddChild(ctx, "ip_local_port_range", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/ip_local_port_range", 0444))
	d.AddChild(ctx, "ip_local_reserved_ports", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/ip_local_reserved_ports", 0444))
	d.AddChild(ctx, "ipfrag_time", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/ipfrag_time", 0444))
	d.AddChild(ctx, "ip_nonlocal_bind", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/ip_nonlocal_bind", 0444))
	d.AddChild(ctx, "ip_no_pmtu_disc", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/ip_no_pmtu_disc", 0444))

	d.AddChild(ctx, "tcp_allowed_congestion_control", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_allowed_congestion_control", 0444))
	d.AddChild(ctx, "tcp_available_congestion_control", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_available_congestion_control", 0444))
	d.AddChild(ctx, "tcp_base_mss", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_base_mss", 0444))
	d.AddChild(ctx, "tcp_congestion_control", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_congestion_control", 0644))
	d.AddChild(ctx, "tcp_dsack", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_dsack", 0644))
	d.AddChild(ctx, "tcp_early_retrans", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_early_retrans", 0644))
	d.AddChild(ctx, "tcp_fack", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_fack", 0644))
	d.AddChild(ctx, "tcp_fastopen", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_fastopen", 0644))
	d.AddChild(ctx, "tcp_fastopen_key", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_fastopen_key", 0444))
	d.AddChild(ctx, "tcp_fin_timeout", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_fin_timeout", 0644))
	d.AddChild(ctx, "tcp_invalid_ratelimit", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_invalid_ratelimit", 0444))
	d.AddChild(ctx, "tcp_keepalive_intvl", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_intvl", 0644))
	d.AddChild(ctx, "tcp_keepalive_probes", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_probes", 0644))
	d.AddChild(ctx, "tcp_keepalive_time", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_keepalive_time", 0644))
	d.AddChild(ctx, "tcp_mem", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_mem", 0444))
	d.AddChild(ctx, "tcp_mtu_probing", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_mtu_probing", 0644))
	d.AddChild(ctx, "tcp_no_metrics_save", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_no_metrics_save", 0444))
	d.AddChild(ctx, "tcp_probe_interval", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_probe_interval", 0444))
	d.AddChild(ctx, "tcp_probe_threshold", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_probe_threshold", 0444))
	d.AddChild(ctx, "tcp_retries1", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_retries1", 0644))
	d.AddChild(ctx, "tcp_retries2", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_retries2", 0644))
	d.AddChild(ctx, "tcp_rfc1337", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_rfc1337", 0444))
	d.AddChild(ctx, "tcp_rmem", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_rmem", 0444))
	d.AddChild(ctx, "tcp_sack", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_sack", 0644))
	d.AddChild(ctx, "tcp_slow_start_after_idle", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_slow_start_after_idle", 0644))
	d.AddChild(ctx, "tcp_synack_retries", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_synack_retries", 0644))
	d.AddChild(ctx, "tcp_syn_retries", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_syn_retries", 0644))
	d.AddChild(ctx, "tcp_timestamps", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_timestamps", 0644))
	d.AddChild(ctx, "tcp_wmem", newRPCProcFSFile(ctx, msrc, "/proc/sys/net/ipv4/tcp_wmem", 0444))

	return newFile(d, msrc, fs.SpecialDirectory, nil)
}
