// Copyright 2019 The gVisor Authors.
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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type tcpMemDir int

const (
	tcpRMem tcpMemDir = iota
	tcpWMem
)

// newSysDir returns the dentry corresponding to /proc/sys directory.
func (fs *filesystem) newSysDir(ctx context.Context, root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	return fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
		"kernel": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"hostname": fs.newInode(ctx, root, 0444, &hostnameData{}),
			"sem":      fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\t%d\t%d\t%d\n", linux.SEMMSL, linux.SEMMNS, linux.SEMOPM, linux.SEMMNI))),
			"shmall":   fs.newInode(ctx, root, 0444, shmData(linux.SHMALL)),
			"shmmax":   fs.newInode(ctx, root, 0444, shmData(linux.SHMMAX)),
			"shmmni":   fs.newInode(ctx, root, 0444, shmData(linux.SHMMNI)),
			"yama": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"ptrace_scope": fs.newYAMAPtraceScopeFile(ctx, k, root),
			}),
		}),
		"vm": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"max_map_count":     fs.newInode(ctx, root, 0444, newStaticFile("2147483647\n")),
			"mmap_min_addr":     fs.newInode(ctx, root, 0444, &mmapMinAddrData{k: k}),
			"overcommit_memory": fs.newInode(ctx, root, 0444, newStaticFile("0\n")),
		}),
		"net": fs.newSysNetDir(ctx, root, k),
	})
}

// newSysNetDir returns the dentry corresponding to /proc/sys/net directory.
func (fs *filesystem) newSysNetDir(ctx context.Context, root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	var contents map[string]kernfs.Inode

	// TODO(gvisor.dev/issue/1833): Support for using the network stack in the
	// network namespace of the calling process.
	if stack := k.RootNetworkNamespace().Stack(); stack != nil {
		contents = map[string]kernfs.Inode{
			"ipv4": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"ip_forward":          fs.newInode(ctx, root, 0444, &ipForwarding{stack: stack}),
				"ip_local_port_range": fs.newInode(ctx, root, 0644, &portRange{stack: stack}),
				"tcp_recovery":        fs.newInode(ctx, root, 0644, &tcpRecoveryData{stack: stack}),
				"tcp_rmem":            fs.newInode(ctx, root, 0644, &tcpMemData{stack: stack, dir: tcpRMem}),
				"tcp_sack":            fs.newInode(ctx, root, 0644, &tcpSackData{stack: stack}),
				"tcp_wmem":            fs.newInode(ctx, root, 0644, &tcpMemData{stack: stack, dir: tcpWMem}),

				// The following files are simple stubs until they are implemented in
				// netstack, most of these files are configuration related. We use the
				// value closest to the actual netstack behavior or any empty file, all
				// of these files will have mode 0444 (read-only for all users).
				"ip_local_reserved_ports": fs.newInode(ctx, root, 0444, newStaticFile("")),
				"ipfrag_time":             fs.newInode(ctx, root, 0444, newStaticFile("30")),
				"ip_nonlocal_bind":        fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"ip_no_pmtu_disc":         fs.newInode(ctx, root, 0444, newStaticFile("1")),

				// tcp_allowed_congestion_control tell the user what they are able to
				// do as an unprivledged process so we leave it empty.
				"tcp_allowed_congestion_control":   fs.newInode(ctx, root, 0444, newStaticFile("")),
				"tcp_available_congestion_control": fs.newInode(ctx, root, 0444, newStaticFile("reno")),
				"tcp_congestion_control":           fs.newInode(ctx, root, 0444, newStaticFile("reno")),

				// Many of the following stub files are features netstack doesn't
				// support. The unsupported features return "0" to indicate they are
				// disabled.
				"tcp_base_mss":              fs.newInode(ctx, root, 0444, newStaticFile("1280")),
				"tcp_dsack":                 fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_early_retrans":         fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_fack":                  fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_fastopen":              fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_fastopen_key":          fs.newInode(ctx, root, 0444, newStaticFile("")),
				"tcp_invalid_ratelimit":     fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_keepalive_intvl":       fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_keepalive_probes":      fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_keepalive_time":        fs.newInode(ctx, root, 0444, newStaticFile("7200")),
				"tcp_mtu_probing":           fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_no_metrics_save":       fs.newInode(ctx, root, 0444, newStaticFile("1")),
				"tcp_probe_interval":        fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_probe_threshold":       fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"tcp_retries1":              fs.newInode(ctx, root, 0444, newStaticFile("3")),
				"tcp_retries2":              fs.newInode(ctx, root, 0444, newStaticFile("15")),
				"tcp_rfc1337":               fs.newInode(ctx, root, 0444, newStaticFile("1")),
				"tcp_slow_start_after_idle": fs.newInode(ctx, root, 0444, newStaticFile("1")),
				"tcp_synack_retries":        fs.newInode(ctx, root, 0444, newStaticFile("5")),
				"tcp_syn_retries":           fs.newInode(ctx, root, 0444, newStaticFile("3")),
				"tcp_timestamps":            fs.newInode(ctx, root, 0444, newStaticFile("1")),
			}),
			"core": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"default_qdisc": fs.newInode(ctx, root, 0444, newStaticFile("pfifo_fast")),
				"message_burst": fs.newInode(ctx, root, 0444, newStaticFile("10")),
				"message_cost":  fs.newInode(ctx, root, 0444, newStaticFile("5")),
				"optmem_max":    fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"rmem_default":  fs.newInode(ctx, root, 0444, newStaticFile("212992")),
				"rmem_max":      fs.newInode(ctx, root, 0444, newStaticFile("212992")),
				"somaxconn":     fs.newInode(ctx, root, 0444, newStaticFile("128")),
				"wmem_default":  fs.newInode(ctx, root, 0444, newStaticFile("212992")),
				"wmem_max":      fs.newInode(ctx, root, 0444, newStaticFile("212992")),
			}),
		}
	}

	return fs.newStaticDir(ctx, root, contents)
}

// mmapMinAddrData implements vfs.DynamicBytesSource for
// /proc/sys/vm/mmap_min_addr.
//
// +stateify savable
type mmapMinAddrData struct {
	kernfs.DynamicBytesFile

	k *kernel.Kernel
}

var _ dynamicInode = (*mmapMinAddrData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *mmapMinAddrData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", d.k.Platform.MinUserAddress())
	return nil
}

// hostnameData implements vfs.DynamicBytesSource for /proc/sys/kernel/hostname.
//
// +stateify savable
type hostnameData struct {
	kernfs.DynamicBytesFile
}

var _ dynamicInode = (*hostnameData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*hostnameData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	buf.WriteString(utsns.HostName())
	buf.WriteString("\n")
	return nil
}

// tcpSackData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/tcp_sack.
//
// +stateify savable
type tcpSackData struct {
	kernfs.DynamicBytesFile

	stack   inet.Stack `state:"wait"`
	enabled *bool
}

var _ vfs.WritableDynamicBytesSource = (*tcpSackData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpSackData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if d.enabled == nil {
		sack, err := d.stack.TCPSACKEnabled()
		if err != nil {
			return err
		}
		d.enabled = &sack
	}

	val := "0\n"
	if *d.enabled {
		// Technically, this is not quite compatible with Linux. Linux stores these
		// as an integer, so if you write "2" into tcp_sack, you should get 2 back.
		// Tough luck.
		val = "1\n"
	}
	_, err := buf.WriteString(val)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpSackData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit the amount of memory allocated.
	src = src.TakeFirst(hostarch.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	if d.enabled == nil {
		d.enabled = new(bool)
	}
	*d.enabled = v != 0
	return n, d.stack.SetTCPSACKEnabled(*d.enabled)
}

// tcpRecoveryData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/tcp_recovery.
//
// +stateify savable
type tcpRecoveryData struct {
	kernfs.DynamicBytesFile

	stack inet.Stack `state:"wait"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpRecoveryData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpRecoveryData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	recovery, err := d.stack.TCPRecovery()
	if err != nil {
		return err
	}

	_, err = buf.WriteString(fmt.Sprintf("%d\n", recovery))
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpRecoveryData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit the amount of memory allocated.
	src = src.TakeFirst(hostarch.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	if err := d.stack.SetTCPRecovery(inet.TCPLossRecovery(v)); err != nil {
		return 0, err
	}
	return n, nil
}

// tcpMemData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/tcp_rmem and /proc/sys/net/ipv4/tcp_wmem.
//
// +stateify savable
type tcpMemData struct {
	kernfs.DynamicBytesFile

	dir   tcpMemDir
	stack inet.Stack `state:"wait"`

	// mu protects against concurrent reads/writes to FDs based on the dentry
	// backing this byte source.
	mu sync.Mutex `state:"nosave"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpMemData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpMemData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	size, err := d.readSizeLocked()
	if err != nil {
		return err
	}
	_, err = buf.WriteString(fmt.Sprintf("%d\t%d\t%d\n", size.Min, size.Default, size.Max))
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpMemData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Limit the amount of memory allocated.
	src = src.TakeFirst(hostarch.PageSize - 1)
	size, err := d.readSizeLocked()
	if err != nil {
		return 0, err
	}
	buf := []int32{int32(size.Min), int32(size.Default), int32(size.Max)}
	n, err := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, buf, src.Opts)
	if err != nil {
		return 0, err
	}
	newSize := inet.TCPBufferSize{
		Min:     int(buf[0]),
		Default: int(buf[1]),
		Max:     int(buf[2]),
	}
	if err := d.writeSizeLocked(newSize); err != nil {
		return 0, err
	}
	return n, nil
}

// Precondition: d.mu must be locked.
func (d *tcpMemData) readSizeLocked() (inet.TCPBufferSize, error) {
	switch d.dir {
	case tcpRMem:
		return d.stack.TCPReceiveBufferSize()
	case tcpWMem:
		return d.stack.TCPSendBufferSize()
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", d.dir))
	}
}

// Precondition: d.mu must be locked.
func (d *tcpMemData) writeSizeLocked(size inet.TCPBufferSize) error {
	switch d.dir {
	case tcpRMem:
		return d.stack.SetTCPReceiveBufferSize(size)
	case tcpWMem:
		return d.stack.SetTCPSendBufferSize(size)
	default:
		panic(fmt.Sprintf("unknown tcpMemFile type: %v", d.dir))
	}
}

// ipForwarding implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/ip_forward.
//
// +stateify savable
type ipForwarding struct {
	kernfs.DynamicBytesFile

	stack   inet.Stack `state:"wait"`
	enabled bool
}

var _ vfs.WritableDynamicBytesSource = (*ipForwarding)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (ipf *ipForwarding) Generate(ctx context.Context, buf *bytes.Buffer) error {
	val := "0\n"
	if ipf.enabled {
		// Technically, this is not quite compatible with Linux. Linux stores these
		// as an integer, so if you write "2" into tcp_sack, you should get 2 back.
		// Tough luck.
		val = "1\n"
	}
	buf.WriteString(val)

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (ipf *ipForwarding) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit input size so as not to impact performance if input size is large.
	src = src.TakeFirst(hostarch.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return 0, err
	}
	ipf.enabled = v != 0
	if err := ipf.stack.SetForwarding(ipv4.ProtocolNumber, ipf.enabled); err != nil {
		return 0, err
	}
	return n, nil
}

// portRange implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/ip_local_port_range.
//
// +stateify savable
type portRange struct {
	kernfs.DynamicBytesFile

	stack inet.Stack `state:"wait"`

	// start and end store the port range. We must save/restore this here,
	// since a netstack instance is created on restore.
	start *uint16
	end   *uint16
}

var _ vfs.WritableDynamicBytesSource = (*portRange)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (pr *portRange) Generate(ctx context.Context, buf *bytes.Buffer) error {
	if pr.start == nil {
		start, end := pr.stack.PortRange()
		pr.start = &start
		pr.end = &end
	}
	_, err := fmt.Fprintf(buf, "%d %d\n", *pr.start, *pr.end)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (pr *portRange) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit input size so as not to impact performance if input size is
	// large.
	src = src.TakeFirst(hostarch.PageSize - 1)

	ports := make([]int32, 2)
	n, err := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, ports, src.Opts)
	if err != nil {
		return 0, err
	}

	// Port numbers must be uint16s.
	if ports[0] < 0 || ports[1] < 0 || ports[0] > math.MaxUint16 || ports[1] > math.MaxUint16 {
		return 0, linuxerr.EINVAL
	}

	if err := pr.stack.SetPortRange(uint16(ports[0]), uint16(ports[1])); err != nil {
		return 0, err
	}
	if pr.start == nil {
		pr.start = new(uint16)
		pr.end = new(uint16)
	}
	*pr.start = uint16(ports[0])
	*pr.end = uint16(ports[1])
	return n, nil
}
