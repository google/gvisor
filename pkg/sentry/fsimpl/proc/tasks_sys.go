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
	"io"
	"math"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/kernel/version"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
			"cap_last_cap":       fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", linux.CAP_LAST_CAP))),
			"hostname":           fs.newInode(ctx, root, 0444, &hostnameData{}),
			"domainname":         fs.newInode(ctx, root, 0444, &domainnameData{}),
			"overflowgid":        fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", auth.OverflowGID))),
			"overflowuid":        fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", auth.OverflowUID))),
			"pid_max":            fs.newInode(ctx, root, 0644, newStaticFile(fmt.Sprintf("%d\n", kernel.TasksLimit))),
			"randomize_va_space": fs.newInode(ctx, root, 0644, newStaticFile("2\n")),
			"random": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"boot_id": fs.newInode(ctx, root, 0444, newStaticFile(randUUID())),
				"uuid":    fs.newInode(ctx, root, 0444, &uuidData{}),
			}),
			"sem":    fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\t%d\t%d\t%d\n", linux.SEMMSL, linux.SEMMNS, linux.SEMOPM, linux.SEMMNI))),
			"shmall": fs.newInode(ctx, root, 0444, ipcData(linux.SHMALL)),
			"shmmax": fs.newInode(ctx, root, 0444, ipcData(linux.SHMMAX)),
			"shmmni": fs.newInode(ctx, root, 0444, ipcData(linux.SHMMNI)),
			"msgmni": fs.newInode(ctx, root, 0444, ipcData(linux.MSGMNI)),
			"msgmax": fs.newInode(ctx, root, 0444, ipcData(linux.MSGMAX)),
			"msgmnb": fs.newInode(ctx, root, 0444, ipcData(linux.MSGMNB)),
			"yama": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"ptrace_scope": fs.newYAMAPtraceScopeFile(ctx, k, root),
			}),
			"keys": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"maxkeys": fs.newMaxKeySizeFile(ctx, k, root),
			}),
			"osrelease": fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxRelease())),
			"ostype":    fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxSysname)),
			"version":   fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxVersion)),
		}),
		"fs": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"file-max":      fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", int64(math.MaxInt64)))),
			"file-nr":       fs.newInode(ctx, root, 0444, &fileNrData{vfs: k.VFS()}),
			"mount-max":     fs.newInode(ctx, root, 0644, &atomicInt32File{val: &k.VFS().MountMax, min: 1, max: math.MaxInt32}),
			"nr_open":       fs.newInode(ctx, root, 0644, &atomicInt32File{val: &k.MaxFDLimit, min: 8, max: kernel.MaxFdLimit}),
			"pipe-max-size": fs.newInode(ctx, root, 0644, newStaticFile(fmt.Sprintf("%d\n", pipe.MaximumPipeSize))),
		}),
		"vm": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"max_map_count":     fs.newInode(ctx, root, 0444, newStaticFile("2147483647\n")),
			"mmap_min_addr":     fs.newInode(ctx, root, 0444, &mmapMinAddrData{k: k}),
			"overcommit_memory": fs.newInode(ctx, root, 0444, newStaticFile("0\n")),
		}),
		"net": fs.newSysNetDir(ctx, root, k),
		"user": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"max_user_namespaces": fs.newInode(ctx, root, 0644, &maxUserNamespacesData{}),
		}),
	})
}

// newSysNetDir returns the dentry corresponding to /proc/sys/net directory.
func (fs *filesystem) newSysNetDir(ctx context.Context, root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	var contents map[string]kernfs.Inode

	// TODO(gvisor.dev/issue/1833): Support for using the network stack in the
	// network namespace of the calling process, as netnsSysctlFile does.
	if stack := k.RootNetworkNamespace().Stack(); stack != nil {
		contents = map[string]kernfs.Inode{
			"ipv4": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"ip_forward":                 fs.newInode(ctx, root, 0644, &ipForwarding{stack: stack, protocol: ipv4.ProtocolNumber}),
				"ip_local_port_range":        fs.newInode(ctx, root, 0644, &portRange{stack: stack}),
				"ip_unprivileged_port_start": fs.newInode(ctx, root, 0644, &netnsSysctlFile{sysctl: unprivilegedPortStartSysctl}),
				"ping_group_range":           fs.newInode(ctx, root, 0644, &netnsSysctlFile{sysctl: pingGroupRangeSysctl}),
				"tcp_recovery":               fs.newInode(ctx, root, 0644, &tcpRecoveryData{stack: stack}),
				"tcp_rmem":                   fs.newInode(ctx, root, 0644, &tcpMemData{stack: stack, dir: tcpRMem}),
				"tcp_sack":                   fs.newInode(ctx, root, 0644, &tcpSackData{stack: stack}),
				"tcp_wmem":                   fs.newInode(ctx, root, 0644, &tcpMemData{stack: stack, dir: tcpWMem}),

				// conf/{all,default}/route_localnet toggles acceptance of martian
				// loopback packets on non-loopback NICs (kube-proxy enables this). It
				// is backed by the IPv4 protocol's AllowExternalLoopbackTraffic option.
				"conf": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
					"all": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
						"route_localnet": fs.newInode(ctx, root, 0644, &routeLocalnetData{stack: stack}),
					}),
					"default": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
						"route_localnet": fs.newInode(ctx, root, 0644, &routeLocalnetData{stack: stack}),
					}),
				}),

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
				"somaxconn":     fs.newInode(ctx, root, 0444, newStaticFile("1024")),
				"wmem_default":  fs.newInode(ctx, root, 0444, newStaticFile("212992")),
				"wmem_max":      fs.newInode(ctx, root, 0444, newStaticFile("212992")),
			}),
			"ipv6": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
				"bindv6only":       fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"ip6frag_time":     fs.newInode(ctx, root, 0444, newStaticFile("60")),
				"ip_nonlocal_bind": fs.newInode(ctx, root, 0444, newStaticFile("0")),
				"auto_flowlabels":  fs.newInode(ctx, root, 0444, newStaticFile("1")),
				"conf": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
					"all": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
						"forwarding": fs.newInode(ctx, root, 0644, &ipForwarding{stack: stack, protocol: ipv6.ProtocolNumber}),
					}),
					// Stub for conf/default/forwarding; doesn't affect behavior.
					"default": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
						"forwarding": fs.newInode(ctx, root, 0644, &atomicInt32File{val: new(atomicbitops.Int32), min: 0, max: 1}),
					}),
				}),
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
	defer utsns.DecRef(ctx)
	buf.WriteString(utsns.HostName())
	buf.WriteString("\n")
	return nil
}

// GetDynamicBytesPoller implements vfs.PollableDynamicBytesSource.GetDynamicBytesPoller.
func (*hostnameData) GetDynamicBytesPoller(ctx context.Context) *vfs.DynamicBytesPoller {
	return &kernel.KernelFromContext(ctx).HostNamePoller
}

// domainnameData implements vfs.DynamicBytesSource for /proc/sys/kernel/domainname.
//
// +stateify savable
type domainnameData struct {
	kernfs.DynamicBytesFile
}

var _ dynamicInode = (*domainnameData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*domainnameData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	utsns := kernel.UTSNamespaceFromContext(ctx)
	defer utsns.DecRef(ctx)
	buf.WriteString(utsns.DomainName())
	buf.WriteString("\n")
	return nil
}

// uuidData implements vfs.DynamicBytesSource for /proc/sys/kernel/random/uuid.
//
// +stateify savable
type uuidData struct {
	kernfs.DynamicBytesFile
}

var _ dynamicInode = (*uuidData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*uuidData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString(randUUID())
	return nil
}

// GetDynamicBytesPoller implements vfs.PollableDynamicBytesSource.GetDynamicBytesPoller.
func (*domainnameData) GetDynamicBytesPoller(ctx context.Context) *vfs.DynamicBytesPoller {
	return &kernel.KernelFromContext(ctx).DomainNamePoller
}

// maxUserNamespacesData implements vfs.WritableDynamicBytesSource for
// /proc/sys/user/max_user_namespaces.
//
// +stateify savable
type maxUserNamespacesData struct {
	kernfs.DynamicBytesFile
}

var _ vfs.WritableDynamicBytesSource = (*maxUserNamespacesData)(nil)

// CheckPermissions implements kernfs.Inode.CheckPermissions.
//
// In Linux, this file's access can be granted via CAP_SYS_RESOURCE
// in the caller's user namespace, and read-only access otherwise.
func (*maxUserNamespacesData) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	if (ats.MayWrite() && !creds.HasSelfCapability(linux.CAP_SYS_RESOURCE)) || ats.MayExec() {
		return linuxerr.EACCES
	}
	return nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (*maxUserNamespacesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	userns := auth.CredentialsFromContext(ctx).UserNamespace
	_, err := fmt.Fprintf(buf, "%d\n", userns.MaxUserNamespaces())
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (*maxUserNamespacesData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// Ignore partial writes.
		return 0, linuxerr.EINVAL
	}
	var buf [1]int32
	n, err := ParseInt32Vec(ctx, src, buf[:])
	if err != nil || n == 0 {
		return 0, err
	}
	// The limit is a non-negative count.
	if buf[0] < 0 {
		return 0, linuxerr.EINVAL
	}
	auth.CredentialsFromContext(ctx).UserNamespace.SetMaxUserNamespaces(buf[0])
	return n, nil
}

// tcpSackData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/tcp_sack.
//
// +stateify savable
type tcpSackData struct {
	kernfs.DynamicBytesFile

	stack inet.Stack `state:"wait"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpSackData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tcpSackData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	enabled, err := d.stack.TCPSACKEnabled()
	if err != nil {
		return err
	}

	val := "0\n"
	if enabled {
		// Technically, this is not quite compatible with Linux. Linux stores these
		// as an integer, so if you write "2" into tcp_sack, you should get 2 back.
		// Tough luck.
		val = "1\n"
	}
	_, err = buf.WriteString(val)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpSackData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	return n, d.stack.SetTCPSACKEnabled(buf[0] != 0)
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

	_, err = fmt.Fprintf(buf, "%d\n", recovery)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tcpRecoveryData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	if err := d.stack.SetTCPRecovery(inet.TCPLossRecovery(buf[0])); err != nil {
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

	// mu serializes reads and read-modify-write updates through this byte source.
	mu sync.Mutex `state:"nosave"`
}

var _ vfs.WritableDynamicBytesSource = (*tcpMemData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
//
// +checklocksexclude:d.mu
func (d *tcpMemData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	size, err := d.readSizeLocked()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(buf, "%d\t%d\t%d\n", size.Min, size.Default, size.Max)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// +checklocksexclude:d.mu
func (d *tcpMemData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	size, err := d.readSizeLocked()
	if err != nil {
		return 0, err
	}
	buf := []int32{int32(size.Min), int32(size.Default), int32(size.Max)}
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
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

// readSizeLocked returns the stack's configured TCP buffer sizes.
//
// +checklocks:d.mu
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

// writeSizeLocked updates the stack's configured TCP buffer sizes.
//
// +checklocks:d.mu
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
// /proc/sys/net/ipv4/ip_forward and /proc/sys/net/ipv6/conf/all/forwarding.
//
// +stateify savable
type ipForwarding struct {
	kernfs.DynamicBytesFile

	stack    inet.Stack `state:"wait"`
	mu       sync.Mutex `state:"nosave"`
	protocol tcpip.NetworkProtocolNumber

	// enabled is the last value successfully written here, which may differ
	// from the forwarding state of individual interfaces.
	//
	// +checklocks:mu
	enabled bool
}

var _ vfs.WritableDynamicBytesSource = (*ipForwarding)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
//
// +checklocksexclude:ipf.mu
func (ipf *ipForwarding) Generate(ctx context.Context, buf *bytes.Buffer) error {
	ipf.mu.Lock()
	enabled := ipf.enabled
	ipf.mu.Unlock()

	val := "0\n"
	if enabled {
		// Linux preserves the written integer; this file reports a boolean,
		// so a nonzero value such as "2" is read back as "1".
		val = "1\n"
	}
	_, err := buf.WriteString(val)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// +checklocksexclude:ipf.mu
func (ipf *ipForwarding) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	enabled := buf[0] != 0
	ipf.mu.Lock()
	defer ipf.mu.Unlock()
	if err := ipf.stack.SetForwarding(ipf.protocol, enabled); err != nil {
		return 0, err
	}
	ipf.enabled = enabled
	return n, nil
}

// routeLocalnetData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/conf/{all,default}/route_localnet. Enabling it accepts
// martian loopback packets (IPv4 AllowExternalLoopbackTraffic), matching
// Linux's net.ipv4.conf.*.route_localnet.
//
// +stateify savable
type routeLocalnetData struct {
	kernfs.DynamicBytesFile

	stack inet.Stack `state:"wait"`
}

var _ vfs.WritableDynamicBytesSource = (*routeLocalnetData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (rl *routeLocalnetData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	enabled, err := rl.stack.GetAllowExternalLoopbackTraffic(ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	val := "0\n"
	if enabled {
		val = "1\n"
	}
	buf.WriteString(val)
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (rl *routeLocalnetData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	if err := rl.stack.SetAllowExternalLoopbackTraffic(ipv4.ProtocolNumber, buf[0] != 0); err != nil {
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
}

var _ vfs.WritableDynamicBytesSource = (*portRange)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (pr *portRange) Generate(ctx context.Context, buf *bytes.Buffer) error {
	start, end := pr.stack.PortRange()
	_, err := fmt.Fprintf(buf, "%d %d\n", start, end)
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (pr *portRange) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}

	ports := make([]int32, 2)
	n, err := ParseInt32Vec(ctx, src, ports)
	if err != nil || n == 0 {
		return 0, err
	}

	// Port numbers must be uint16s.
	if ports[0] < 0 || ports[1] < 0 || ports[0] > math.MaxUint16 || ports[1] > math.MaxUint16 {
		return 0, linuxerr.EINVAL
	}

	if err := pr.stack.SetPortRange(uint16(ports[0]), uint16(ports[1])); err != nil {
		return 0, err
	}
	return n, nil
}

// netnsSysctl identifies a netnsSysctlFile.
type netnsSysctl int

const (
	unprivilegedPortStartSysctl netnsSysctl = iota
	pingGroupRangeSysctl
)

// netnsSysctlFile is a /proc/sys/net file that applies to the network
// namespace of the task that opens it. Linux resolves /proc/sys/net entries in
// current's network namespace when they are looked up
// (net/sysctl_net.c:net_ctl_header_lookup()), and an open file keeps referring
// to that namespace.
//
// +stateify savable
type netnsSysctlFile struct {
	kernfs.DynamicBytesFile

	sysctl netnsSysctl
}

var _ dynamicInode = (*netnsSysctlFile)(nil)

// Init implements dynamicInode.Init.
func (f *netnsSysctlFile) Init(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, _ vfs.DynamicBytesSource, perm linux.FileMode) {
	f.DynamicBytesFile.Init(ctx, creds, devMajor, devMinor, ino, nil, perm)
	f.SetDataSourceProvider(f)
}

// DataSource implements kernfs.DataSourceProvider.DataSource.
func (f *netnsSysctlFile) DataSource(ctx context.Context) (vfs.DynamicBytesSource, error) {
	var netns *inet.Namespace
	if t := kernel.TaskFromContext(ctx); t != nil {
		netns = t.NetworkNamespace()
	} else {
		netns = kernel.KernelFromContext(ctx).RootNetworkNamespace()
	}
	if netns.Stack() == nil {
		return nil, linuxerr.ENOENT
	}
	switch f.sysctl {
	case unprivilegedPortStartSysctl:
		return &unprivilegedPortStart{netns: netns}, nil
	case pingGroupRangeSysctl:
		return &pingGroupRange{netns: netns}, nil
	default:
		panic(fmt.Sprintf("unknown sysctl: %d", f.sysctl))
	}
}

var _ kernfs.DataSourceProvider = (*netnsSysctlFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (*netnsSysctlFile) Generate(context.Context, *bytes.Buffer) error {
	panic("unreachable")
}

// unprivilegedPortStart implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/ip_unprivileged_port_start. It holds the namespace rather
// than its stack because a restore gives child namespaces new stacks.
//
// +stateify savable
type unprivilegedPortStart struct {
	netns *inet.Namespace
}

var _ vfs.WritableDynamicBytesSource = (*unprivilegedPortStart)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (u *unprivilegedPortStart) Generate(ctx context.Context, buf *bytes.Buffer) error {
	_, err := fmt.Fprintf(buf, "%d\n", u.netns.Stack().UnprivilegedPortStart())
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (u *unprivilegedPortStart) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	return writeUnprivilegedPortStart(ctx, u.netns.Stack(), src)
}

// writeUnprivilegedPortStart writes src to net.ipv4.ip_unprivileged_port_start
// of stack, as Linux's net/ipv4/sysctl_net_ipv4.c:ipv4_privileged_ports()
// does.
func writeUnprivilegedPortStart(ctx context.Context, stack inet.Stack, src usermem.IOSequence) (int64, error) {
	buf := []int32{int32(stack.UnprivilegedPortStart())}
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	if buf[0] < 0 || buf[0] > math.MaxUint16 {
		return 0, linuxerr.EINVAL
	}
	if err := stack.SetUnprivilegedPortStart(uint16(buf[0])); err != nil {
		return 0, err
	}
	return n, nil
}

// pingGroupRange implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/ping_group_range. It holds the namespace for the same
// reason as unprivilegedPortStart.
//
// +stateify savable
type pingGroupRange struct {
	netns *inet.Namespace
}

var _ vfs.WritableDynamicBytesSource = (*pingGroupRange)(nil)

// gidTMax is Linux's GID_T_MAX, the largest valid gid_t.
const gidTMax = math.MaxUint32 - 1

// Generate implements vfs.DynamicBytesSource.Generate.
func (p *pingGroupRange) Generate(ctx context.Context, buf *bytes.Buffer) error {
	userns := auth.CredentialsFromContext(ctx).UserNamespace
	low, high := p.netns.Stack().PingGroupRange()
	_, err := fmt.Fprintf(buf, "%d\t%d\n", userns.MapFromKGID(low).OrOverflow(), userns.MapFromKGID(high).OrOverflow())
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (p *pingGroupRange) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	return writePingGroupRange(ctx, p.netns.Stack(), auth.CredentialsFromContext(ctx).UserNamespace, src)
}

// writePingGroupRange writes src to net.ipv4.ping_group_range of stack, with
// GIDs in userns, as Linux's net/ipv4/sysctl_net_ipv4.c:ipv4_ping_group_range()
// does.
func writePingGroupRange(ctx context.Context, stack inet.Stack, userns *auth.UserNamespace, src usermem.IOSequence) (int64, error) {
	low, high := stack.PingGroupRange()
	// A write of one value leaves the high end unchanged.
	urange := []uint64{
		uint64(userns.MapFromKGID(low).OrOverflow()),
		uint64(userns.MapFromKGID(high).OrOverflow()),
	}
	n, err := parseUint64Vec(ctx, src, urange)
	if err != nil || n == 0 {
		return 0, err
	}
	if urange[0] > gidTMax || urange[1] > gidTMax {
		return 0, linuxerr.EINVAL
	}
	low = userns.MapToKGID(auth.GID(urange[0]))
	high = userns.MapToKGID(auth.GID(urange[1]))
	if !low.Ok() || !high.Ok() {
		return 0, linuxerr.EINVAL
	}
	if urange[1] < urange[0] || high < low {
		// Linux stores an empty range as "1 0" in the root user namespace.
		low, high = 1, 0
	}
	if err := stack.SetPingGroupRange(low, high); err != nil {
		return 0, err
	}
	return n, nil
}

// SetNetIPv4Sysctl writes val to /proc/sys/net/ipv4/<name> of stack, with
// GIDs in userns. Only ip_unprivileged_port_start and ping_group_range are
// supported.
func SetNetIPv4Sysctl(ctx context.Context, stack inet.Stack, userns *auth.UserNamespace, name, val string) error {
	src := usermem.BytesIOSequence([]byte(val))
	var err error
	switch name {
	case "ip_unprivileged_port_start":
		_, err = writeUnprivilegedPortStart(ctx, stack, src)
	case "ping_group_range":
		_, err = writePingGroupRange(ctx, stack, userns, src)
	default:
		return fmt.Errorf("unsupported sysctl net.ipv4.%s", name)
	}
	return err
}

// parseUint64Vec is ParseInt32Vec for unsigned values up to math.MaxUint64,
// as Linux's kernel/sysctl.c:proc_doulongvec_minmax() parses them.
func parseUint64Vec(ctx context.Context, src usermem.IOSequence, dsts []uint64) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	src = src.TakeFirst(int(hostarch.PageSize) - 1)
	buf := make([]byte, src.NumBytes())
	n, cperr := src.CopyIn(ctx, buf)
	buf = buf[:n]

	isSpace := func(b byte) bool { return b == ' ' || (b >= '\t' && b <= '\r') }
	var i, j int
	for ; j < len(dsts); j++ {
		for i < len(buf) && isSpace(buf[i]) {
			i++
		}
		if i == len(buf) {
			break
		}
		end := i + 1
		for end < len(buf) && !isSpace(buf[end]) {
			end++
		}
		v, err := strconv.ParseUint(string(buf[i:end]), 10, 64)
		if err != nil {
			return int64(i), linuxerr.EINVAL
		}
		dsts[j] = v
		i = end
	}
	for i < len(buf) && isSpace(buf[i]) {
		i++
	}
	if cperr != nil {
		return int64(i), cperr
	}
	if j == 0 {
		return int64(i), linuxerr.EINVAL
	}
	return int64(i), nil
}

// atomicInt32File implements vfs.WritableDynamicBytesSource sysctls
// represented by int32 atomic objects.
//
// +stateify savable
type atomicInt32File struct {
	kernfs.DynamicBytesFile

	val      *atomicbitops.Int32
	min, max int32
}

var _ vfs.WritableDynamicBytesSource = (*atomicInt32File)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *atomicInt32File) Generate(ctx context.Context, buf *bytes.Buffer) error {
	_, err := fmt.Fprintf(buf, "%d\n", f.val.Load())
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *atomicInt32File) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// Ignore partial writes.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}

	if buf[0] < f.min || buf[0] > f.max {
		return 0, linuxerr.EINVAL
	}

	f.val.Store(buf[0])
	return n, nil
}

// fileNrData implements /proc/sys/fs/file-nr.
//
// +stateify savable
type fileNrData struct {
	kernfs.DynamicBytesFile

	vfs *vfs.VirtualFilesystem
}

var _ dynamicInode = (*fileNrData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate. Like Linux's
// proc_nr_files, the fields are the allocated file count, the unused file
// count (always 0), and the maximum number of files.
func (f *fileNrData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	_, err := fmt.Fprintf(buf, "%d\t0\t%d\n", f.vfs.NumFiles(), int64(math.MaxInt64))
	return err
}

// randUUID returns a string containing a randomly-generated UUID followed by a
// newline.
func randUUID() string {
	var uuid [16]byte
	if _, err := io.ReadFull(rand.Reader, uuid[:]); err != nil {
		panic(fmt.Sprintf("failed to read random bytes for UUID: %v", err))
	}
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // RFC 4122 UUID
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4 (random)
	return fmt.Sprintf("%x-%x-%x-%x-%x\n", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

// ParseInt32Vec interprets src as string encoding slice of int32, and
// returns the parsed value and the number of bytes read.
//
// The numbers of int32 will be populated even if an error is returned eventually.
func ParseInt32Vec(ctx context.Context, src usermem.IOSequence, buf []int32) (int64, error) {
	if src.NumBytes() == 0 {
		return 0, nil
	}
	// Limit input size so as not to impact performance if input size is large.
	src = src.TakeFirst(int(hostarch.PageSize) - 1)

	return usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, buf, src.Opts)
}
