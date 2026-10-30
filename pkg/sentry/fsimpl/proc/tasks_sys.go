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

// lazySysDir is a /proc/sys directory whose children are created on first
// use.
//
// Each procfs instance can have many /proc/sys inodes, and most workloads only
// access a few of them. Creating them lazily keeps unused ones out of memory
// and out of checkpoints: directories that were never populated are saved
// empty, and are populated after restore if needed.
//
// It is only used for directories that have children, so that
// HasChildren doesn't need to populate it.
//
// +stateify savable
type lazySysDir struct {
	kernfs.StaticDirectory

	fs    *filesystem
	k     *kernel.Kernel
	creds *auth.Credentials

	// path is the path of the directory relative to /proc/sys.
	// It identifies the children to create.
	// See filesystem.sysDirChildren. Immutable.
	path string

	// populateMu serializes populate calls.
	populateMu sync.Mutex `state:"nosave"`

	// populated is true once the children of the directory have been
	// created.
	populated atomicbitops.Bool
}

var _ kernfs.Inode = (*lazySysDir)(nil)

func (fs *filesystem) newLazySysDir(ctx context.Context, creds *auth.Credentials, k *kernel.Kernel, path string) kernfs.Inode {
	d := &lazySysDir{
		fs:    fs,
		k:     k,
		creds: creds,
		path:  path,
	}
	d.StaticDirectory.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), 0555, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndZero,
	})
	d.InitRefs()
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	// Set the link count of the populated directory now, so that Stat does
	// not need to populate d.
	d.IncLinks(uint32(len(sysSubdirs(path))))
	return d
}

// populate creates the children of d if it is not already populated.
func (d *lazySysDir) populate(ctx context.Context) {
	if d.populated.Load() {
		return
	}
	d.populateMu.Lock()
	defer d.populateMu.Unlock()
	if d.populated.Load() {
		return
	}
	// sysDirChildren creates subdirectories only from sysSubdirs, so the
	// link count set by newLazySysDir is correct unless sysDirFiles returns
	// a directory.
	if links, want := d.OrderedChildren.Populate(d.fs.sysDirChildren(ctx, d.creds, d.k, d.path)), uint32(len(sysSubdirs(d.path))); links != want {
		panic(fmt.Sprintf("/proc/sys/%s populated %d subdirectories, want %d", d.path, links, want))
	}
	d.populated.Store(true)
}

// Lookup implements kernfs.Inode.Lookup.
func (d *lazySysDir) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	d.populate(ctx)
	return d.StaticDirectory.Lookup(ctx, name)
}

// Open implements kernfs.Inode.Open.
func (d *lazySysDir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Populate before GenericDirectoryFD reads d.OrderedChildren.
	d.populate(ctx)
	return d.StaticDirectory.Open(ctx, rp, kd, opts)
}

// HasChildren implements kernfs.Inode.HasChildren.
func (d *lazySysDir) HasChildren() bool {
	// Every lazySysDir has children once populated.
	return !d.populated.Load() || d.StaticDirectory.HasChildren()
}

// newSysDir returns the inode for the /proc/sys directory.
func (fs *filesystem) newSysDir(ctx context.Context, root *auth.Credentials, k *kernel.Kernel) kernfs.Inode {
	return fs.newLazySysDir(ctx, root, k, "")
}

// sysSubdirs returns the names of the subdirectories of the /proc/sys
// directory at path, which is relative to /proc/sys. All of these
// subdirectories are lazySysDirs.
//
// The returned slice must not be modified.
func sysSubdirs(path string) []string {
	switch path {
	case "":
		return []string{"kernel", "fs", "vm", "user", "net"}
	case "kernel":
		return []string{"random", "yama", "keys"}
	case "net":
		return []string{"ipv4", "core", "ipv6"}
	case "net/ipv4", "net/ipv6":
		return []string{"conf"}
	case "net/ipv4/conf", "net/ipv6/conf":
		return []string{"all", "default"}
	default:
		return nil
	}
}

// sysDirChildren returns the children of the /proc/sys directory at path,
// which is relative to /proc/sys.
func (fs *filesystem) sysDirChildren(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, path string) map[string]kernfs.Inode {
	// TODO(gvisor.dev/issue/1833): Support for using the network stack in the
	// network namespace of the calling process.
	//
	// The stack of the root network namespace is set when the kernel is
	// initialized, before tasks run. It is saved and restored with
	// inet.Namespace, and it does not change after that. So it is safe to
	// retrieve it here instead of when procfs is mounted.
	stack := k.RootNetworkNamespace().Stack()

	children := fs.sysDirFiles(ctx, root, k, stack, path)
	subdirs := sysSubdirs(path)
	if children == nil {
		children = make(map[string]kernfs.Inode, len(subdirs))
	}
	for _, name := range subdirs {
		if path == "" && name == "net" && stack == nil {
			// Without a network stack, /proc/sys/net is empty.
			children[name] = fs.newStaticDir(ctx, root, nil)
			continue
		}
		subdir := name
		if path != "" {
			subdir = path + "/" + name
		}
		children[name] = fs.newLazySysDir(ctx, root, k, subdir)
	}
	return children
}

// sysDirFiles returns the non-directory children of the /proc/sys directory at
// path, which is relative to /proc/sys. stack is the network stack of the
// root network namespace.
func (fs *filesystem) sysDirFiles(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, stack inet.Stack, path string) map[string]kernfs.Inode {
	switch path {
	case "", "net", "net/ipv4/conf", "net/ipv6/conf":
		// These directories only contain subdirectories.
		return nil
	case "kernel":
		return map[string]kernfs.Inode{
			"cap_last_cap":       fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", linux.CAP_LAST_CAP))),
			"hostname":           fs.newInode(ctx, root, 0444, &hostnameData{}),
			"domainname":         fs.newInode(ctx, root, 0444, &domainnameData{}),
			"overflowgid":        fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", auth.OverflowGID))),
			"overflowuid":        fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", auth.OverflowUID))),
			"pid_max":            fs.newInode(ctx, root, 0644, newStaticFile(fmt.Sprintf("%d\n", kernel.TasksLimit))),
			"randomize_va_space": fs.newInode(ctx, root, 0644, newStaticFile("2\n")),
			"sem":                fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\t%d\t%d\t%d\n", linux.SEMMSL, linux.SEMMNS, linux.SEMOPM, linux.SEMMNI))),
			"shmall":             fs.newInode(ctx, root, 0444, ipcData(linux.SHMALL)),
			"shmmax":             fs.newInode(ctx, root, 0444, ipcData(linux.SHMMAX)),
			"shmmni":             fs.newInode(ctx, root, 0444, ipcData(linux.SHMMNI)),
			"msgmni":             fs.newInode(ctx, root, 0444, ipcData(linux.MSGMNI)),
			"msgmax":             fs.newInode(ctx, root, 0444, ipcData(linux.MSGMAX)),
			"msgmnb":             fs.newInode(ctx, root, 0444, ipcData(linux.MSGMNB)),
			"osrelease":          fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxRelease())),
			"ostype":             fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxSysname)),
			"version":            fs.newInode(ctx, root, 0444, newStaticFile(version.LinuxVersion)),
		}
	case "kernel/random":
		return map[string]kernfs.Inode{
			"boot_id": fs.newInode(ctx, root, 0444, newStaticFile(randUUID())),
			"uuid":    fs.newInode(ctx, root, 0444, &uuidData{}),
		}
	case "kernel/yama":
		return map[string]kernfs.Inode{
			"ptrace_scope": fs.newYAMAPtraceScopeFile(ctx, k, root),
		}
	case "kernel/keys":
		return map[string]kernfs.Inode{
			"maxkeys": fs.newMaxKeySizeFile(ctx, k, root),
		}
	case "fs":
		return map[string]kernfs.Inode{
			"file-max":      fs.newInode(ctx, root, 0444, newStaticFile(fmt.Sprintf("%d\n", int64(math.MaxInt64)))),
			"file-nr":       fs.newInode(ctx, root, 0444, &fileNrData{vfs: k.VFS()}),
			"mount-max":     fs.newInode(ctx, root, 0644, &atomicInt32File{val: &k.VFS().MountMax, min: 1, max: math.MaxInt32}),
			"nr_open":       fs.newInode(ctx, root, 0644, &atomicInt32File{val: &k.MaxFDLimit, min: 8, max: kernel.MaxFdLimit}),
			"pipe-max-size": fs.newInode(ctx, root, 0644, newStaticFile(fmt.Sprintf("%d\n", pipe.MaximumPipeSize))),
		}
	case "vm":
		return map[string]kernfs.Inode{
			"max_map_count":     fs.newInode(ctx, root, 0444, newStaticFile("2147483647\n")),
			"mmap_min_addr":     fs.newInode(ctx, root, 0444, &mmapMinAddrData{k: k}),
			"overcommit_memory": fs.newInode(ctx, root, 0444, newStaticFile("0\n")),
		}
	case "user":
		return map[string]kernfs.Inode{
			"max_user_namespaces": fs.newInode(ctx, root, 0644, &maxUserNamespacesData{}),
		}
	case "net/ipv4":
		return map[string]kernfs.Inode{
			"ip_forward":          fs.newInode(ctx, root, 0644, &ipForwarding{stack: stack, protocol: ipv4.ProtocolNumber}),
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
		}
	case "net/ipv4/conf/all", "net/ipv4/conf/default":
		// route_localnet toggles acceptance of martian loopback packets on
		// non-loopback NICs (kube-proxy enables this). It is backed by the
		// IPv4 protocol's AllowExternalLoopbackTraffic option.
		return map[string]kernfs.Inode{
			"route_localnet": fs.newInode(ctx, root, 0644, &routeLocalnetData{stack: stack}),
		}
	case "net/core":
		return map[string]kernfs.Inode{
			"default_qdisc": fs.newInode(ctx, root, 0444, newStaticFile("pfifo_fast")),
			"message_burst": fs.newInode(ctx, root, 0444, newStaticFile("10")),
			"message_cost":  fs.newInode(ctx, root, 0444, newStaticFile("5")),
			"optmem_max":    fs.newInode(ctx, root, 0444, newStaticFile("0")),
			"rmem_default":  fs.newInode(ctx, root, 0444, newStaticFile("212992")),
			"rmem_max":      fs.newInode(ctx, root, 0444, newStaticFile("212992")),
			"somaxconn":     fs.newInode(ctx, root, 0444, newStaticFile("1024")),
			"wmem_default":  fs.newInode(ctx, root, 0444, newStaticFile("212992")),
			"wmem_max":      fs.newInode(ctx, root, 0444, newStaticFile("212992")),
		}
	case "net/ipv6":
		return map[string]kernfs.Inode{
			"bindv6only":       fs.newInode(ctx, root, 0444, newStaticFile("0")),
			"ip6frag_time":     fs.newInode(ctx, root, 0444, newStaticFile("60")),
			"ip_nonlocal_bind": fs.newInode(ctx, root, 0444, newStaticFile("0")),
			"auto_flowlabels":  fs.newInode(ctx, root, 0444, newStaticFile("1")),
		}
	case "net/ipv6/conf/all":
		return map[string]kernfs.Inode{
			"forwarding": fs.newInode(ctx, root, 0644, &ipForwarding{stack: stack, protocol: ipv6.ProtocolNumber}),
		}
	case "net/ipv6/conf/default":
		// Stub for conf/default/forwarding.
		return map[string]kernfs.Inode{
			"forwarding": fs.newInode(ctx, root, 0644, &atomicInt32File{val: new(atomicbitops.Int32), min: 0, max: 1}),
		}
	}
	panic(fmt.Sprintf("unknown /proc/sys directory %q", path))
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
