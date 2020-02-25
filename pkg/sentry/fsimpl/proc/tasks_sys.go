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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// newSysDir returns the dentry corresponding to /proc/sys directory.
func newSysDir(root *auth.Credentials, inoGen InoGenerator, k *kernel.Kernel) *kernfs.Dentry {
	return kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
		"kernel": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
			"hostname": newDentry(root, inoGen.NextIno(), 0444, &hostnameData{}),
			"shmall":   newDentry(root, inoGen.NextIno(), 0444, shmData(linux.SHMALL)),
			"shmmax":   newDentry(root, inoGen.NextIno(), 0444, shmData(linux.SHMMAX)),
			"shmmni":   newDentry(root, inoGen.NextIno(), 0444, shmData(linux.SHMMNI)),
		}),
		"vm": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
			"mmap_min_addr":     newDentry(root, inoGen.NextIno(), 0444, &mmapMinAddrData{}),
			"overcommit_memory": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0\n")),
		}),
		"net": newSysNetDir(root, inoGen, k),
	})
}

// newSysNetDir returns the dentry corresponding to /proc/sys/net directory.
func newSysNetDir(root *auth.Credentials, inoGen InoGenerator, k *kernel.Kernel) *kernfs.Dentry {
	var contents map[string]*kernfs.Dentry

	// TODO(gvisor.dev/issue/1833): Support for using the network stack in the
	// network namespace of the calling process.
	if stack := k.RootNetworkNamespace().Stack(); stack != nil {
		contents = map[string]*kernfs.Dentry{
			"ipv4": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
				"tcp_sack": newDentry(root, inoGen.NextIno(), 0644, &tcpSackData{stack: stack}),

				// The following files are simple stubs until they are implemented in
				// netstack, most of these files are configuration related. We use the
				// value closest to the actual netstack behavior or any empty file, all
				// of these files will have mode 0444 (read-only for all users).
				"ip_local_port_range":     newDentry(root, inoGen.NextIno(), 0444, newStaticFile("16000   65535")),
				"ip_local_reserved_ports": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("")),
				"ipfrag_time":             newDentry(root, inoGen.NextIno(), 0444, newStaticFile("30")),
				"ip_nonlocal_bind":        newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"ip_no_pmtu_disc":         newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1")),

				// tcp_allowed_congestion_control tell the user what they are able to
				// do as an unprivledged process so we leave it empty.
				"tcp_allowed_congestion_control":   newDentry(root, inoGen.NextIno(), 0444, newStaticFile("")),
				"tcp_available_congestion_control": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("reno")),
				"tcp_congestion_control":           newDentry(root, inoGen.NextIno(), 0444, newStaticFile("reno")),

				// Many of the following stub files are features netstack doesn't
				// support. The unsupported features return "0" to indicate they are
				// disabled.
				"tcp_base_mss":              newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1280")),
				"tcp_dsack":                 newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_early_retrans":         newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_fack":                  newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_fastopen":              newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_fastopen_key":          newDentry(root, inoGen.NextIno(), 0444, newStaticFile("")),
				"tcp_invalid_ratelimit":     newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_keepalive_intvl":       newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_keepalive_probes":      newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_keepalive_time":        newDentry(root, inoGen.NextIno(), 0444, newStaticFile("7200")),
				"tcp_mtu_probing":           newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_no_metrics_save":       newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1")),
				"tcp_probe_interval":        newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_probe_threshold":       newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"tcp_retries1":              newDentry(root, inoGen.NextIno(), 0444, newStaticFile("3")),
				"tcp_retries2":              newDentry(root, inoGen.NextIno(), 0444, newStaticFile("15")),
				"tcp_rfc1337":               newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1")),
				"tcp_slow_start_after_idle": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1")),
				"tcp_synack_retries":        newDentry(root, inoGen.NextIno(), 0444, newStaticFile("5")),
				"tcp_syn_retries":           newDentry(root, inoGen.NextIno(), 0444, newStaticFile("3")),
				"tcp_timestamps":            newDentry(root, inoGen.NextIno(), 0444, newStaticFile("1")),
			}),
			"core": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
				"default_qdisc": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("pfifo_fast")),
				"message_burst": newDentry(root, inoGen.NextIno(), 0444, newStaticFile("10")),
				"message_cost":  newDentry(root, inoGen.NextIno(), 0444, newStaticFile("5")),
				"optmem_max":    newDentry(root, inoGen.NextIno(), 0444, newStaticFile("0")),
				"rmem_default":  newDentry(root, inoGen.NextIno(), 0444, newStaticFile("212992")),
				"rmem_max":      newDentry(root, inoGen.NextIno(), 0444, newStaticFile("212992")),
				"somaxconn":     newDentry(root, inoGen.NextIno(), 0444, newStaticFile("128")),
				"wmem_default":  newDentry(root, inoGen.NextIno(), 0444, newStaticFile("212992")),
				"wmem_max":      newDentry(root, inoGen.NextIno(), 0444, newStaticFile("212992")),
			}),
		}
	}

	return kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
		"net": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, contents),
	})
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

// Generate implements vfs.DynamicBytesSource.
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
	buf.WriteString(val)
	return nil
}

func (d *tcpSackData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, syserror.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}

	// Limit the amount of memory allocated.
	src = src.TakeFirst(usermem.PageSize - 1)

	var v int32
	n, err := usermem.CopyInt32StringInVec(ctx, src.IO, src.Addrs, &v, src.Opts)
	if err != nil {
		return n, err
	}
	if d.enabled == nil {
		d.enabled = new(bool)
	}
	*d.enabled = v != 0
	return n, d.stack.SetTCPSACKEnabled(*d.enabled)
}
