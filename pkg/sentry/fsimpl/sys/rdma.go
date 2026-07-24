// Copyright 2026 The gVisor Authors.
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

package sys

import (
	"fmt"
	"path"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/rdma"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// This file builds the RDMA sysfs surface from a rdma.Snapshot.
//
// The layout is path-identical to the host: one canonical subtree under
// /sys/devices/pci... holds every attribute, with the device-class
// directories (infiniband, infiniband_verbs, net) as real directories under
// their PCI leaf, exactly as the kernel lays them out. /sys/class/* and
// /sys/bus/pci/devices contain only symlinks into the canonical subtree,
// with kernel-identical relative targets. Fidelity matters because
// consumers resolve these links with realpath() and then navigate the
// resolved paths: libibverbs discovers devices via
// /sys/class/infiniband_verbs, and NCCL's topology discovery realpath()s
// /sys/class/infiniband/<dev>/device, walks the PCI hierarchy upward
// reading bridge attributes, and locates GPUs via
// "/sys/class/pci_bus/<bus>/../../<bdf>".
//
// Most attributes are static snapshots. Per-port dynamic state (link state,
// rate, and above all the RoCE GID table, which repopulates whenever the
// paired netdev's netns or addresses change) is served by reading host sysfs
// at access time; those host paths are bind-mounted into the sandbox's chroot.

// rdmaSysfsDirs is the output of newRDMASysfs: subtrees for GetFilesystem
// to graft into the overall /sys hierarchy.
type rdmaSysfsDirs struct {
	// devices maps the pciXXXX:YY root-complex names to their subtrees,
	// to be added under /sys/devices.
	devices map[string]kernfs.Inode
	// class maps class-directory names (infiniband, infiniband_verbs,
	// net, pci_bus) to symlink-farm directories for /sys/class.
	class map[string]kernfs.Inode
	// busPCIDevices contains the /sys/bus/pci/devices symlinks.
	busPCIDevices map[string]kernfs.Inode
	// node is the /sys/devices/system/node subtree, or nil.
	node kernfs.Inode
}

// rdmaDirTree is the intermediate mutable representation, keyed by entry name.
type rdmaDirTree struct {
	children  map[string]*rdmaDirTree
	files     map[string]string // static file contents
	hostFiles map[string]string // file name -> host path read at access time
	symlinks  map[string]string // link name -> relative target
}

func newRDMADirTree() *rdmaDirTree {
	return &rdmaDirTree{
		children:  map[string]*rdmaDirTree{},
		files:     map[string]string{},
		hostFiles: map[string]string{},
		symlinks:  map[string]string{},
	}
}

// get returns the subtree at relPath (slash-separated), creating
// intermediate directories.
func (t *rdmaDirTree) get(relPath string) *rdmaDirTree {
	cur := t
	for _, part := range strings.Split(relPath, "/") {
		if part == "" {
			continue
		}
		next, ok := cur.children[part]
		if !ok {
			next = newRDMADirTree()
			cur.children[part] = next
		}
		cur = next
	}
	return cur
}

// newRDMASysfs builds the RDMA sysfs subtrees from snap.
func (fs *filesystem) newRDMASysfs(ctx context.Context, creds *auth.Credentials, snap *rdma.Snapshot) (*rdmaSysfsDirs, error) {
	root := newRDMADirTree()
	classIB := map[string]string{}     // ibdev -> symlink target
	classUverbs := map[string]string{} // uverbsN -> symlink target
	classNet := map[string]string{}    // netdev -> symlink target
	classPCIBus := map[string]string{} // bus ("0000:0c") -> symlink target

	// 1. The canonical PCI hierarchy with per-level static attributes, plus
	// the "subsystem" symlink every PCI device carries. NCCL and other
	// consumers classify a directory as a PCI device by following
	// subsystem to /sys/bus/pci; without it a device reads as "not a PCI
	// device" and topology discovery aborts. The link points into our own
	// synthesized /sys/bus/pci, so it is not a host escape hatch. The
	// bus/<bus> entry each device sits on is created for pci_bus below.
	for _, n := range snap.PCINodes {
		if err := checkRelPath(n.Path); err != nil {
			return nil, err
		}
		d := root.get(n.Path)
		for name, val := range n.Attrs {
			if rdma.SafeName(name) {
				d.files[name] = val
			}
		}
		// Root complexes (pciXXXX:YY) carry no subsystem link and sit on
		// no parent bus; only function directories (BDFs) do.
		if rdma.IsBDF(path.Base(n.Path)) {
			// depth of n.Path below /sys == number of "../" to reach /sys.
			depth := strings.Count(n.Path, "/") + 1
			d.symlinks["subsystem"] = strings.Repeat("../", depth) + "bus/pci"
			fs.addPCIBus(root, n.Path, classPCIBus)
		}
	}

	// 2. Per-device class subtrees under their PCI leaves.
	for i := range snap.Devices {
		dev := &snap.Devices[i]
		if err := checkRelPath(dev.LeafPCI); err != nil {
			return nil, err
		}
		if !rdma.SafeName(dev.IBDev) || !rdma.SafeName(dev.Uverbs) {
			return nil, fmt.Errorf("unsafe RDMA device names %q/%q", dev.IBDev, dev.Uverbs)
		}
		// From <leaf>/<classdir>/<name>, the PCI function directory is
		// three levels up plus its own name.
		deviceLink := "../../../" + path.Base(dev.LeafPCI)

		// infiniband/<ibdev>/
		ibRel := dev.LeafPCI + "/infiniband/" + dev.IBDev
		ib := root.get(ibRel)
		for name, val := range dev.IBAttrs {
			if rdma.SafeName(name) {
				ib.files[name] = val
			}
		}
		ib.symlinks["device"] = deviceLink
		fs.addPorts(ib, dev)
		classIB[dev.IBDev] = "../../" + ibRel

		// infiniband_verbs/<uverbsN>/
		uvRel := dev.LeafPCI + "/infiniband_verbs/" + dev.Uverbs
		uv := root.get(uvRel)
		// IBDev is the trimmed device name (it is also a path component); the
		// sysfs "ibdev" file holds that name followed by a newline. dev and
		// abi_version were snapshotted verbatim, so they already carry the
		// host's trailing newline.
		uv.files["ibdev"] = dev.IBDev + "\n"
		uv.files["abi_version"] = dev.ABIVersion
		// The RDMA proxy registers the uverbs device at the host's fixed
		// IB uverbs major (IB_UVERBS_MAJOR), so this host "major:minor"
		// already matches the guest /dev/infiniband node and needs no rewrite.
		uv.files["dev"] = dev.Dev
		uv.symlinks["device"] = deviceLink
		classUverbs[dev.Uverbs] = "../../" + uvRel

		// net/<name>/
		for _, nd := range dev.NetDevs {
			if !rdma.SafeName(nd.Name) {
				continue
			}
			netRel := dev.LeafPCI + "/net/" + nd.Name
			nt := root.get(netRel)
			for name, val := range nd.Attrs {
				if rdma.SafeName(name) {
					nt.files[name] = val
				}
			}
			nt.symlinks["device"] = deviceLink
			classNet[nd.Name] = "../../" + netRel
		}
	}
	// pci_bus and subsystem entries are created for every BDF node in the
	// loop above; GPU leaves are already in snap.PCINodes, so they are
	// covered without special handling here.

	// 3. Convert the tree and assemble the outputs.
	out := &rdmaSysfsDirs{
		devices:       map[string]kernfs.Inode{},
		class:         map[string]kernfs.Inode{},
		busPCIDevices: map[string]kernfs.Inode{},
	}
	devicesTree, ok := root.children["devices"]
	if !ok {
		return nil, fmt.Errorf("RDMA snapshot contains no devices/ paths")
	}
	for name, sub := range devicesTree.children {
		out.devices[name] = fs.buildRDMADir(ctx, creds, sub)
	}

	out.class["infiniband"] = fs.newDir(ctx, creds, defaultSysDirMode, fs.symlinkFarm(ctx, creds, classIB))
	uverbsEntries := fs.symlinkFarm(ctx, creds, classUverbs)
	if snap.VerbsABIVersion != "" {
		uverbsEntries["abi_version"] = fs.newStaticFile(ctx, creds, defaultSysMode, snap.VerbsABIVersion)
	}
	out.class["infiniband_verbs"] = fs.newDir(ctx, creds, defaultSysDirMode, uverbsEntries)
	if len(classNet) > 0 {
		out.class["net"] = fs.newDir(ctx, creds, defaultSysDirMode, fs.symlinkFarm(ctx, creds, classNet))
	}
	if len(classPCIBus) > 0 {
		out.class["pci_bus"] = fs.newDir(ctx, creds, defaultSysDirMode, fs.symlinkFarm(ctx, creds, classPCIBus))
	}

	for _, n := range snap.PCINodes {
		base := path.Base(n.Path)
		if rdma.IsBDF(base) {
			out.busPCIDevices[base] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), "../../../"+n.Path)
		}
	}

	if snap.NUMA != nil {
		out.node = fs.buildNUMA(ctx, creds, snap.NUMA)
	}
	return out, nil
}

// addPorts populates <ibdev>/ports/<n>/ with static attributes and
// live host-backed files (GIDs, GID attributes, state, counters).
func (fs *filesystem) addPorts(ib *rdmaDirTree, dev *rdma.Device) {
	for num, port := range dev.Ports {
		if !rdma.SafeName(num) {
			continue
		}
		hostBase := path.Join("/sys/class/infiniband", dev.IBDev, "ports", num)
		p := ib.get("ports/" + num)
		for name, val := range port.StaticAttrs {
			if rdma.SafeName(name) {
				p.files[name] = val
			}
		}
		for _, name := range port.LiveAttrs {
			if rdma.SafeName(name) {
				p.hostFiles[name] = path.Join(hostBase, name)
			}
		}
		gids := p.get("gids")
		types := p.get("gid_attrs/types")
		ndevs := p.get("gid_attrs/ndevs")
		for _, idx := range port.GIDNames {
			if !rdma.SafeName(idx) {
				continue
			}
			gids.hostFiles[idx] = path.Join(hostBase, "gids", idx)
			types.hostFiles[idx] = path.Join(hostBase, "gid_attrs/types", idx)
			ndevs.hostFiles[idx] = path.Join(hostBase, "gid_attrs/ndevs", idx)
		}
		for _, name := range port.CounterNames {
			if rdma.SafeName(name) {
				p.get("counters").hostFiles[name] = path.Join(hostBase, "counters", name)
			}
		}
		for _, name := range port.HWCounterNames {
			if rdma.SafeName(name) {
				p.get("hw_counters").hostFiles[name] = path.Join(hostBase, "hw_counters", name)
			}
		}
	}
}

// addPCIBus creates <parent-of-leaf>/pci_bus/<bus> (the kernel places a
// bus directory inside the bridge that creates the bus) and records the
// /sys/class/pci_bus symlink. NCCL resolves GPU and NIC positions via
// "/sys/class/pci_bus/<bus>/../../<bdf>".
func (fs *filesystem) addPCIBus(root *rdmaDirTree, leaf string, classPCIBus map[string]string) {
	base := path.Base(leaf)
	if len(base) < 7 {
		return
	}
	bus := base[:7] // "0000:0c" of "0000:0c:00.0"
	parent := path.Dir(leaf)
	root.get(parent + "/pci_bus/" + bus)
	classPCIBus[bus] = "../../" + parent + "/pci_bus/" + bus
}

func (fs *filesystem) buildNUMA(ctx context.Context, creds *auth.Credentials, numa *rdma.NUMA) kernfs.Inode {
	entries := map[string]kernfs.Inode{}
	for name, val := range numa.Aggregate {
		if rdma.SafeName(name) {
			entries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val)
		}
	}
	for name, attrs := range numa.Nodes {
		if !rdma.SafeName(name) {
			continue
		}
		sub := map[string]kernfs.Inode{}
		for attr, val := range attrs {
			if rdma.SafeName(attr) {
				sub[attr] = fs.newStaticFile(ctx, creds, defaultSysMode, val)
			}
		}
		entries[name] = fs.newDir(ctx, creds, defaultSysDirMode, sub)
	}
	return fs.newDir(ctx, creds, defaultSysDirMode, entries)
}

// buildRDMADir converts an rdmaDirTree into kernfs inodes.
func (fs *filesystem) buildRDMADir(ctx context.Context, creds *auth.Credentials, t *rdmaDirTree) kernfs.Inode {
	entries := map[string]kernfs.Inode{}
	for name, val := range t.files {
		entries[name] = fs.newStaticFile(ctx, creds, defaultSysMode, val)
	}
	for name, hostPath := range t.hostFiles {
		// Read from host sysfs at file-read time via openat(-1, ...,
		// O_RDONLY|O_NOFOLLOW) (sys.hostFile.Generate); the rdmaproxy seccomp
		// filter allows that openat.
		entries[name] = fs.newHostFile(ctx, creds, defaultSysMode, hostPath)
	}
	for name, target := range t.symlinks {
		entries[name] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
	}
	for name, child := range t.children {
		entries[name] = fs.buildRDMADir(ctx, creds, child)
	}
	return fs.newDir(ctx, creds, defaultSysDirMode, entries)
}

func (fs *filesystem) symlinkFarm(ctx context.Context, creds *auth.Credentials, targets map[string]string) map[string]kernfs.Inode {
	entries := map[string]kernfs.Inode{}
	for name, target := range targets {
		if rdma.SafeName(name) {
			entries[name] = kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
		}
	}
	return entries
}

// checkRelPath validates a snapshot-provided sysfs-relative path: rooted
// under devices/, with every component a safe name (see SafeName).
func checkRelPath(relPath string) error {
	if !strings.HasPrefix(relPath, "devices/") {
		return fmt.Errorf("RDMA sysfs path %q is not under devices/", relPath)
	}
	for _, part := range strings.Split(relPath, "/") {
		if !rdma.SafeName(part) {
			return fmt.Errorf("RDMA sysfs path %q contains unsafe component %q", relPath, part)
		}
	}
	return nil
}
