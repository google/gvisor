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

// rdma_netdev.go moves RDMA-fabric netdevs (RoCE-backed Ethernet ports and
// IPoIB-backed InfiniBand ports alike) from the host's network namespace
// into the sandbox container's network namespace before the sandbox process
// is forked. This eliminates the need for the sentry to switch namespaces
// (and hold CAP_SYS_ADMIN against init_user_ns) during ibv_modify_qp
// ioctls — the netdev that owns the RDMA GIDs lives directly in the sandbox
// netns, so kernel-side GID-to-netdev resolution succeeds in the calling
// task's netns without any privileged operation by the sentry.
//
// All the privileged work (LinkSetNsFd, AddrAdd, RouteAdd) runs in the
// `runsc create` parent process, which retains the parent's CAP_NET_ADMIN +
// CAP_SYS_ADMIN against init_user_ns. The sandbox process inherits no extra
// caps from this code path.
//
// Activation is gated by --rdmaproxy-move-netdevs (default off): moving
// netdevs mutates host network state, so operators must opt in. RoCE
// collective workloads (e.g. NCCL under --network=sandbox) require the
// move; native IB users may opt in too if they want netdev isolation.

package sandbox

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

// rdmaNetdevSnapshot captures the host-netns configuration of a RoCE netdev
// that's about to be moved into the sandbox netns. Moving a netdev between
// namespaces zeros its IP configuration and brings it down, so we have to
// reapply the captured state on the other side.
type rdmaNetdevSnapshot struct {
	Name   string
	MAC    net.HardwareAddr
	MTU    int
	Up     bool
	Addrs  []netlink.Addr
	Routes []netlink.Route
}

// snapshotRDMANetdev captures the current state of a netdev in whichever
// netns the calling thread is in. Caller must be in the source netns
// (typically the host) and have CAP_NET_ADMIN.
func snapshotRDMANetdev(name string) (*rdmaNetdevSnapshot, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("LinkByName: %w", err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("AddrList: %w", err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{LinkIndex: link.Attrs().Index},
		netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, fmt.Errorf("RouteList: %w", err)
	}
	return &rdmaNetdevSnapshot{
		Name:   name,
		MAC:    link.Attrs().HardwareAddr,
		MTU:    link.Attrs().MTU,
		Up:     link.Attrs().Flags&net.FlagUp != 0,
		Addrs:  addrs,
		Routes: routes,
	}, nil
}

// applyRDMANetdevSnapshot reapplies a snapshot to the netdev, which is
// expected to be present in the *current* netns. Caller must be in the
// destination netns.
func applyRDMANetdevSnapshot(snap *rdmaNetdevSnapshot) error {
	link, err := netlink.LinkByName(snap.Name)
	if err != nil {
		return fmt.Errorf("LinkByName after move: %w", err)
	}
	if snap.MTU != 0 && snap.MTU != link.Attrs().MTU {
		if err := netlink.LinkSetMTU(link, snap.MTU); err != nil {
			log.Warningf("rdma: LinkSetMTU(%q,%d): %v", snap.Name, snap.MTU, err)
		}
	}
	// Replicate the host's admin state. We deliberately do NOT force the
	// link up here: cloud RDMA fabrics (OCI in particular) only provision
	// switch ACLs for NICs that are admin-up when their NIC configurer
	// runs at boot. Forcing additional NICs admin-up later exposes them
	// to the workload but the fabric drops their traffic, manifesting as
	// 110 Connection timed out on ibv_modify_qp. Honoring snap.Up keeps
	// the sandbox's view consistent with what a non-sandboxed process on
	// the same host would see.
	if snap.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			log.Warningf("rdma: LinkSetUp(%q): %v", snap.Name, err)
		}
	}
	for _, a := range snap.Addrs {
		// Drop interface-scoped, kernel-managed link-local v6 addrs; the
		// kernel will autoconfigure them in the new netns. Reapplying them
		// explicitly causes EEXIST.
		if a.Scope == int(netlink.SCOPE_LINK) && a.IP.To4() == nil {
			continue
		}
		na := a
		// LinkIndex changes after a netns move; let the kernel resolve via the
		// link reference passed to AddrAdd.
		na.LinkIndex = 0
		if err := netlink.AddrAdd(link, &na); err != nil {
			log.Warningf("rdma: AddrAdd(%q,%v): %v", snap.Name, na.IPNet, err)
		}
	}
	for _, r := range snap.Routes {
		// Skip kernel-installed connected routes — adding the address above
		// regenerates them. Reapplying here would EEXIST.
		if r.Protocol == unix.RTPROT_KERNEL {
			continue
		}
		nr := r
		nr.LinkIndex = link.Attrs().Index
		if err := netlink.RouteAdd(&nr); err != nil {
			log.Warningf("rdma: RouteAdd(%q,%v): %v", snap.Name, nr.Dst, err)
		}
	}
	return nil
}

// MoveRDMANetdevsIntoSandbox moves the named RoCE netdevs from the calling
// thread's current netns (the host) into the netns at targetNetnsPath, then
// reapplies their captured IPv4/IPv6 configuration on the other side.
//
// On any error after the first netdev has moved, all already-moved netdevs
// are rolled back to the source netns so the host RDMA fabric is left in a
// consistent state. Callers should treat any returned error as fatal for
// the sandbox start.
//
// netdevNames must reference netdevs in the calling thread's current netns;
// netdevs missing from that netns are skipped with a warning (e.g. another
// container may already own them).
func MoveRDMANetdevsIntoSandbox(netdevNames []string, targetNetnsPath string) (retErr error) {
	if len(netdevNames) == 0 {
		return nil
	}
	if targetNetnsPath == "" {
		return fmt.Errorf("empty target netns path; nothing to move into")
	}

	targetFD, err := unix.Open(targetNetnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open target netns %q: %w", targetNetnsPath, err)
	}
	defer unix.Close(targetFD)

	srcFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open source (host) netns: %w", err)
	}
	defer unix.Close(srcFD)

	// Snapshot first so a partial failure can roll back cleanly. We also
	// silently skip netdevs that aren't in the host netns at all; that
	// indicates someone else already moved them.
	snapshots := make([]*rdmaNetdevSnapshot, 0, len(netdevNames))
	for _, name := range netdevNames {
		snap, err := snapshotRDMANetdev(name)
		if err != nil {
			log.Warningf("rdma: snapshot %q: %v (skipping)", name, err)
			continue
		}
		snapshots = append(snapshots, snap)
	}
	if len(snapshots) == 0 {
		return nil
	}

	// Move each netdev into the target netns, then enter the target netns to
	// reapply addrs/routes. On the first failure we undo everything we've
	// already done (move netdevs back, drop addrs/routes the way the kernel
	// would on the host side anyway).
	moved := make([]*rdmaNetdevSnapshot, 0, len(snapshots))
	defer func() {
		if retErr == nil {
			return
		}
		for _, snap := range moved {
			if err := rollbackNetdevToSourceNetns(snap, targetFD, srcFD); err != nil {
				log.Warningf("rdma: rollback %q: %v", snap.Name, err)
			}
		}
	}()

	for _, snap := range snapshots {
		link, err := netlink.LinkByName(snap.Name)
		if err != nil {
			return fmt.Errorf("LinkByName %q: %w", snap.Name, err)
		}
		log.Infof("rdma: moving netdev %q into sandbox netns %q", snap.Name, targetNetnsPath)
		if err := netlink.LinkSetNsFd(link, targetFD); err != nil {
			return fmt.Errorf("LinkSetNsFd %q: %w", snap.Name, err)
		}
		moved = append(moved, snap)
	}

	// Reapply addrs/routes inside the target netns. We do this with the OS
	// thread locked and explicit setns to avoid disturbing other goroutines'
	// view of the network namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("setns target: %w", err)
	}
	var applyErr error
	for _, snap := range snapshots {
		if err := applyRDMANetdevSnapshot(snap); err != nil {
			applyErr = fmt.Errorf("apply snapshot %q: %w", snap.Name, err)
			break
		}
	}
	if err := unix.Setns(srcFD, unix.CLONE_NEWNET); err != nil {
		// Failure to restore the host netns is fatal for the parent — the
		// caller's process can't keep running with the wrong netns.
		return fmt.Errorf("setns back to host: %w (apply err: %v)", err, applyErr)
	}
	if applyErr != nil {
		return applyErr
	}
	log.Infof("rdma: moved %d netdev(s) into sandbox netns and reapplied IP configuration", len(snapshots))
	return nil
}

// rollbackNetdevToSourceNetns moves a netdev back from the target netns to
// the source netns. Used when a later step fails after some moves have
// already happened. Best-effort: addr/route reapply on the source side is
// not performed because the kernel re-adds connected routes when AddrAdd
// runs and the source-side caller's snapshot is no longer authoritative.
// Callers should log on error.
func rollbackNetdevToSourceNetns(snap *rdmaNetdevSnapshot, targetFD, srcFD int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("setns target: %w", err)
	}
	link, err := netlink.LinkByName(snap.Name)
	if err != nil {
		_ = unix.Setns(srcFD, unix.CLONE_NEWNET)
		return fmt.Errorf("LinkByName in target: %w", err)
	}
	if err := netlink.LinkSetNsFd(link, srcFD); err != nil {
		_ = unix.Setns(srcFD, unix.CLONE_NEWNET)
		return fmt.Errorf("LinkSetNsFd back: %w", err)
	}
	if err := unix.Setns(srcFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("setns back: %w", err)
	}
	// On the source side, reapply the snapshot best-effort. The kernel will
	// regenerate the connected route from the address; user-installed
	// routes are reapplied where possible.
	if err := applyRDMANetdevSnapshot(snap); err != nil {
		log.Warningf("rdma: rollback reapply %q: %v", snap.Name, err)
	}
	return nil
}

// RDMANetdevsForSpec returns the host-netns names of netdevs whose underlying
// ibdev is referenced by /dev/infiniband/uverbs* devices in the container's
// spec. The lookup uses the same sysfs path that ibdev2netdev walks:
// uverbsN → ibdev → first non-empty ports/*/gid_attrs/ndevs/0. This covers
// both RoCE (Ethernet-backed) and InfiniBand (IPoIB-backed) HCAs — the
// netdev mover is link-layer agnostic, since snapshot/restore goes through
// generic netlink (MTU, addrs, routes, IPv4 sysctls) and the kernel handles
// IB-specific L2 internals (20-byte HW addr, PKEY children, etc.) without
// our help.
//
// Two classes of netdev are still skipped to keep us from breaking host
// networking when we move:
//
//   - Netdevs that are the kernel's default-route egress: those are the
//     host's primary uplink (eth0 etc.) and moving them severs SSH and
//     all other host networking. RDMA fabric NICs are point-to-point and
//     should never carry the default route.
//   - Netdevs whose name matches /^eth\d+$/: belt-and-braces against the
//     same problem in case default-route detection is in a transient state
//     during host bringup.
//
// The caller decides whether to act on this list at all; gating happens
// at the rdmaproxy-move-netdevs flag check in the call site, not here.
//
// Returns the unique netdev names in arbitrary order.
func RDMANetdevsForSpec(specDevices []string) []string {
	defaultRouteIfaces := defaultRouteOifNames()
	seen := map[string]struct{}{}
	out := []string{}
	nUverbs := 0
	for _, devPath := range specDevices {
		if !strings.HasPrefix(devPath, "/dev/infiniband/uverbs") {
			continue
		}
		nUverbs++
		uverbsName := filepath.Base(devPath)
		ibdev := readSysfsTrim(filepath.Join("/sys/class/infiniband_verbs", uverbsName, "ibdev"))
		if ibdev == "" {
			log.Warningf("rdma: spec device %q has no ibdev backing in sysfs — skipping", devPath)
			continue
		}
		ibBase := filepath.Join("/sys/class/infiniband", ibdev, "ports")
		ports, err := os.ReadDir(ibBase)
		if err != nil {
			log.Warningf("rdma: ibdev %q (from %s) has no readable ports dir: %v — skipping", ibdev, devPath, err)
			continue
		}
		foundForThisIbdev := false
		for _, port := range ports {
			ndev := readSysfsTrim(filepath.Join(ibBase, port.Name(), "gid_attrs", "ndevs", "0"))
			if ndev == "" {
				continue
			}
			if _, ok := seen[ndev]; ok {
				log.Debugf("rdma: %s -> ibdev %q port %s -> netdev %q (already detected from another uverbs device)", devPath, ibdev, port.Name(), ndev)
				foundForThisIbdev = true
				continue
			}
			if isHostPrimaryNetdev(ndev, defaultRouteIfaces) {
				log.Warningf("rdma: %s -> ibdev %q port %s -> netdev %q — skipping (host primary uplink: carries default route or matches eth* name pattern)", devPath, ibdev, port.Name(), ndev)
				continue
			}
			log.Infof("rdma: detected %s -> ibdev %q port %s -> netdev %q", devPath, ibdev, port.Name(), ndev)
			seen[ndev] = struct{}{}
			out = append(out, ndev)
			foundForThisIbdev = true
		}
		if !foundForThisIbdev {
			log.Warningf("rdma: ibdev %q (from %s) has no netdev in any port's gid_attrs/ndevs/0 — GID table may not be populated yet, or the HCA may be in raw-Ethernet mode", ibdev, devPath)
		}
	}
	if nUverbs > 0 {
		log.Infof("rdma: resolved %d netdev(s) from %d /dev/infiniband/uverbs* device(s) in spec: %v", len(out), nUverbs, out)
	}
	return out
}

// isHostPrimaryNetdev returns true if a netdev should NOT be moved because
// it carries host-critical traffic (default route, primary NIC name).
func isHostPrimaryNetdev(name string, defaultRouteIfaces map[string]struct{}) bool {
	if _, ok := defaultRouteIfaces[name]; ok {
		return true
	}
	// Belt-and-braces name check. RDMA fabric NICs are conventionally
	// rdma*, ib*, mlx*, ens* depending on the cloud; eth0..ethN is
	// reserved for primary connectivity.
	if matched, _ := filepath.Match("eth*", name); matched {
		return true
	}
	return false
}

// defaultRouteOifNames returns the set of netdev names that are the egress
// interface for any default (0.0.0.0/0 or ::/0) route in the current netns.
// Errors are swallowed: returning an empty set degrades to the name-pattern
// safety net above, which still blocks the obvious eth0 case.
func defaultRouteOifNames() map[string]struct{} {
	out := map[string]struct{}{}
	links, err := netlink.LinkList()
	if err != nil {
		return out
	}
	idxToName := map[int]string{}
	for _, l := range links {
		idxToName[l.Attrs().Index] = l.Attrs().Name
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return out
	}
	for _, r := range routes {
		// Default routes have a nil/empty Dst.
		if r.Dst == nil || r.Dst.IP == nil || r.Dst.IP.IsUnspecified() {
			if name, ok := idxToName[r.LinkIndex]; ok {
				out[name] = struct{}{}
			}
		}
	}
	return out
}

func readSysfsTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
