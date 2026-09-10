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

// Package bwrap implements a bubblewrap-compatible command line for running
// commands in a gVisor sandbox.
package bwrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// generateUID generates a random ID for the runsc container.
// The ID must not exceed 12 characters so that virtual network interface
// names ("ve-" + cid or "vp-" + cid) do not exceed Linux's 15-character
// limit (IFNAMSIZ - 1).
func generateUID() string {
	return fmt.Sprintf("runsc-%06d", rand.Int31n(1000000))
}

// CapOpType represents the type of capability operation.
type CapOpType string

const (
	// CapOpDrop represents a capability drop operation.
	CapOpDrop CapOpType = "drop"
	// CapOpAdd represents a capability add operation.
	CapOpAdd CapOpType = "add"
)

// CapOp represents a capability operation.
type CapOp struct {
	Type CapOpType
	Cap  string
}

// bwrapConfig represents the configuration for the bwrap sandbox.
type bwrapConfig struct {
	Mounts       []sandbox.Mount
	CapOps       []*CapOp
	UnshareNet   bool
	Args         []string
	Chdir        string
	WorkspaceDir string
	runscConfig  *config.Config
	Env          []string
	UnsetEnv     []string
	UID          int
	GID          int
	UnshareUser  bool
	Hostname     string
	ip           string
	cleanNet     func()
}

// String returns a string representation of the bwrapConfig.
func (c *bwrapConfig) String() string {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal bwrapConfig to JSON: %v", err))
	}
	return string(j)
}

// defaultMounts are the filesystems bwrap provides in every sandbox.
func defaultMounts() []sandbox.Mount {
	return []sandbox.Mount{
		{Destination: "/proc", Type: sandbox.MountTypeProc},
		{Destination: "/sys", Type: sandbox.MountTypeSysfs},
		{Destination: "/dev", Type: sandbox.MountTypeDevtmpfs},
		{Destination: "/dev/pts", Type: sandbox.MountTypeDevpts},
		{Destination: "/sys/fs/cgroup", Type: sandbox.MountTypeCgroup},
		{Destination: "/tmp", Type: sandbox.MountTypeTmpfs},
	}
}

// newMount creates a mount for the sandbox bindings.
func (c *bwrapConfig) newMount(src, dst string, mountType sandbox.MountType, readOnly bool) (sandbox.Mount, error) {
	if dst == "" {
		return sandbox.Mount{}, fmt.Errorf("bwrap: destination path is empty")
	}
	dst = filepath.Clean(dst)
	if mountType != sandbox.MountTypeBind {
		return sandbox.Mount{Type: mountType, Destination: dst}, nil
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return sandbox.Mount{}, fmt.Errorf("bwrap: Can't get absolute path for source path %v: %v", src, err)
	}
	if _, err := os.Stat(src); err != nil {
		return sandbox.Mount{}, fmt.Errorf("bwrap: Can't find source path %v: %v", absSrc, err)
	}
	m := sandbox.Mount{
		Type:        sandbox.MountTypeBind,
		Source:      absSrc,
		Destination: dst,
		ReadOnly:    readOnly,
	}
	if absSrc == "/" {
		m.Recursive, m.Private, m.NoSuid, m.NoDev = true, true, true, true
	}
	return m, nil
}

// getRootMount returns the root mount if it exists.
func (c *bwrapConfig) getRootMount() (sandbox.Mount, bool) {
	for _, m := range c.Mounts {
		if m.Destination == "/" {
			return m, true
		}
	}
	return sandbox.Mount{}, false
}

// subDirPath returns the absolute path of a child path
// if it is a subpath of the parent path.
func (c *bwrapConfig) subDirPath(parent, child string) (string, bool) {
	// Empty paths are not valid.
	if parent == "" || child == "" {
		return "", false
	}
	splitFunc := func(c rune) bool {
		return c == filepath.Separator
	}
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return "", false
	}
	parentParts := strings.FieldsFunc(absParent, splitFunc)

	absChild, err := filepath.Abs(child)
	if err != nil {
		return "", false
	}
	childParts := strings.FieldsFunc(absChild, splitFunc)

	if len(childParts) < len(parentParts) {
		return "", false
	}
	for i := 0; i < len(parentParts); i++ {
		if parentParts[i] != childParts[i] {
			return "", false
		}
	}
	return filepath.Join(parent, filepath.Join(childParts[len(parentParts):]...)), true
}

// mapCWD maps the current working directory to the sandbox directory.
// Follows similar logic as bwrap.
func (c *bwrapConfig) mapCWD() (string, error) {
	cwd := ""
	if c.Chdir != "" {
		cwd = c.Chdir
	} else {
		hostCWD, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %v", err)
		}
		cwd = hostCWD
	}
	for _, m := range c.Mounts {
		if m.Source == "" {
			continue
		}
		if path, ok := c.subDirPath(m.Source, cwd); ok {
			return filepath.Join(m.Destination, strings.TrimPrefix(path, m.Source)), nil
		}
	}
	return "/", nil
}

// userNamespace returns the namespace and the user options implied by
// --unshare-user, --uid and --gid.
func (c *bwrapConfig) userNamespace() []sandbox.Option {
	hostUID := os.Getuid()
	targetUID := hostUID
	if c.UID != -1 {
		targetUID = c.UID
	}
	hostGID := os.Getgid()
	targetGID := hostGID
	if c.GID != -1 {
		targetGID = c.GID
	}

	// When running under sudo (e.g. in CI tests), SUDO_UID/SUDO_GID point to the true non-root workspace owner.
	// When running without sudo, they gracefully fallback to the current host UID/GID.
	sudoUID := getEnvInt("SUDO_UID", hostUID)
	sudoGID := getEnvInt("SUDO_GID", hostGID)

	uidMappings := []specs.LinuxIDMapping{
		{ContainerID: uint32(targetUID), HostID: uint32(sudoUID), Size: 1},
	}
	gidMappings := []specs.LinuxIDMapping{
		{ContainerID: uint32(targetGID), HostID: uint32(sudoGID), Size: 1},
	}

	// When runsc is executed by root (hostUID == 0), gVisor's Gofer initialization requires Container 0:0
	// to be mapped to Host 0:0 so the Gofer process can successfully call setuid(0)/setgid(0).
	// TODO(gvisor.dev/issue/13747): Have the sandbox bindings add the 0:0 mapping for root sandboxes with a user namespace.
	if hostUID == 0 {
		if targetUID != 0 {
			uidMappings = append(uidMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
		}
		if targetGID != 0 {
			gidMappings = append(gidMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
		}
	}

	return []sandbox.Option{
		sandbox.WithUser(uint32(targetUID), uint32(targetGID)),
		sandbox.WithIDMappings(uidMappings, gidMappings),
	}
}

// sandboxOptions translates the parsed bubblewrap configuration into options
// for the sandbox bindings.
func (c *bwrapConfig) sandboxOptions() ([]sandbox.Option, error) {
	if c.UID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --uid requires --unshare-user")
	}
	if c.GID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --gid requires --unshare-user")
	}

	cwd, err := c.mapCWD()
	if err != nil {
		return nil, fmt.Errorf("failed to map current working directory: %v", err)
	}

	cid := generateUID()
	network := sandbox.NetworkModeSandbox
	var netns specs.LinuxNamespace

	if c.UnshareNet {
		network = sandbox.NetworkModeNone
	} else if os.Geteuid() != 0 {
		// Non-root users cannot configure veth devices or iptables on the host.
		// Fall back to host network mode, matching runsc do and real bubblewrap.
		network = sandbox.NetworkModeHost
	} else {
		ns, clean, err := c.setupNet(cid)
		switch err {
		case errNoDefaultInterface:
			log.Warningf("Network interface not found, using internal network")
			network = sandbox.NetworkModeNone
		case nil:
			c.cleanNet = clean
			netns = ns
		default:
			return nil, fmt.Errorf("error setting up network: %v", err)
		}
	}

	opts := []sandbox.Option{
		sandbox.WithID(cid),
		sandbox.WithWorkingDir(cwd),
		// A bubblewrap sandbox holds only what the command line asks for.
		sandbox.WithoutLinuxSystemMounts(),
		sandbox.WithoutHostBinaryMounts(),
		sandbox.WithoutBaseEnv(),
		sandbox.WithEnv(c.Env...),
		// TODO: b/508701483 - Fix support for network args.
		sandbox.WithNetwork(network),
	}
	opts = append(opts,
		sandbox.WithStateDir(c.runscConfig.RootDir),
	)
	if c.runscConfig.Debug {
		opts = append(opts, sandbox.WithDebug(c.runscConfig.DebugLog))
	}
	if c.Hostname != "" {
		opts = append(opts, sandbox.WithHostname(c.Hostname))
	}

	var mounts []sandbox.Mount
	if rootMount, ok := c.getRootMount(); ok {
		opts = append(opts, sandbox.WithRootfs(rootMount.Source, rootMount.ReadOnly))
	} else {
		mounts = append(mounts, sandbox.Mount{Destination: "/", Type: sandbox.MountTypeTmpfs})
	}
	mounts = append(mounts, defaultMounts()...)
	mounts = append(mounts, c.Mounts...)
	opts = append(opts, sandbox.WithMount(mounts...))

	var namespaces []specs.LinuxNamespace
	if c.UnshareUser {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		opts = append(opts, c.userNamespace()...)
	}
	if netns.Path != "" {
		namespaces = append(namespaces, netns)
	}
	opts = append(opts, sandbox.WithNamespaces(namespaces...))

	caps := specutils.AllCapabilities()
	for _, capOp := range c.CapOps {
		normCap, err := normalizeCap(capOp.Cap)
		if err != nil {
			return nil, err
		}
		switch capOp.Type {
		case CapOpAdd:
			addCapability(caps, normCap)
		case CapOpDrop:
			dropCapability(caps, normCap)
		}
	}
	opts = append(opts, sandbox.WithCapabilities(caps))

	return opts, nil
}

// do runs the command in a gVisor sandbox and records its exit status.
func do(ctx context.Context, c *bwrapConfig, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	opts, err := c.sandboxOptions()
	if err != nil {
		return util.Errorf("%v", err)
	}
	if c.cleanNet != nil {
		defer c.cleanNet()
	}
	// Configure the sandbox to invoke the current runsc executable.
	if err := os.Setenv(sandbox.RunscPathEnvVar, specutils.ExePath); err != nil {
		return util.Errorf("bwrap: %v", err)
	}

	sb, err := sandbox.New(ctx, opts...)
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			log.Warningf("bwrap: failed to clean up sandbox: %v", err)
		}
	}()

	res, err := sb.Exec(ctx, c.Args,
		sandbox.WithExecStdio(os.Stdin, os.Stdout, os.Stderr),
		sandbox.WithExecSignalRelay())
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	*waitStatus = unix.WaitStatus(res.ExitCode << 8)
	return subcommands.ExitSuccess
}

// getEnvInt parses an environment variable as an integer, returning fallback if empty or invalid.
func getEnvInt(key string, fallback int) int {
	if s := os.Getenv(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return fallback
}

func (c *bwrapConfig) resolveEnv() {
	var env []string
	for _, e := range c.Env {
		if strings.Contains(e, "=") {
			env = append(env, e)
		}
	}
	for _, e := range c.UnsetEnv {
		for i, v := range env {
			if strings.HasPrefix(v, e+"=") {
				env = append(env[:i], env[i+1:]...)
				break
			}
		}
	}
	c.Env = env
}

// normalizeCap normalizes a capability name to uppercase and prepends "CAP_"
// if necessary. "ALL" is treated as a special CLI keyword and returned as-is.
func normalizeCap(capName string) (string, error) {
	normCap := strings.ToUpper(strings.TrimSpace(capName))
	if normCap != "ALL" {
		if !strings.HasPrefix(normCap, "CAP_") {
			normCap = "CAP_" + normCap
		}
		if !isKnownCapability(normCap) {
			return "", fmt.Errorf("bwrap: unknown cap: %s", capName)
		}
	}
	return normCap, nil
}

// isKnownCapability checks if capName is a valid Linux capability known to gVisor.
func isKnownCapability(capName string) bool {
	for _, c := range specutils.AllCapabilities().Bounding {
		if c == capName {
			return true
		}
	}
	return false
}

// addCapability adds a single capability to all 5 capability sets.
// This is used by bwrap to support re-adding capabilities after --cap-drop ALL.
func addCapability(caps *specs.LinuxCapabilities, capName string) {
	addUnique := func(set []string) []string {
		for _, c := range set {
			if c == capName {
				return set
			}
		}
		return append(set, capName)
	}
	caps.Bounding = addUnique(caps.Bounding)
	caps.Effective = addUnique(caps.Effective)
	caps.Inheritable = addUnique(caps.Inheritable)
	caps.Permitted = addUnique(caps.Permitted)
	caps.Ambient = addUnique(caps.Ambient)
}

// dropCapability removes a capability from all 5 capability sets.
//
// If capName is "ALL" (a CLI keyword for --cap-drop ALL), all capability
// sets are cleared. This logic is kept in bwrap rather than specutils because
// "ALL" is not a valid Linux capability name, and bwrap uniquely supports
// dropping all capabilities and subsequently re-adding specific ones via --cap-add.
func dropCapability(caps *specs.LinuxCapabilities, capName string) {
	if capName == "ALL" {
		caps.Bounding = nil
		caps.Effective = nil
		caps.Inheritable = nil
		caps.Permitted = nil
		caps.Ambient = nil
		return
	}
	specutils.DropCapability(caps, capName)
}

func defaultDevice() (string, error) {
	out, err := exec.Command("ip", "route", "list", "default").CombinedOutput()
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) < 5 {
		return "", fmt.Errorf("malformed %q output: %q", "ip route list default", string(out))
	}
	return parts[4], nil
}

func deviceMTU(dev string) (int, error) {
	intf, err := net.InterfaceByName(dev)
	if err != nil {
		return 0, err
	}
	return intf.MTU, nil
}

func calculatePeerIP(ip string) (string, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP format %q", ip)
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", fmt.Errorf("invalid IP format %q: %v", ip, err)
	}
	n++
	if n > 255 {
		n = 1
	}
	return fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], n), nil
}

func deviceNames(cid string) (string, string) {
	// Device name is limited to 15 letters.
	return "ve-" + cid, "vp-" + cid
}

func (c *bwrapConfig) makeFile(dest, content string) (string, error) {
	tmpFile, err := os.CreateTemp("", filepath.Base(dest))
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	if _, err := tmpFile.WriteString(content); err != nil {
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Warningf("Failed to remove %q: %v", tmpFile.Name(), err)
		}
		return "", err
	}
	c.Mounts = append(c.Mounts, sandbox.Mount{
		Source:      tmpFile.Name(),
		Destination: dest,
		Type:        sandbox.MountTypeBind,
		ReadOnly:    true,
	})
	return tmpFile.Name(), nil
}

func tryRemove(path string) {
	if path == "" {
		return
	}

	if err := os.Remove(path); err != nil {
		log.Warningf("Failed to remove %q: %v", path, err)
	}
}

// errNoDefaultInterface is returned when no default network interface is found
var errNoDefaultInterface = errors.New("no default interface found")

// cleanupNet tries to cleanup the network setup in setupNet.
//
// It may be called when setupNet is only partially complete, in which case it
// will cleanup as much as possible, logging warnings for the rest.
//
// Unfortunately none of this can be automatically cleaned up on process exit,
// we must do so explicitly.
func (c *bwrapConfig) cleanupNet(cid, dev, resolvPath, hostnamePath, hostsPath string) {
	_, peer := deviceNames(cid)
	ip := c.ip

	cmds := []string{
		fmt.Sprintf("ip link delete %s", peer),
		fmt.Sprintf("ip netns delete %s", cid),
		fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -m comment --comment runsc-%s -j MASQUERADE", ip, dev, peer),
		fmt.Sprintf("iptables -D FORWARD -i %s -o %s -j ACCEPT", dev, peer),
		fmt.Sprintf("iptables -D FORWARD -o %s -i %s -j ACCEPT", dev, peer),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Fields(cmd)
		execCmd := exec.Command(args[0], args[1:]...)
		if err := execCmd.Run(); err != nil {
			log.Warningf("Failed to run %q: %v", cmd, err)
		}
	}

	tryRemove(resolvPath)
	tryRemove(hostnamePath)
	tryRemove(hostsPath)
}

// setupNet setups up the sandbox network, including the creation of a network
// namespace, and iptable rules to redirect the traffic. Returns a cleanup
// function to tear down the network. Returns errNoDefaultInterface when there
// is no network interface available to setup the network.
func (c *bwrapConfig) setupNet(cid string) (specs.LinuxNamespace, func(), error) {
	if c.ip == "" {
		randSubnet := 10 + rand.Int31n(245)
		c.ip = fmt.Sprintf("192.168.%d.2", randSubnet)
	}
	ip := c.ip
	dev, err := defaultDevice()
	if err != nil {
		return specs.LinuxNamespace{}, nil, errNoDefaultInterface
	}
	mtu, err := deviceMTU(dev)
	if err != nil {
		return specs.LinuxNamespace{}, nil, err
	}
	peerIP, err := calculatePeerIP(ip)
	if err != nil {
		return specs.LinuxNamespace{}, nil, err
	}
	veth, peer := deviceNames(cid)

	cmds := []string{
		fmt.Sprintf("ip link add %s mtu %v type veth peer name %s", veth, mtu, peer),

		// Setup device outside the namespace.
		fmt.Sprintf("ip addr add %s/24 dev %s", peerIP, peer),
		fmt.Sprintf("ip link set %s up", peer),

		// Setup device inside the namespace.
		fmt.Sprintf("ip netns add %s", cid),
		fmt.Sprintf("ip link set %s netns %s", veth, cid),
		fmt.Sprintf("ip netns exec %s ip addr add %s/24 dev %s", cid, ip, veth),
		fmt.Sprintf("ip netns exec %s ip link set %s up", cid, veth),
		fmt.Sprintf("ip netns exec %s ip link set lo up", cid),
		fmt.Sprintf("ip netns exec %s ip route add default via %s", cid, peerIP),

		// Enable network access.
		"sysctl -w net.ipv4.ip_forward=1",
		fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -m comment --comment runsc-%s -j MASQUERADE", ip, dev, peer),
		fmt.Sprintf("iptables -A FORWARD -i %s -o %s -j ACCEPT", dev, peer),
		fmt.Sprintf("iptables -A FORWARD -o %s -i %s -j ACCEPT", dev, peer),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Fields(cmd)
		execCmd := exec.Command(args[0], args[1:]...)
		if err := execCmd.Run(); err != nil {
			c.cleanupNet(cid, dev, "", "", "")
			return specs.LinuxNamespace{}, nil, fmt.Errorf("failed to run %q: %v", cmd, err)
		}
	}

	resolvPath, err := c.makeFile("/etc/resolv.conf", "nameserver 8.8.8.8\n")
	if err != nil {
		c.cleanupNet(cid, dev, "", "", "")
		return specs.LinuxNamespace{}, nil, err
	}
	hostnamePath, err := c.makeFile("/etc/hostname", cid+"\n")
	if err != nil {
		c.cleanupNet(cid, dev, resolvPath, "", "")
		return specs.LinuxNamespace{}, nil, err
	}
	hosts := fmt.Sprintf("127.0.0.1\tlocalhost\n%s\t%s\n", ip, cid)
	hostsPath, err := c.makeFile("/etc/hosts", hosts)
	if err != nil {
		c.cleanupNet(cid, dev, resolvPath, hostnamePath, "")
		return specs.LinuxNamespace{}, nil, err
	}

	netns := specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: filepath.Join("/var/run/netns", cid),
	}

	return netns, func() { c.cleanupNet(cid, dev, resolvPath, hostnamePath, hostsPath) }, nil
}
