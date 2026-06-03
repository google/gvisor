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

// Package bwrap provides functions for interacting with the bwrap command.
package bwrap

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/specutils"
)

// generateUID generates a random ID for the runsc container.
func generateUID() string {
	return fmt.Sprintf("runsc-bwrap-%06d", rand.Int31n(1000000))
}

// setupWorkspace creates a temporary directory for the bwrap runtime files.
func (c *bwrapConfig) setupWorkspace() (string, error) {
	tmpDir, err := os.MkdirTemp("", "runsc-bwrap-bundle")
	if err != nil {
		return "", fmt.Errorf("creating tmp dir: %v", err)
	}
	log.Infof("bwrap bundle dir: %s", tmpDir)
	return tmpDir, nil
}

// runscDo runs the container; copied from runsc/cmd/do.go.
// TODO: b/508701483 - Use the causeway library when it is ready.
func (c *bwrapConfig) runscDo(spec *specs.Spec, workspaceDir string, conf *config.Config, cid string, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	// Create bundle directory.
	bundleDir := filepath.Join(workspaceDir, "bundle")
	if err := os.Mkdir(bundleDir, 0755); err != nil {
		return util.Errorf("creating bundle dir: %v", err)
	}
	log.Infof("bwrap bundle dir: %s", bundleDir)

	out, err := json.Marshal(spec)
	if err != nil {
		return util.Errorf("marshalling spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), out, 0644); err != nil {
		return util.Errorf("writing config.json: %v", err)
	}

	containerArgs := container.Args{
		ID:        cid,
		Spec:      spec,
		BundleDir: bundleDir,
		Attached:  true, // Run in foreground
	}

	ct, err := container.New(conf, containerArgs)
	if err != nil {
		return util.Errorf("creating container: %v", err)
	}
	defer ct.Destroy()

	if err := ct.Start(conf); err != nil {
		return util.Errorf("starting container: %v", err)
	}

	// Forward signals.
	stopForwarding := ct.ForwardSignals(0 /* pid */, spec.Process.Terminal /* fgProcess */)
	defer stopForwarding()

	ws, err := ct.Wait()
	if err != nil {
		return util.Errorf("waiting for container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}

// do executes the container.
func do(c *bwrapConfig, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	// Create a temporary directory for the bwrap runtime files.
	workspaceDir, err := c.setupWorkspace()
	if err != nil {
		return util.Errorf("failed to setup workspace: %v", err)
	}
	defer os.RemoveAll(workspaceDir)
	c.WorkspaceDir = workspaceDir

	// Build the runsc spec from the bwrap config.

	spec, err := c.buildRunscSpec()
	if err != nil {
		return util.Errorf("failed to build runsc spec: %v", err)
	}

	// Run the container.
	return c.runscDo(spec, c.WorkspaceDir, c.runscConfig, generateUID(), waitStatus)
}

// MountOpType represents the type of mount operation.
type MountOpType string

const (
	// MountOpBind represents a bind mount operation.
	MountOpBind MountOpType = "bind"
	// MountOpRoBind represents a read-only bind mount operation.
	MountOpRoBind MountOpType = "ro-bind"
	// MountOpTmpfs represents a tmpfs mount operation.
	MountOpTmpfs MountOpType = "tmpfs"
)

// MountOp represents a mount operation.
type MountOp struct {
	Type MountOpType
	Src  string
	Dst  string
}

// newMountOp creates a new MountOp struct.
func (c *bwrapConfig) newMountOp(src, dst string, mountType MountOpType) (*MountOp, error) {
	if dst == "" {
		return nil, fmt.Errorf("bwrap: destination path is empty")
	}
	dst = filepath.Clean(dst)
	if mountType == MountOpTmpfs {
		return &MountOp{
			Type: mountType,
			Dst:  dst,
		}, nil
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return nil, fmt.Errorf("bwrap: Can't get absolute path for source path %v: %v", src, err)
	}
	if _, err := os.Stat(src); err != nil {
		return nil, fmt.Errorf("bwrap: Can't find source path %v: %v", absSrc, err)
	}
	return &MountOp{
		Type: mountType,
		Src:  absSrc,
		Dst:  dst,
	}, nil
}

// bwrapConfig represents the configuration for the bwrap sandbox.
type bwrapConfig struct {
	Mounts       []*MountOp
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
	ProcDest     map[string]struct{}
}

// String returns a string representation of the bwrapConfig.
func (c *bwrapConfig) String() string {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal bwrapConfig to JSON: %v", err))
	}
	return string(j)
}

// getRootMount returns the root mount if it exists.
func (c *bwrapConfig) getRootMount() (r *MountOp, ok bool) {
	for _, m := range c.Mounts {
		if m.Dst == "/" {
			return m, true
		}
	}
	return nil, false
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
		if m.Src == "" {
			continue
		}
		if path, ok := c.subDirPath(m.Src, cwd); ok {
			return filepath.Join(m.Dst, strings.TrimPrefix(path, m.Src)), nil
		}
	}
	return "/", nil
}

// buildRunscSpec builds the runsc Spec from the bwrapConfig.
// TODO: b/508701483 - Use the causeway library when it is ready
// and update this function.
func (c *bwrapConfig) buildRunscSpec() (*specs.Spec, error) {
	if c.UID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --uid requires --unshare-user")
	}

	if c.GID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --gid requires --unshare-user")
	}

	spec := &specs.Spec{}
	// Find what the current working directory should be in the sandbox.
	cwd, err := c.mapCWD()
	if err != nil {
		return nil, fmt.Errorf("failed to map current working directory: %v", err)
	}
	spec.Process = &specs.Process{
		Cwd:          cwd,
		Args:         c.Args,
		Env:          c.Env,
		Capabilities: specutils.AllCapabilities(),
	}

	c.setupUserNamespace(spec)

	rootMount, rootMountPresent := c.getRootMount()
	if rootMountPresent {
		// If a root mount is specified, use it as the root.
		spec.Root = &specs.Root{
			Path:     rootMount.Src,
			Readonly: rootMount.Type == MountOpRoBind,
		}
	} else {
		// If no root mount is specified, use a tmpfs root.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/",
			Type:        "tmpfs",
		})
		// Set the root path to the workspace directory.
		spec.Root = &specs.Root{
			Path:     c.WorkspaceDir,
			Readonly: false,
		}
	}

	// Add default mounts. Copied from sandboxexec.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/proc",
		Type:        "proc",
	}, specs.Mount{
		Destination: "/sys",
		Type:        "sysfs",
	}, specs.Mount{
		Destination: "/dev",
		Type:        "devtmpfs",
	}, specs.Mount{
		Destination: "/dev/pts",
		Type:        "devpts",
	}, specs.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroupfs",
	}, specs.Mount{
		Destination: "/tmp",
		Type:        "tmpfs",
	})

	for _, mount := range c.Mounts {
		var opts []string
		if mount.Src == "/" {
			opts = []string{"rbind", "rprivate", "nosuid", "nodev"}
		}
		if mount.Type == MountOpRoBind {
			opts = append(opts, "ro")
		}
		switch mount.Type {
		case MountOpBind:
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Type:        "bind",
				Source:      mount.Src,
				Destination: mount.Dst,
				Options:     opts,
			})
		case MountOpRoBind:
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Type:        "bind",
				Source:      mount.Src,
				Destination: mount.Dst,
				Options:     opts,
			})
		case MountOpTmpfs:
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Type:        "tmpfs",
				Destination: mount.Dst,
				Options:     opts,
			})
		}
	}

	if c.Hostname != "" {
		spec.Hostname = c.Hostname
	}

	// TODO: b/508701483 - Fix support for network args.
	if c.UnshareNet {
		if spec.Linux == nil {
			spec.Linux = &specs.Linux{}
		}
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}

	// Add proc mounts.
	for procDest := range c.ProcDest {
		if procDest == "/proc" {
			continue
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "proc",
			Destination: procDest,
		})
	}

	// Set the current working directory.
	spec.Process.Cwd = cwd
	return spec, nil
}

// setupUserNamespace configures the user namespace, UID/GID mappings, and process user in the Spec.
func (c *bwrapConfig) setupUserNamespace(spec *specs.Spec) {
	if c.UnshareUser {
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
		spec.Process.User = specs.User{
			UID: uint32(targetUID),
			GID: uint32(targetGID),
		}
		if spec.Linux == nil {
			spec.Linux = &specs.Linux{}
		}

		// When running under sudo (e.g. in CI tests), SUDO_UID/SUDO_GID point to the true non-root workspace owner.
		// When running without sudo, they gracefully fallback to the current host UID/GID.
		sudoUID := getEnvInt("SUDO_UID", hostUID)
		sudoGID := getEnvInt("SUDO_GID", hostGID)

		spec.Linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: uint32(targetUID), HostID: uint32(sudoUID), Size: 1},
		}
		spec.Linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: uint32(targetGID), HostID: uint32(sudoGID), Size: 1},
		}

		// When runsc is executed by root (hostUID == 0), gVisor's Gofer initialization requires Container 0:0
		// to be mapped to Host 0:0 so the Gofer process can successfully call setuid(0)/setgid(0).
		if hostUID == 0 {
			if targetUID != 0 {
				spec.Linux.UIDMappings = append(spec.Linux.UIDMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
			}
			if targetGID != 0 {
				spec.Linux.GIDMappings = append(spec.Linux.GIDMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
			}
		}

		spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		return
	}

	if c.UID != -1 || c.GID != -1 {
		spec.Process.User = specs.User{}
		if c.UID != -1 {
			spec.Process.User.UID = uint32(c.UID)
		}
		if c.GID != -1 {
			spec.Process.User.GID = uint32(c.GID)
		}
	}
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
