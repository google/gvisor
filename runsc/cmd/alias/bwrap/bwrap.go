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
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// generateUID generates a random ID for the runsc container.
func generateUID() string {
	return fmt.Sprintf("runsc-bwrap-%06d", rand.Int31n(1000000))
}

// bwrapConfig represents the configuration for the bwrap sandbox.
type bwrapConfig struct {
	Mounts      []sandbox.Mount
	UnshareNet  bool
	Args        []string
	Chdir       string
	runscConfig *config.Config
	Env         []string
	UnsetEnv    []string
	UID         int
	GID         int
	UnshareUser bool
	Hostname    string
	ShareNet    bool
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

	network := sandbox.NetworkModeHost
	if c.UnshareNet {
		network = sandbox.NetworkModeNone
	}

	opts := []sandbox.Option{
		sandbox.WithID(generateUID()),
		sandbox.WithWorkingDir(cwd),
		sandbox.WithCapabilities(specutils.AllCapabilities()),
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
	opts = append(opts, sandbox.WithNamespaces(namespaces...))

	return opts, nil
}

// do runs the command in a gVisor sandbox and records its exit status.
func do(ctx context.Context, c *bwrapConfig, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	opts, err := c.sandboxOptions()
	if err != nil {
		return util.Errorf("%v", err)
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
