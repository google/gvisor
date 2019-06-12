// Copyright 2018 The gVisor Authors.
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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Do implements subcommands.Command for the "do" command. It sets up a simple
// sandbox and executes the command inside it. See Usage() for more details.
type Do struct {
	root string
	cwd  string
	ip   string
}

// Name implements subcommands.Command.Name.
func (*Do) Name() string {
	return "do"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Do) Synopsis() string {
	return "Simplistic way to execute a command inside the sandbox. It's to be used for testing only."
}

// Usage implements subcommands.Command.Usage.
func (*Do) Usage() string {
	return `do [flags] <cmd> - runs a command.

This command starts a sandbox with host filesystem mounted inside as readonly,
with a writable tmpfs overlay on top of it. The given command is executed inside
the sandbox. It's to be used to quickly test applications without having to
install or run docker. It doesn't give nearly as many options and it's to be
used for testing only.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Do) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.root, "root", "/", `path to the root directory, defaults to "/"`)
	f.StringVar(&c.cwd, "cwd", ".", "path to the current directory, defaults to the current directory")
	f.StringVar(&c.ip, "ip", "192.168.10.2", "IPv4 address for the sandbox")
}

// Execute implements subcommands.Command.Execute.
func (c *Do) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		c.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	if conf.Rootless {
		if err := specutils.MaybeRunAsRoot(); err != nil {
			return Errorf("Error executing inside namespace: %v", err)
		}
		// Execution will continue here if no more capabilities are needed...
	}

	hostname, err := os.Hostname()
	if err != nil {
		return Errorf("Error to retrieve hostname: %v", err)
	}

	// Map the entire host file system, but make it readonly with a writable
	// overlay on top (ignore --overlay option).
	conf.Overlay = true
	absRoot, err := resolvePath(c.root)
	if err != nil {
		return Errorf("Error resolving root: %v", err)
	}
	absCwd, err := resolvePath(c.cwd)
	if err != nil {
		return Errorf("Error resolving current directory: %v", err)
	}

	spec := &specs.Spec{
		Root: &specs.Root{
			Path: absRoot,
		},
		Process: &specs.Process{
			Cwd:          absCwd,
			Args:         f.Args(),
			Env:          os.Environ(),
			Capabilities: specutils.AllCapabilities(),
		},
		Hostname: hostname,
	}

	specutils.LogSpec(spec)

	cid := fmt.Sprintf("runsc-%06d", rand.Int31n(1000000))
	if conf.Network == boot.NetworkNone {
		netns := specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
		}
		if spec.Linux != nil {
			panic("spec.Linux is not nil")
		}
		spec.Linux = &specs.Linux{Namespaces: []specs.LinuxNamespace{netns}}

	} else if conf.Rootless {
		if conf.Network == boot.NetworkSandbox {
			fmt.Println("*** Rootless requires changing network type to host ***")
			conf.Network = boot.NetworkHost
		}

	} else {
		clean, err := c.setupNet(cid, spec)
		if err != nil {
			return Errorf("Error setting up network: %v", err)
		}
		defer clean()
	}

	out, err := json.Marshal(spec)
	if err != nil {
		return Errorf("Error to marshal spec: %v", err)
	}
	tmpDir, err := ioutil.TempDir("", "runsc-do")
	if err != nil {
		return Errorf("Error to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Infof("Changing configuration RootDir to %q", tmpDir)
	conf.RootDir = tmpDir

	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := ioutil.WriteFile(cfgPath, out, 0755); err != nil {
		return Errorf("Error write spec: %v", err)
	}

	ws, err := container.Run(cid, spec, conf, tmpDir, "", "", "", false)
	if err != nil {
		return Errorf("running container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}

func resolvePath(path string) (string, error) {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %v", path, err)
	}
	path = filepath.Clean(path)
	if err := syscall.Access(path, 0); err != nil {
		return "", fmt.Errorf("unable to access %q: %v", path, err)
	}
	return path, nil
}

func (c *Do) setupNet(cid string, spec *specs.Spec) (func(), error) {
	dev, err := defaultDevice()
	if err != nil {
		return nil, err
	}
	peerIP, err := calculatePeerIP(c.ip)
	if err != nil {
		return nil, err
	}
	veth, peer := deviceNames(cid)

	cmds := []string{
		fmt.Sprintf("ip link add %s type veth peer name %s", veth, peer),

		// Setup device outside the namespace.
		fmt.Sprintf("ip addr add %s/24 dev %s", peerIP, peer),
		fmt.Sprintf("ip link set %s up", peer),

		// Setup device inside the namespace.
		fmt.Sprintf("ip netns add %s", cid),
		fmt.Sprintf("ip link set %s netns %s", veth, cid),
		fmt.Sprintf("ip netns exec %s ip addr add %s/24 dev %s", cid, c.ip, veth),
		fmt.Sprintf("ip netns exec %s ip link set %s up", cid, veth),
		fmt.Sprintf("ip netns exec %s ip link set lo up", cid),
		fmt.Sprintf("ip netns exec %s ip route add default via %s", cid, peerIP),

		// Enable network access.
		"sysctl -w net.ipv4.ip_forward=1",
		fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", c.ip, dev),
		fmt.Sprintf("iptables -A FORWARD -i %s -o %s -j ACCEPT", dev, peer),
		fmt.Sprintf("iptables -A FORWARD -o %s -i %s -j ACCEPT", dev, peer),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Split(cmd, " ")
		c := exec.Command(args[0], args[1:]...)
		if err := c.Run(); err != nil {
			return nil, fmt.Errorf("failed to run %q: %v", cmd, err)
		}
	}

	if err := makeFile("/etc/resolv.conf", "nameserver 8.8.8.8\n", spec); err != nil {
		return nil, err
	}
	if err := makeFile("/etc/hostname", cid+"\n", spec); err != nil {
		return nil, err
	}
	hosts := fmt.Sprintf("127.0.0.1\tlocalhost\n%s\t%s\n", c.ip, cid)
	if err := makeFile("/etc/hosts", hosts, spec); err != nil {
		return nil, err
	}

	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	netns := specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: filepath.Join("/var/run/netns", cid),
	}
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, netns)

	return func() { c.cleanNet(cid, dev) }, nil
}

func (c *Do) cleanNet(cid, dev string) {
	veth, peer := deviceNames(cid)

	cmds := []string{
		fmt.Sprintf("ip link delete %s", peer),
		fmt.Sprintf("ip netns delete %s", cid),

		fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s/24 -o %s -j MASQUERADE", c.ip, dev),
		fmt.Sprintf("iptables -D FORWARD -i %s -o %s -j ACCEPT", dev, veth),
		fmt.Sprintf("iptables -D FORWARD -o %s -i %s -j ACCEPT", dev, veth),
	}

	for _, cmd := range cmds {
		log.Debugf("Run %q", cmd)
		args := strings.Split(cmd, " ")
		c := exec.Command(args[0], args[1:]...)
		if err := c.Run(); err != nil {
			log.Warningf("Failed to run %q: %v", cmd, err)
		}
	}
}

func deviceNames(cid string) (string, string) {
	// Device name is limited to 15 letters.
	return "ve-" + cid, "vp-" + cid

}

func defaultDevice() (string, error) {
	out, err := exec.Command("ip", "route", "list", "default").CombinedOutput()
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(out), " ")
	if len(parts) < 5 {
		return "", fmt.Errorf("malformed %q output: %q", "ip route list default", string(out))
	}
	return parts[4], nil
}

func makeFile(dest, content string, spec *specs.Spec) error {
	tmpFile, err := ioutil.TempFile("", filepath.Base(dest))
	if err != nil {
		return err
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		return err
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      tmpFile.Name(),
		Destination: dest,
		Type:        "bind",
		Options:     []string{"ro"},
	})
	return nil
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
