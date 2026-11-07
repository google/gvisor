// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Under the sandbox API, containerd leaves the pod's hostname, hosts and
// resolv.conf files to the sandboxer: it creates them only in its podsandbox
// controller (setupSandboxFiles), and mounts them into a container only if
// they exist ("could be delegated to remote sandbox controller",
// internal/cri/server/container_create.go). So the shim creates them in the
// sandbox bundle, and mounts them into each container.

// sandboxFiles are the files the shim creates in the sandbox bundle, and the
// container paths they are mounted on.
var sandboxFiles = []struct {
	name string
	dest string
}{
	{name: "hostname", dest: "/etc/hostname"},
	{name: "hosts", dest: "/etc/hosts"},
	{name: "resolv.conf", dest: "/etc/resolv.conf"},
}

// writeSandboxFiles writes the pod's hostname, hosts and resolv.conf files in
// bundle, as containerd's podsandbox controller does.
func writeSandboxFiles(bundle string, config *podSandboxConfig) error {
	hostname := config.hostname
	if hostname == "" {
		var err error
		if hostname, err = os.Hostname(); err != nil {
			return fmt.Errorf("get hostname: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundle, "hostname"), []byte(hostname+"\n"), 0644); err != nil {
		return err
	}
	if err := copyFile("/etc/hosts", filepath.Join(bundle, "hosts")); err != nil {
		return err
	}
	resolv := filepath.Join(bundle, "resolv.conf")
	if config.dns == nil {
		// containerd uses the host's file then too.
		return copyFile("/etc/resolv.conf", resolv)
	}
	return os.WriteFile(resolv, []byte(resolvConf(config.dns)), 0644)
}

// resolvConf returns the resolv.conf contents for dns, in the format of
// containerd's parseDNSOptions.
func resolvConf(dns *podDNSConfig) string {
	var b strings.Builder
	if len(dns.searches) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(dns.searches, " "))
	}
	for _, server := range dns.servers {
		fmt.Fprintf(&b, "nameserver %s\n", server)
	}
	if len(dns.options) > 0 {
		fmt.Fprintf(&b, "options %s\n", strings.Join(dns.options, " "))
	}
	return b.String()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// addSandboxFileMounts mounts the files in sandboxBundle on the paths where s
// has no mount yet, with the options CRI uses for them. It reports whether it
// changed s.
func addSandboxFileMounts(s *specs.Spec, sandboxBundle string) bool {
	access := "rw"
	if s.Root != nil && s.Root.Readonly {
		access = "ro"
	}
	changed := false
	for _, f := range sandboxFiles {
		if hasMount(s, f.dest) {
			continue
		}
		src := filepath.Join(sandboxBundle, f.name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		s.Mounts = append(s.Mounts, specs.Mount{
			Destination: f.dest,
			Type:        "bind",
			Source:      src,
			Options:     []string{"rbind", "rprivate", access},
		})
		changed = true
	}
	return changed
}

// mountSandboxFiles mounts the sandbox's files into the spec of a CRI
// container that lacks them, and reports whether it changed s. Under
// containerd's podsandbox controller, CRI always mounts them, so this does
// nothing there.
func mountSandboxFiles(ctx context.Context, runtime *runsccmd.Runsc, s *specs.Spec) bool {
	if specutils.SpecContainerType(s) != specutils.ContainerTypeContainer || !needsSandboxFiles(s) {
		return false
	}
	sandboxID, ok := specutils.SandboxID(s)
	if !ok {
		return false
	}
	// The container's shim may not be the sandbox's, so ask runsc where the
	// sandbox bundle is.
	sandbox, err := runtime.State(ctx, sandboxID)
	if err != nil {
		log.L.Warningf("Looking up sandbox %q for its hostname, hosts and resolv.conf: %v", sandboxID, err)
		return false
	}
	return addSandboxFileMounts(s, sandbox.Bundle)
}

// needsSandboxFiles reports whether s lacks a mount for any sandbox file.
func needsSandboxFiles(s *specs.Spec) bool {
	for _, f := range sandboxFiles {
		if !hasMount(s, f.dest) {
			return true
		}
	}
	return false
}

func hasMount(s *specs.Spec, dest string) bool {
	for _, m := range s.Mounts {
		if filepath.Clean(m.Destination) == dest {
			return true
		}
	}
	return false
}
