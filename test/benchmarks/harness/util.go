// Copyright 2020 The gVisor Authors.
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

package harness

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

//TODO(gvisor.dev/issue/3535): move to own package or move methods to harness struct.

// WaitUntilContainerServing grabs a container from `machine` and waits for a server on
// the given container and port.
func WaitUntilContainerServing(ctx context.Context, machine Machine, container *dockerutil.Container, port int) error {
	var logger testutil.DefaultLogger = "util"
	netcat := machine.GetNativeContainer(ctx, logger)
	defer netcat.CleanUp(ctx)

	cmd := fmt.Sprintf("while ! wget -q --spider http://%s:%d; do true; done", "server", port)
	_, err := netcat.Run(ctx, dockerutil.RunOpts{
		Image: "benchmarks/util",
		Links: []string{container.MakeLink("server")},
	}, "sh", "-c", cmd)
	return err
}

// DropCaches drops caches on the provided machine. Requires root.
func DropCaches(machine Machine) error {
	if out, err := machine.RunCommand("/bin/sh", "-c", "sync && sysctl vm.drop_caches=3"); err != nil {
		return fmt.Errorf("failed to drop caches: %v logs: %s", err, out)
	}
	return nil
}

// DebugLog prints debug messages if the debug flag is set.
func DebugLog(b *testing.B, msg string, args ...any) {
	b.Helper()
	if *debug {
		b.Logf(msg, args...)
	}
}

// FileSystemType represents a type container mount.
type FileSystemType string

const (
	// BindFS indicates a bind mount should be created.
	BindFS FileSystemType = "bindfs"
	// TmpFS indicates a tmpfs mount should be created.
	TmpFS FileSystemType = "tmpfs"
	// RootFS indicates no mount should be created and the root mount should be used.
	RootFS FileSystemType = "rootfs"
)

// MakeMount makes a mount and cleanup based on the requested type. Bind
// and volume mounts are backed by a temp directory made with mktemp.
// tmpfs mounts require no such backing and are just made.
// rootfs mounts do not make a mount, but instead return a target direectory at root.
// It is up to the caller to call Clean on the passed *cleanup.Cleanup
func MakeMount(machine Machine, fsType FileSystemType, cu *cleanup.Cleanup) ([]mount.Mount, string, error) {
	mounts := make([]mount.Mount, 0, 1)
	target := "/data"
	switch fsType {
	case BindFS:
		dir, err := machine.RunCommand("mktemp", "-d")
		if err != nil {
			return mounts, "", fmt.Errorf("failed to create tempdir: %v", err)
		}
		dir = strings.TrimSuffix(dir, "\n")
		cu.Add(func() {
			machine.RunCommand("rm", "-rf", dir)
		})
		out, err := machine.RunCommand("chmod", "777", dir)
		if err != nil {
			return mounts, "", fmt.Errorf("failed modify directory: %v %s", err, out)
		}
		mounts = append(mounts, mount.Mount{
			Target: target,
			Source: dir,
			Type:   mount.TypeBind,
		})
		return mounts, target, nil
	case RootFS:
		return mounts, target, nil
	case TmpFS:
		mounts = append(mounts, mount.Mount{
			Target: target,
			Type:   mount.TypeTmpfs,
		})
		return mounts, target, nil
	default:
		return mounts, "", fmt.Errorf("illegal mount type not supported: %v", fsType)
	}
}
