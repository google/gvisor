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

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"io"

	"github.com/BurntSushi/toml"
	types "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/sys"
	"github.com/containerd/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

const (
	// oomScoreMaxKillable is the maximum score keeping the process killable by the oom killer
	oomScoreMax = -999
)

// NewShimManager returns an implementation of the shim manager
// using runsc.
func NewShimManager(name string) shim.Manager {
	return &manager{
		name: name,
	}
}

type manager struct {
	name string
}

var _ shim.Manager = (*manager)(nil)

func newCommand(ctx context.Context, id, containerdAddress string, debug bool) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-address", containerdAddress,
		"-id", id,
	}
	if debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func (m manager) Name() string {
	return m.name
}

// Start implements shim.Manager.Start.
func (m *manager) Start(ctx context.Context, id string, opts shim.StartOpts) (shim.BootstrapParams, error) {
	grouping := id
	enableGrouping := getEnableGrouping()
	if enableGrouping {
		// The config.json is always at the current directory by containerd.
		configFile, err := os.Open("config.json")
		if err != nil {
			return shim.BootstrapParams{}, fmt.Errorf("failed to read config.json when starting shim: %w", err)
		}
		var readSpec spec
		if err := json.NewDecoder(configFile).Decode(&readSpec); err != nil {
			configFile.Close()
			return shim.BootstrapParams{}, err
		}
		configFile.Close()
		if groupID, ok := readSpec.Annotations[kubernetesGroupAnnotation]; ok {
			log.L.Debugf("group label found %v: %v", kubernetesGroupAnnotation, groupID)
			grouping = groupID
		}
	}

	cmd, err := newCommand(ctx, id, opts.Address, opts.Debug)
	if err != nil {
		return shim.BootstrapParams{}, err
	}

	address, err := shim.SocketAddress(ctx, opts.Address, grouping, opts.Debug)
	if err != nil {
		return shim.BootstrapParams{}, err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		// The only time where this would happen is if there is a bug and the socket
		// was not cleaned up in the cleanup method of the shim or we are using the
		// grouping functionality where the new process should be run with the same
		// shim as an existing container.
		if !shim.SocketEaddrinuse(err) {
			return shim.BootstrapParams{}, fmt.Errorf("create new shim socket: %w", err)
		}
		if shim.CanConnect(address) {
			if err := writeAddress("address", address); err != nil {
				return shim.BootstrapParams{}, fmt.Errorf("write existing socket for shim: %w", err)
			}
			return shim.BootstrapParams{Version: 2, Address: address, Protocol: "ttrpc"}, nil
		}
		if err := shim.RemoveSocket(address); err != nil {
			return shim.BootstrapParams{}, fmt.Errorf("remove pre-existing socket: %w", err)
		}
		if socket, err = shim.NewSocket(address); err != nil {
			return shim.BootstrapParams{}, fmt.Errorf("try create new shim socket 2x: %w", err)
		}
	}
	cu := cleanup.Make(func() {
		socket.Close()
		_ = shim.RemoveSocket(address)
	})
	defer cu.Clean()

	// make sure that reexec shim binary use the value if need.
	if err := writeAddress("address", address); err != nil {
		return shim.BootstrapParams{}, err
	}

	f, err := socket.File()
	if err != nil {
		return shim.BootstrapParams{}, err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	if err := cmd.Start(); err != nil {
		f.Close()
		return shim.BootstrapParams{}, err
	}

	cu.Add(func() {
		cmd.Process.Kill()
	})

	// make sure to wait after start
	go cmd.Wait()
	if err := shim.WritePidFile("shim.pid", cmd.Process.Pid); err != nil {
		return shim.BootstrapParams{}, err
	}
	if err := writeAddress(shimAddressPath, address); err != nil {
		return shim.BootstrapParams{}, err
	}
	if err := sys.SetOOMScore(cmd.Process.Pid, oomScoreMax); err != nil {
		return shim.BootstrapParams{}, fmt.Errorf("failed to set OOM Score on shim: %w", err)
	}
	cu.Release()
	return shim.BootstrapParams{Version: 2, Address: address, Protocol: "ttrpc"}, nil
}

// Stop implements shim.Manager.Stop.
func (manager) Stop(ctx context.Context, id string) (shim.StopStatus, error) {
	log.L.Debugf("StopShim, id: %v", id)
	path, err := os.Getwd()
	if err != nil {
		return shim.StopStatus{}, err
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return shim.StopStatus{}, err
	}
	var st runsc.State
	if err := st.Load(path); err != nil {
		return shim.StopStatus{}, err
	}
	r := proc.NewRunsc(st.Options.Root, path, ns, st.Options.BinaryName, nil, nil)

	if err := r.Delete(ctx, id, &runsccmd.DeleteOpts{
		Force: true,
	}); err != nil {
		log.L.Infof("failed to remove runsc container: %v", err)
	}
	if err := mount.UnmountAll(st.Rootfs, 0); err != nil {
		log.L.Infof("failed to cleanup rootfs mount: %v", err)
	}
	return shim.StopStatus{
		ExitedAt:   time.Now(),
		ExitStatus: 128 + int(unix.SIGKILL),
	}, nil
}

func getRuntimeOptions() *runsc.Options {
	opts := &runsc.Options{}
	shimConfigPaths := []string{"/run/containerd/runsc/config.toml", "/etc/containerd/runsc/config.toml"}

	tomlPath := ""
	for _, path := range shimConfigPaths {
		if _, err := os.Stat(path); err == nil {
			tomlPath = path
			break
		}
	}
	if len(tomlPath) == 0 {
		return opts
	}

	if _, err := toml.DecodeFile(tomlPath, opts); err != nil {
		log.L.Debugf("Failed to decode shim config file %q: %v", tomlPath, err)
		return opts
	}

	return opts
}

func getEnableGrouping() bool {
	opts := getRuntimeOptions()
	if opts == nil {
		return false
	}
	return opts.Grouping
}

func (m *manager) Info(ctx context.Context, optionsR io.Reader) (*types.RuntimeInfo, error) {
	return &types.RuntimeInfo{
		Name: "io.containerd.runsc.v1",
		Version: &types.RuntimeVersion{
			Version: "v1.0.0",
		},
	}, nil
}

func writeAddress(path, address string) error {
	return os.WriteFile(path, []byte(address), 0o644)
}
