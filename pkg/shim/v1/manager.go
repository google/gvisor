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
	"io"
	"os"
	"os/exec"
	"time"

	types "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/sys"
	"github.com/containerd/log"
	typeurl "github.com/containerd/typeurl/v2"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
	"gvisor.dev/gvisor/runsc/specutils"
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

// resolveGrouping determines the grouping key from the OCI spec annotations.
// It checks the containerd annotation first, then falls back to the CRI-O
// annotation. If neither is found, it returns the container ID unchanged.
func resolveGrouping(id string, annotations map[string]string) string {
	if groupID, ok := annotations[kubernetesGroupAnnotation]; ok {
		log.L.Debugf("group label found %v: %v", kubernetesGroupAnnotation, groupID)
		return groupID
	}
	if groupID, ok := annotations[specutils.CRIOSandboxIDAnnotation]; ok {
		log.L.Debugf("group label found %v: %v", specutils.CRIOSandboxIDAnnotation, groupID)
		return groupID
	}
	return id
}

// Start implements shim.Manager.Start.
func (m *manager) Start(ctx context.Context, id string, opts shim.StartOpts) (shim.BootstrapParams, error) {
	// containerd runs us in the bundle directory with the handler's runtime
	// options on stdin.
	options, err := utils.DrainRuntimeOptions(os.Stdin)
	if err != nil {
		return shim.BootstrapParams{}, err
	}

	// Under CRI, a sandbox bundle has no config.json.
	readSpec, specErr := readBundleSpec()

	// Containers get their options in every CreateTaskRequest, but
	// CreateSandboxRequest has no options field, so save them for the sandbox.
	if readSpec == nil && specErr == nil {
		if err := utils.SaveRuntimeOptions(".", options); err != nil {
			return shim.BootstrapParams{}, err
		}
	}

	// Grouping serves a whole pod from one shim by naming the socket after the
	// pod. Sandbox API pods need it too: below bootstrap version 3, containerd
	// starts a shim per container instead of using the sandbox's shim
	// (supportSandboxAPIVersion in core/runtime/v2/shim_manager.go).
	grouping := id
	if getEnableGrouping() {
		if specErr != nil {
			return shim.BootstrapParams{}, specErr
		}
		if readSpec == nil {
			// A sandbox: its id is the group.
			log.L.Debugf("no config.json found, grouping shim by its own id %v", id)
		} else {
			grouping = resolveGrouping(id, readSpec.Annotations)
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
	// containerd 1.7 rejects shims above version 2.
	return shim.BootstrapParams{Version: 2, Address: address, Protocol: "ttrpc"}, nil
}

// readBundleSpec decodes config.json in the current directory, or returns nil
// if there is none.
func readBundleSpec() (*spec, error) {
	configFile, err := os.Open("config.json")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read config.json when starting shim: %w", err)
	}
	defer configFile.Close()

	readSpec := &spec{}
	if err := json.NewDecoder(configFile).Decode(readSpec); err != nil {
		return nil, fmt.Errorf("failed to decode config.json when starting shim: %w", err)
	}
	return readSpec, nil
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

func getEnableGrouping() bool {
	opts := runsc.GetRuntimeOptions()
	if opts == nil {
		return false
	}
	return opts.Grouping
}

func (m *manager) Info(ctx context.Context, optionsR io.Reader) (*types.RuntimeInfo, error) {
	info := &types.RuntimeInfo{
		Name: m.name,
		Version: &types.RuntimeVersion{
			Version: "v1.0.0",
		},
	}

	feat := specutils.Features()
	if feat != nil {
		var err error
		info.Features, err = typeurl.MarshalAnyToProto(feat)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %T: %w", feat, err)
		}
	}

	return info, nil
}

func writeAddress(path, address string) error {
	return os.WriteFile(path, []byte(address), 0o644)
}
