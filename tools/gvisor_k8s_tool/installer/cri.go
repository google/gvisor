// Copyright The Isola Authors
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

package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type criStatus struct {
	RuntimeReady bool
	Handlers     []string
	// From the daemon's loaded config, keyed by handler.
	Runtimes map[string]criRuntime
}

type criRuntime struct {
	OptionsTypeURL string
	Type           string
	Path           string
	ConfigPath     string
}

var errIdentityMismatch = errors.New("CRI target identity mismatch")
var errCRIUnavailable = errors.New("CRI endpoint unavailable")

var errNoRuntimeHandlers = errors.New(
	"containerd reports no runtime handlers over CRI (neither the RuntimeHandlers status field of " +
		"containerd 2.x nor the verbose CRI plugin config of containerd 1.x). " +
		"gVisor auto-install requires containerd 1.6 or newer")

// CRIClient judges containerd over the same surface the kubelet does.
type CRIClient interface {
	VerifyIdentity(ctx context.Context, mainPID int, podUID string) error
	// withHandlers costs a second round trip on containerd 1.x.
	Status(ctx context.Context, withHandlers bool) (criStatus, error)
}

type criClient struct {
	socket string
	mu     sync.Mutex
	// +checklocks:mu
	expectedPID int
	// +checklocks:mu
	identityMismatch bool
}

func NewCRIClient(socketPath string) CRIClient {
	return &criClient{socket: socketPath}
}

func (c *criClient) connection() (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///containerd", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
		if err != nil {
			return nil, err
		}
		socket, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("CRI transport is not a Unix socket")
		}
		raw, err := socket.SyscallConn()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		var cred *unix.Ucred
		var credentialErr error
		if err := raw.Control(func(fd uintptr) {
			cred, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil {
			_ = conn.Close()
			return nil, err
		}
		c.mu.Lock()
		pid := c.expectedPID
		c.mu.Unlock()
		if credentialErr != nil || cred == nil || pid <= 0 || int(cred.Pid) != pid {
			_ = conn.Close()
			c.mu.Lock()
			c.identityMismatch = true
			c.mu.Unlock()
			return nil, fmt.Errorf("%w: socket peer is not systemd containerd MainPID %d", errIdentityMismatch, pid)
		}
		return conn, nil
	}))
}

func (c *criClient) VerifyIdentity(ctx context.Context, mainPID int, podUID string) error {
	c.mu.Lock()
	c.expectedPID = mainPID
	c.identityMismatch = false
	c.mu.Unlock()
	conn, err := c.connection()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := runtimeapi.NewRuntimeServiceClient(conn).ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{Filter: &runtimeapi.PodSandboxFilter{State: &runtimeapi.PodSandboxStateValue{State: runtimeapi.PodSandboxState_SANDBOX_READY}}})
	if err != nil {
		return fmt.Errorf("CRI ListPodSandbox: %w", c.classifyError(err))
	}
	for _, sandbox := range resp.GetItems() {
		if sandbox.GetState() == runtimeapi.PodSandboxState_SANDBOX_READY && sandbox.GetMetadata().GetUid() == podUID {
			return nil
		}
	}
	return fmt.Errorf("%w: endpoint does not serve this installer pod UID", errIdentityMismatch)
}

func (c *criClient) Status(ctx context.Context, withHandlers bool) (criStatus, error) {
	// A fresh connection per probe keeps each check independent of stale
	// connection state across containerd restarts.
	conn, err := c.connection()
	if err != nil {
		return criStatus{}, fmt.Errorf("connecting to CRI socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rt := runtimeapi.NewRuntimeServiceClient(conn)
	st, err := statusFromRPC(ctx, func(ctx context.Context, verbose bool) (*runtimeapi.StatusResponse, error) {
		return rt.Status(ctx, &runtimeapi.StatusRequest{Verbose: verbose})
	}, withHandlers)
	if err != nil {
		return st, c.classifyError(err)
	}
	return st, nil
}

func (c *criClient) classifyError(err error) error {
	c.mu.Lock()
	mismatch := c.identityMismatch
	c.mu.Unlock()
	if mismatch {
		return fmt.Errorf("%w: %w", errIdentityMismatch, err)
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Unimplemented:
		return fmt.Errorf("%w: %w", errCRIUnavailable, err)
	}
	return err
}

// statusRPC is the seam that makes statusFromRPC testable without containerd.
type statusRPC func(ctx context.Context, verbose bool) (*runtimeapi.StatusResponse, error)

// Only the verbose Info config reports which shim and ConfigPath a handler
// resolves to. RuntimeHandlers (2.0+) carries names alone.
func statusFromRPC(ctx context.Context, call statusRPC, withHandlers bool) (criStatus, error) {
	resp, err := call(ctx, false)
	if err != nil {
		return criStatus{}, fmt.Errorf("CRI runtime status: %w", err)
	}

	var st criStatus
	for _, cond := range resp.GetStatus().GetConditions() {
		if cond.GetType() == runtimeapi.RuntimeReady {
			st.RuntimeReady = cond.GetStatus()
		}
	}
	for _, h := range resp.GetRuntimeHandlers() {
		st.Handlers = append(st.Handlers, h.GetName())
	}
	if !withHandlers {
		return st, nil
	}

	verbose, err := call(ctx, true)
	if err != nil {
		return st, fmt.Errorf("CRI runtime status (verbose): %w", err)
	}
	st.Runtimes, err = runtimesFromPluginConfig(verbose.GetInfo()["config"])
	if err != nil {
		return st, err
	}
	if len(st.Handlers) == 0 {
		for name := range st.Runtimes {
			st.Handlers = append(st.Handlers, name)
		}
		slices.Sort(st.Handlers)
	}
	return st, nil
}

// Mirrors the verbose Info["config"], where runtimes sit at
// containerd.runtimes.<handler>, NOT under the plugins."io.containerd..."
// nesting containerd.go parses from `config dump`.
type criPluginConfigInfo struct {
	Containerd struct {
		Runtimes map[string]struct {
			RuntimeType string `json:"runtimeType"`
			RuntimePath string `json:"runtimePath"`
			Options     struct {
				ConfigPath string `json:"ConfigPath"`
				TypeURL    string `json:"TypeUrl"`
			} `json:"options"`
		} `json:"runtimes"`
	} `json:"containerd"`
}

// Distinguishes absent (no handlers, caller fails closed) from unparsable (an
// error), so a regression is not hidden behind a version complaint.
func runtimesFromPluginConfig(raw string) (map[string]criRuntime, error) {
	if raw == "" {
		return nil, nil
	}
	var cfg criPluginConfigInfo
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parsing the CRI plugin config reported by containerd: %w", err)
	}
	if len(cfg.Containerd.Runtimes) == 0 {
		return nil, nil
	}
	out := make(map[string]criRuntime, len(cfg.Containerd.Runtimes))
	for name, rt := range cfg.Containerd.Runtimes {
		out[name] = criRuntime{
			Type:           rt.RuntimeType,
			Path:           rt.RuntimePath,
			ConfigPath:     rt.Options.ConfigPath,
			OptionsTypeURL: rt.Options.TypeURL,
		}
	}
	return out, nil
}
