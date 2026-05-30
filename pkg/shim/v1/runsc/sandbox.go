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

	api "github.com/containerd/containerd/api/runtime/sandbox/v1"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
)

// CreateSandbox will be called right after sandbox shim instance launched.
// It is a good place to initialize sandbox environment.
func (s *runscService) CreateSandbox(ctx context.Context, req *api.CreateSandboxRequest) (*api.CreateSandboxResponse, error) {
	log.L.Debugf("CreateSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// StartSandbox will start a previously created sandbox.
func (s *runscService) StartSandbox(ctx context.Context, req *api.StartSandboxRequest) (*api.StartSandboxResponse, error) {
	log.L.Debugf("StartSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// Platform queries the platform the sandbox is going to run containers on.
func (s *runscService) Platform(ctx context.Context, req *api.PlatformRequest) (*api.PlatformResponse, error) {
	log.L.Debugf("Platform (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// StopSandbox will stop existing sandbox instance
func (s *runscService) StopSandbox(ctx context.Context, req *api.StopSandboxRequest) (*api.StopSandboxResponse, error) {
	log.L.Debugf("StopSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// WaitSandbox blocks until sandbox exits.
func (s *runscService) WaitSandbox(ctx context.Context, req *api.WaitSandboxRequest) (*api.WaitSandboxResponse, error) {
	log.L.Debugf("WaitSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// SandboxStatus will return current status of the running sandbox instance
func (s *runscService) SandboxStatus(ctx context.Context, req *api.SandboxStatusRequest) (*api.SandboxStatusResponse, error) {
	log.L.Debugf("SandboxStatus (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// PingSandbox is a lightweight API call to check whether sandbox alive.
func (s *runscService) PingSandbox(ctx context.Context, req *api.PingRequest) (*api.PingResponse, error) {
	log.L.Debugf("PingSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// ShutdownSandbox must shutdown shim instance.
func (s *runscService) ShutdownSandbox(ctx context.Context, req *api.ShutdownSandboxRequest) (*api.ShutdownSandboxResponse, error) {
	log.L.Debugf("ShutdownSandbox (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}

// SandboxMetrics retrieves metrics about a sandbox instance.
func (s *runscService) SandboxMetrics(ctx context.Context, req *api.SandboxMetricsRequest) (*api.SandboxMetricsResponse, error) {
	log.L.Debugf("SandboxMetrics (unimplemented), id: %s", req.SandboxID)
	return nil, errdefs.ErrNotImplemented
}
