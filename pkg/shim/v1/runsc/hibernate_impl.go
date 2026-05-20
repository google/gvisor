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

//go:build !false
// +build !false

package runsc

import (
	"context"
	"fmt"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	hibernatepb "gvisor.dev/gvisor/pkg/shim/v1/runsc/hibernate_go_proto"
)

// NewHibernateServerEndpoint returns a new HibernateServerEndpoint.
func NewHibernateServerEndpoint(root, namespace, id string) (*HibernateServerEndpoint, error) {
	return nil, nil
}

// Serve starts the ttrpc server and listen for hibernate requests.
func (s *HibernateServerEndpoint) Serve(ctx context.Context) error {
	return nil
}

// Shutdown shuts down the hibernate server.
func (s *HibernateServerEndpoint) Shutdown(ctx context.Context) error {
	return nil
}

// RegisterService registers the hibernate service with the given task service.
func (s *HibernateServerEndpoint) RegisterService(srvc extension.TaskServiceExt) {
}

// Hide hides the gVisor sandbox.
func (s *runscService) Hide(ctx context.Context, req *hibernatepb.HideRequest, resp *hibernatepb.HideResponse) error {
	return fmt.Errorf("Hide is not implemented")
}

// Unhide unhides the gVisor sandbox.
func (s *runscService) Unhide(ctx context.Context, req *hibernatepb.UnhideRequest, resp *hibernatepb.UnhideResponse) error {
	return fmt.Errorf("Unhide is not implemented")
}
