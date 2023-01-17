// Copyright 2022 The gVisor Authors.
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

// Package portforward holds the infrastructure to support the port forward command.
package portforward

import (
	"gvisor.dev/gvisor/pkg/context"
)

// portForwardConn is a port forwarding connection. It is used to manage the
// lifecycle of the connection and clean it up if necessary.
type portForwardConn interface {
	// start starts the connection goroutines and returns.
	start(ctx context.Context) error
	// close closes and cleans up the connection.
	close(ctx context.Context) error
	// cleanup registers a callback for when the connection closes.
	cleanup(func())
}
