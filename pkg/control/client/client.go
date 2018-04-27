// Copyright 2018 Google Inc.
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

// Package client provides a basic control client interface.
package client

import (
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
)

// ConnectTo attempts to connect to the sandbox with the given address.
func ConnectTo(addr string) (*urpc.Client, error) {
	// Connect to the server.
	conn, err := unet.Connect(addr, false)
	if err != nil {
		return nil, err
	}

	// Wrap in our stream codec.
	return urpc.NewClient(conn), nil
}
