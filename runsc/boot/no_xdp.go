// Copyright 2025 The gVisor Authors.
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

//go:build !xdp
// +build !xdp

package boot

import (
	"errors"
	"net"
	"os"
)

// This file holds placeholders for XDP support, which is not compiled in by default.
//
// To enable XDP support, build gVisor with `--define=gotags=xdp`.

const noXDPMsg = "XDP support was not built into this release -- rebuild with --define=gotags=xdp"

func (n *Network) SetupXDPModeRedirect(netConf *NetworkConfig, _ *struct{}) error {
	return errors.New(noXDPMsg)
}

func createSocketXDP(iface net.Interface) ([]*os.File, error) {
	return nil, errors.New(noXDPMsg)
}

func (n *Network) SetupXDPModeTunnel(netConf *NetworkConfig, _ *struct{}) error {
	return errors.New(noXDPMsg)
}
