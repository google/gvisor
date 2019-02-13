// Copyright 2019 Google LLC
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

// +build !linux !amd64

package fdbased

import "gvisor.googlesource.com/gvisor/pkg/tcpip"

// Stubbed out versions for non-linux/non-amd64 platforms.

func (e *endpoint) setupPacketRXRing() error {
	return nil
}

func (e *endpoint) readMMappedPacket() ([]byte, *tcpip.Error) {
	return nil, nil
}

func (e *endpoint) packetMMapDispatch() (bool, *tcpip.Error) {
	return false, nil
}
