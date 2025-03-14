// Copyright 2024 The gVisor Authors.
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

package stack

import (
	"context"
	"math/rand"
	"time"

	cryptorand "gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// afterLoad is invoked by stateify.
func (s *Stack) afterLoad(context.Context) {
	s.insecureRNG = rand.New(rand.NewSource(time.Now().UnixNano()))
	s.secureRNG = cryptorand.RNGFrom(cryptorand.Reader)
	s.mu.Lock()
	s.nics = make(map[tcpip.NICID]*nic)
	s.mu.Unlock()
}
