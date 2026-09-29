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
	"encoding/binary"
	"math/rand"

	cryptorand "gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// beforeSave is invoked by stateify.
func (s *Stack) beforeSave() {
	// removeConf will be set only in case of save/restore.
	s.mu.Lock()
	s.routeMu.RLock()
	s.preservedRoutes = nil
	for r := s.routeTable.Front(); r != nil; r = r.Next() {
		if _, ok := s.preservedNICs[r.NIC]; ok {
			rCopy := *r
			rCopy.RouteEntry = tcpip.RouteEntry{}
			s.preservedRoutes = append(s.preservedRoutes, rCopy)
		}
	}
	s.routeMu.RUnlock()

	for _, nic := range s.preservedNICs {
		nic.linkResQueue.mu.Lock()
		for _, resolver := range nic.linkAddrResolvers {
			resolver.neigh.mu.Lock()
			for _, entry := range resolver.neigh.mu.cache {
				entry.mu.Lock()
				if entry.mu.done != nil {
					entry.mu.pendingPackets = nic.linkResQueue.mu.packets[entry.mu.done]
				}
				entry.mu.Unlock()
			}
			resolver.neigh.mu.Unlock()
		}
		nic.linkResQueue.mu.Unlock()
	}

	s.unpreservedNICs = nil
	if !s.removeConf {
		for id, n := range s.nics {
			if _, ok := s.preservedNICs[id]; !ok {
				s.unpreservedNICs = append(s.unpreservedNICs, n)
			}
		}
		s.mu.Unlock()
		return
	}

	// Remove all the NICs and routes from the stack as they will be
	// created again during restore based on the new network config,
	// except for preserved virtual NICs created inside the sandbox.
	deferActs := make([]func(), 0)
	for id := range s.nics {
		if _, ok := s.preservedNICs[id]; ok {
			continue
		}
		act, _ := s.removeNICLocked(id, true /* closeLinkEndpoint */)
		if act != nil {
			deferActs = append(deferActs, act)
		}
	}
	s.mu.Unlock()

	for _, act := range deferActs {
		act()
	}
}

func (s *Stack) ensureRNG() {
	if s.insecureRNG == nil {
		var v int64
		if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &v); err != nil {
			panic(err)
		}
		randSrc := &lockedRandomSource{src: rand.NewSource(v)}
		s.insecureRNG = rand.New(randSrc)
	}
	if s.secureRNG.Reader == nil {
		s.secureRNG = cryptorand.RNGFrom(cryptorand.Reader)
	}
}

// afterLoad is invoked by stateify.
//
// +checklocksexclude:s.mu
func (s *Stack) afterLoad(context.Context) {
	s.ensureRNG()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preservedNICs == nil {
		s.preservedNICs = make(map[tcpip.NICID]*nic)
	}
	for _, n := range s.unpreservedNICs {
		n.enabled.Store(false)
		for _, ep := range n.networkEndpoints {
			ep.Close()
		}
	}
	s.unpreservedNICs = nil
}
