// Copyright 2026 The gVisor Authors.
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

//go:build amd64
// +build amd64

package slimvm

import (
	"sync"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

const (
	limitPCID       = 4096
	fixedKernelPCID = 1
)

var (
	pcidCache []uint16
	pcidMu    sync.Mutex
)

type pcidBitmap [(limitPCID + 64 - 1) / 64]atomicbitops.Uint64

func (bm *pcidBitmap) set(pcid uint16) {
	atomicbitops.OrUint64(&bm[pcid/64], 1<<(pcid%64))
}

func (bm *pcidBitmap) clear(pcid uint16) {
	atomicbitops.AndUint64(&bm[pcid/64], ^(1 << (pcid % 64)))
}

func (bm *pcidBitmap) test(pcid uint16) bool {
	return bm[pcid/64].Load()&(1<<(pcid%64)) != 0
}

func initPCIDs() {
	if !hasGuestPCID {
		return
	}
	for pcid := fixedKernelPCID + 1; pcid < limitPCID; pcid++ {
		pcidCache = append(pcidCache, uint16(pcid))
	}
}

func assignPCID(pcid *uint16) uint16 {
	pcidMu.Lock()
	if *pcid == 0 && len(pcidCache) > 0 {
		*pcid = pcidCache[len(pcidCache)-1]
		pcidCache = pcidCache[:len(pcidCache)-1]
	}
	pcidMu.Unlock()
	return *pcid
}

func dropPCID(pcid uint16) {
	if pcid == 0 {
		return
	}
	pcidMu.Lock()
	pcidCache = append(pcidCache, pcid)
	pcidMu.Unlock()
}
