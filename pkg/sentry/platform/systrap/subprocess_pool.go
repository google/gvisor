// Copyright 2023 The gVisor Authors.
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

package systrap

import (
	"sync"
)

// subprocessPool exists to solve these distinct problems:
//
// 1) Subprocesses can't always be killed properly (see subprocess.Release).
// In general it's helpful to be able to reuse subprocesses, but we must observe
// the subprocess lifecycle before we can do so (e.g. should wait for all
// contexts to be released).
//
// 2) Any seccomp filters that have been installed will apply to subprocesses
// created here. Therefore we use the intermediary (source), which is created
// on initialization of the platform.
type subprocessPool struct {
	mu     sync.Mutex
	source *subprocess
	// available stores all subprocesses that are available for reuse.
	// +checklocks:mu
	available []*subprocess
}

func (p *subprocessPool) markAvailable(s *subprocess) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.available = append(p.available, s)
}

func (p *subprocessPool) fetchAvailable() *subprocess {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.available) > 0 {
		s := p.available[len(p.available)-1]
		p.available = p.available[:len(p.available)-1]

		return s
	}
	return nil
}
