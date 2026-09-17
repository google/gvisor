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

package proc

import (
	"context"
	"time"

	"github.com/containerd/log"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

func (p *Init) abortFuse() error {
	if !p.FuseAbort {
		return nil
	}
	if err := utils.AbortContainerFuse(p.K8sPodUID, p.Bundle, p.id); err != nil {
		log.L.Warningf("Failed to abort FUSE connections for container %q: %v", p.id, err)
		return err
	}
	return nil
}

func (p *Init) isExited() bool {
	select {
	case <-p.waitBlock:
		return true
	default:
		return false
	}
}

// monitorGofer monitors the gofer process of the container.
// It waits for the gofer process to exit and if it does, it will escalate
// to FUSE abort and SIGKILL.
func (p *Init) monitorGofer(ctx context.Context) {
	if p.runtime == nil {
		return
	}
	var goferPid int
	for i := 0; i < 30; i++ {
		goferPid = utils.FindGoferPID(p.runtime.Root, p.Bundle, p.id)
		if goferPid > 0 {
			break
		}
		select {
		case <-p.waitBlock:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if goferPid <= 0 {
		log.L.Debugf("monitorGofer: gofer PID not found for container %q, giving up", p.id)
		return
	}
	log.L.Debugf("Monitoring gofer (PID=%d) for container %q (pod %q)", goferPid, p.id, p.K8sPodUID)

	if err := utils.WaitForProcessExit(goferPid, p.waitBlock); err != nil {
		log.L.Debugf("monitorGofer: WaitForProcessExit returned err=%v", err)
		return
	}
	log.L.Debugf("monitorGofer: gofer PID %d exited for container %q", goferPid, p.id)

	if p.isExited() {
		return
	}

	log.L.Warningf("Gofer (PID=%d) for container %q died; starting H4 wedge escalation", goferPid, p.id)

	select {
	case <-p.waitBlock:
		log.L.Debugf("monitorGofer: Container %q exited naturally within 2s grace window", p.id)
		return
	case <-time.After(2 * time.Second):
	}

	if p.isExited() {
		return
	}

	log.L.Warningf("Container %q wedged in Kernel.Pause following gofer death (PID=%d); aborting FUSE connections", p.id, goferPid)
	if err := p.abortFuse(); err != nil {
		log.L.Warningf("abortFuse failed during gofer death escalation for container %q: %v", p.id, err)
	}

	select {
	case <-p.waitBlock:
		log.L.Infof("Container %q exited after FUSE abort following gofer death", p.id)
		return
	case <-time.After(1 * time.Second):
	}

	if p.isExited() {
		return
	}

	log.L.Warningf("Container %q did not exit after FUSE abort; escalating to SIGKILL", p.id)
	p.KillAll(context.Background())
}
