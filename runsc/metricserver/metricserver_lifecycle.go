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

//go:build go1.1
// +build go1.1

package metricserver

import (
	"context"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/container"
)

// verifyLoopInterval is the interval at which we check whether there are any sandboxes we need
// to serve metrics for.
const verifyLoopInterval = 20 * time.Second

// sandboxData contains additional per-sandbox data.
type sandboxData struct{}

// load loads additional per-sandbox data.
func (s *sandboxData) load(*servedSandbox) error {
	return nil
}

// serverData contains additional server-wide data.
type serverData struct{}

// verify is one iteration of verifyLoop.
// It runs in a loop in the background which checks all sandboxes for liveness, tries to load
// their metadata if that hasn't been loaded yet, and tries to pick up new sandboxes that
// failed to register for whatever reason.
func (m *metricServer) verify(ctx context.Context) {
	_, err := container.ListSandboxes(m.rootDir)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if !m.allowUnknownRoot {
			log.Warningf("Cannot list sandboxes in root directory %s, it has likely gone away: %v. Server shutting down.", m.rootDir, err)
			m.shutdownLocked(ctx)
		}
		return
	}
	m.refreshSandboxesLocked()
}

// startVerifyLoop runs in the background and periodically calls verify.
func (m *metricServer) startVerifyLoop(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(verifyLoopInterval)
		defer ticker.Stop()
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-m.shutdownCh:
				log.Infof("Received interrupt signal, shutting down server.")
				m.mu.Lock()
				m.shutdownLocked(ctx)
				m.mu.Unlock()
				return
			case <-ticker.C:
				m.verify(ctx)
			}
		}
	}()
	return nil
}

// shutdownLocked shuts down the server. It assumes mu is held.
func (m *metricServer) shutdownLocked(ctx context.Context) {
	log.Infof("Server shutting down.")
	m.shuttingDown = true
	if m.udsPath != "" {
		if err := os.Remove(m.udsPath); err != nil {
			log.Warningf("Cannot remove UDS at %s: %v", m.udsPath, err)
		} else {
			m.udsPath = ""
		}
	}
	if m.pidFile != "" {
		if err := os.Remove(m.pidFile); err != nil {
			log.Warningf("Cannot remove PID file at %s: %v", m.pidFile, err)
		} else {
			m.pidFile = ""
		}
	}
	m.srv.Shutdown(ctx)
}
