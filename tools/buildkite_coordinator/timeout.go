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

package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	compute "google.golang.org/api/compute/v1"
)

const (
	// jobTimeout is the maximum time an instance is allowed to spend per job.
	// An instance will be killed if it exceeds the timeout.
	//
	// jobTimeout should be kept <= BucketTokenLifetime otherwise bucket tokens
	// may expire before the job is complete.
	jobTimeout = time.Hour

	// setupGracePeriod is the grace period added to a timeout specified by a
	// Buildkite job to account for agent setup, etc.
	setupGracePeriod = 10 * time.Minute

	// deleteTimeout bounds a single attempt to delete a timed-out instance.
	deleteTimeout = 5 * time.Minute

	// deleteRetryInterval is how long to wait before retrying a failed
	// deletion.
	deleteRetryInterval = 5 * time.Minute
)

// TimeoutController deletes instances whose jobs exceed the specified timeout.
// Each instance's expiry is recorded in its metadata, so timers survive a
// coordinator restart.
//
// Safe for concurrent use.
type TimeoutController struct {
	svc *compute.Service

	// mu protects pendingTimers.
	mu            sync.Mutex
	pendingTimers map[instanceIdentity]*time.Timer
}

// NewTimeoutController returns a controller with timeouts restored for every
// instance running as the agent service account that has an expiry recorded.
func NewTimeoutController(ctx context.Context, computeSvc *compute.Service, project, agentServiceAccount string) (*TimeoutController, error) {
	tc := &TimeoutController{
		svc:           computeSvc,
		pendingTimers: make(map[instanceIdentity]*time.Timer),
	}
	ids, err := listAllInstances(ctx, computeSvc, project, agentServiceAccount)
	if err != nil {
		return nil, err
	}
	expiries, err := getInstanceExpiryBulk(ctx, computeSvc, ids)
	if err != nil {
		return nil, err
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for id, expiry := range expiries {
		tc.registerTimeoutLocked(id, expiry)
	}
	log.Printf("Restored job timeouts for %d instances", len(expiries))
	return tc, nil
}

// RegisterTimeout schedules the instance to be deleted after the specified
// job timeout, canceling any existing timeout.
//
// If RegisterTimeout returns an error, it is guaranteed that the previous timeout
// was NOT cleared.
func (tc *TimeoutController) RegisterTimeout(ctx context.Context, id instanceIdentity, timeout time.Duration) error {
	expiry := time.Now().Add(timeout)
	// Record the timeout in the instance metadata so we can restore it
	// upon coordinator restart
	if err := id.setExpiryTime(ctx, tc.svc, expiry); err != nil {
		return fmt.Errorf("failed to record expiry for %v: %w", id, err)
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.registerTimeoutLocked(id, expiry)
	return nil
}

// registerTimeoutLocked schedules the instance to be deleted at the specified time,
// canceling any existing timeout.
//
// tc.mu must be held.
func (tc *TimeoutController) registerTimeoutLocked(id instanceIdentity, expiry time.Time) {
	if oldTimer := tc.pendingTimers[id]; oldTimer != nil {
		oldTimer.Stop()
		delete(tc.pendingTimers, id)
	}

	timer := time.AfterFunc(time.Until(expiry), func() {
		ctx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
		defer cancel()
		err := id.forceDelete(ctx, tc.svc)

		tc.mu.Lock()
		defer tc.mu.Unlock()
		if err != nil {
			log.Printf("Error: failed to delete timed-out %v, retrying in %v: %v", id, deleteRetryInterval, err)
			tc.registerTimeoutLocked(id, time.Now().Add(deleteRetryInterval))
			return
		}
		log.Printf("Deleted %v due to timeout expiry", id)
		delete(tc.pendingTimers, id)
	})
	tc.pendingTimers[id] = timer
}
