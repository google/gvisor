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

// Lock order: pendingTimer.mu -> TimeoutController.mu

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"
	"time"

	compute "google.golang.org/api/compute/v1"
)

const (
	// idleTimeout is the maximum time an agent can await a job before being
	// killed.
	idleTimeout = 1 * time.Minute

	// untimedInstanceMaxAge is how long an instance can run without a timeout
	// before it is deleted.
	untimedInstanceMaxAge = 10 * time.Minute

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

// pendingTimer is a slot that represents a single instance's pending
// timer info.
type pendingTimer struct {
	// timer is protected by mu.
	timer *time.Timer

	// expiry is protected by mu.
	expiry time.Time

	// pendingTimer.mu synchronizes mutation to the instance's timer "slot" within
	// the TimeoutController.pendingTimers map.
	//
	// The primary reason for this fine-grained lock is to synchronize instance
	// metadata updates (which are slow network operations) with local timer state
	// updates.
	mu sync.Mutex

	// refs is the number of currently running operations on this timer slot.
	// refs is protected by TimeoutController.mu.
	refs uint64
}

// TimeoutController deletes instances whose jobs exceed the specified timeout.
// Each instance's expiry is recorded in its metadata, so timers survive a
// coordinator restart.
//
// Safe for concurrent use.
type TimeoutController struct {
	svc *compute.Service

	// TimeoutController.mu synchronizes accesses to pendingTimers.
	//
	// To remove an existing pendingTimer, pendingTimer.mu must also
	// be held for that slot.
	mu            sync.Mutex
	pendingTimers map[instanceIdentity]*pendingTimer
}

// NewTimeoutController returns a controller with timeouts restored for every
// instance running as the agent service account that has an expiry recorded.
func NewTimeoutController(ctx context.Context, computeSvc *compute.Service, project, agentServiceAccount string) (*TimeoutController, error) {
	tc := &TimeoutController{
		svc:           computeSvc,
		pendingTimers: make(map[instanceIdentity]*pendingTimer),
	}
	instances, err := listAllInstances(ctx, computeSvc, project, agentServiceAccount)
	if err != nil {
		return nil, err
	}
	expiries, err := getInstanceExpiryBulk(ctx, computeSvc, slices.Collect(maps.Keys(instances)))
	if err != nil {
		return nil, err
	}
	for id, expiry := range expiries {
		pt := &pendingTimer{}
		pt.mu.Lock()
		tc.mu.Lock()
		tc.pendingTimers[id] = pt
		tc.registerTimeoutLocked(id, expiry)
		pt.mu.Unlock()
		tc.mu.Unlock()
	}
	log.Printf("Restored job timeouts for %d instances", len(expiries))
	return tc, nil
}

// TimeoutPolicy determines how RegisterTimeout behaves if the agent has an existing timeout.
type TimeoutPolicy int

const (
	// ReplaceTimeout specifies to replace any existing timeout.
	ReplaceTimeout TimeoutPolicy = iota

	// ShortenTimeout specifies to replace an existing timeout only if the new timeout
	// expires first.
	ShortenTimeout

	// IfNoTimeout specifies to apply the timeout only if there is no existing timeout.
	IfNoTimeout
)

// RegisterTimeout schedules the instance to be deleted after the specified
// job timeout. If the instance already has a timeout, policy determines whether
// RegisterTimeout replaces it. RegisterTimeout returns whether it applied the
// new timeout.
//
// If RegisterTimeout returns an error, it is guaranteed that the previous timeout
// was NOT cleared.
func (tc *TimeoutController) RegisterTimeout(ctx context.Context, id instanceIdentity, timeout time.Duration, policy TimeoutPolicy) (bool, error) {
	tc.mu.Lock()
	pt := tc.pendingTimers[id]
	if pt == nil {
		pt = &pendingTimer{}
		tc.pendingTimers[id] = pt
	}
	pt.refs++
	tc.mu.Unlock()

	// (a)

	pt.mu.Lock()
	defer pt.mu.Unlock()
	defer func() {
		// To avoid leaking empty timer slots, the last operation to complete
		// on a timer slot clears the slot if it's empty.

		tc.mu.Lock()
		pt.refs--
		if pt.refs == 0 && pt.timer == nil && tc.pendingTimers[id] == pt {
			delete(tc.pendingTimers, id)
		}
		tc.mu.Unlock()
	}()

	// Check that the timer slot wasn't cleared at position (a)
	tc.mu.Lock()
	currTC := tc.pendingTimers[id]
	tc.mu.Unlock()
	if currTC != pt {
		return false, fmt.Errorf("%v was deleted by timeout expiry", id)
	}

	expiry := time.Now().Add(timeout)

	if pt.timer != nil {
		switch policy {
		case ShortenTimeout:
			// If we were asked *not* to extend an existing timeout, don't do so.
			if pt.expiry.Before(expiry) {
				return false, nil
			}
		case IfNoTimeout:
			return false, nil
		}
	}

	// Record the timeout in the instance metadata so we can restore it
	// upon coordinator restart
	if err := id.setExpiryTime(ctx, tc.svc, expiry); err != nil {
		return false, fmt.Errorf("failed to record expiry for %v: %w", id, err)
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if pt.timer != nil {
		// Unregister the old timeout.
		pt.timer.Stop()
	}
	tc.registerTimeoutLocked(id, expiry)
	return true, nil
}

// DeleteUntimedInstances deletes every coordinator-managed instance that has
// no timeout and has an age greater than untimedInstanceMaxAge.
//
// Agents get a timeout whenever they request a job, so such an instance has
// never requested one (for example, because its startup script failed).
func (tc *TimeoutController) DeleteUntimedInstances(ctx context.Context, project, agentServiceAccount string) error {
	instances, err := listAllInstances(ctx, tc.svc, project, agentServiceAccount)
	if err != nil {
		return err
	}
	expiries, err := getInstanceExpiryBulk(ctx, tc.svc, slices.Collect(maps.Keys(instances)))
	if err != nil {
		return err
	}
	var errs []error
	now := time.Now()
	for id, created := range instances {
		if _, ok := expiries[id]; ok {
			continue
		}
		if now.Sub(created) <= untimedInstanceMaxAge {
			// Skip brand-new agents
			continue
		}
		// Delete the instance right away (unless it got a timeout since we last looked).
		scheduled, err := tc.RegisterTimeout(ctx, id, 0, IfNoTimeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if scheduled {
			log.Printf("Deleting %v, created at %v, since it has no timeout", id, created)
		}
	}
	return errors.Join(errs...)
}

// registerTimeoutLocked schedules the instance to be deleted at the specified time.
//
// tc.mu and tc.pendingTimers[id].mu must be held.
func (tc *TimeoutController) registerTimeoutLocked(id instanceIdentity, expiry time.Time) {
	pt := tc.pendingTimers[id]
	var timer *time.Timer
	timer = time.AfterFunc(time.Until(expiry), func() {
		pt.mu.Lock()
		defer pt.mu.Unlock()

		// make sure we're still the active timer
		tc.mu.Lock()
		currPT := tc.pendingTimers[id]
		tc.mu.Unlock()
		// Note two things:
		// (i) timer is captured by reference;
		// (ii) this check cannot run *before* timer has been set because registerTimeoutLocked
		//  still holds pt.mu when this closure is instantiated.
		if currPT != pt || timer != pt.timer {
			return
		}

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
	tc.pendingTimers[id].timer = timer
	tc.pendingTimers[id].expiry = expiry
}
