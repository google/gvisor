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
	"strconv"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	firestoreTimeout = 5 * time.Second
)

// rateLimits defines per-author job rate limits.
//
// It is immutable.
var rateLimits = map[uint]uint{
	// Daily limit (600 compute-hours / 1 day)
	1: 36000,

	// Weekly limit (2400 compute-hours / 7 days)
	7: 144000,

	// Monthly limit (6000 compute-hours / 30 days)
	30: 360000,
}

// quotaDoc is the Firestore document recording an author's usage.
type quotaDoc struct {
	// MinutesPerDay maps dates (YYYY-MM-DD) to the number of minutes accounted for
	// the author on that day.
	MinutesPerDay map[string]int64 `firestore:"minutesPerDay"`
}

// RateLimitController tracks per-author quotas of compute minutes.
// Usage is stored in Firestore.
//
// Safe for concurrent use.
type RateLimitController struct {
	// client is safe for concurrent use.
	client *firestore.Client

	// limits stores a mapping from number of days to the total
	// quota of minutes per author within that time frame.
	//
	// It is immutable.
	limits map[uint]uint

	// maxDays is the longest window in limits.
	//
	// It is immutable.
	maxDays uint

	// collection is the Firestore collection holding one quotaDoc per author.
	//
	// It is immutable.
	collection string
}

// NewRateLimitController returns a controller storing quotas in the given
// Firestore collection of the given project.
func NewRateLimitController(ctx context.Context, project, collection string, limits map[uint]uint) (*RateLimitController, error) {
	var maxDays uint
	for days := range limits {
		if days == 0 {
			return nil, fmt.Errorf("rate limit window must be at least one day")
		}
		maxDays = max(maxDays, days)
	}
	client, err := firestore.NewClient(ctx, project)
	if err != nil {
		return nil, err
	}
	return &RateLimitController{
		client:     client,
		limits:     limits,
		maxDays:    maxDays,
		collection: collection,
	}, nil
}

// AccountForTime records the given duration for the author if doing so keeps them within
// limits.
//
// The duration is rounded up to the nearest minute.
//
//   - If increasing the count succeeded and the rate-limit has not been exceeded,
//     returns true.
//   - If the minutes would exceed a rate-limit, returns false, along with two
//     uints representing the interval (in days) and quota (in minutes) of the
//     limit that would be exceeded. If several limits would be exceeded, the
//     one with the longest interval is returned.
//   - If an error occurs while communicating with Firestore, the error is returned.
func (r *RateLimitController) AccountForTime(ctx context.Context, author authorID, now time.Time, duration time.Duration) (bool, uint, uint, error) {
	ctx, cancel := context.WithTimeout(ctx, firestoreTimeout)
	defer cancel()

	minutes := toMinutes(duration)
	now = now.UTC()
	ref := r.client.Collection(r.collection).Doc(strconv.FormatUint(uint64(author), 10))

	var allowed bool
	var exceededDays, exceededQuota uint
	err := r.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		// The transaction may run more than once; don't let an earlier
		// attempt's result leak out.
		allowed = false
		exceededDays, exceededQuota = 0, 0

		var prevDoc quotaDoc
		snapshot, err := tx.Get(ref)
		switch {
		case err == nil:
			if err := snapshot.DataTo(&prevDoc); err != nil {
				return fmt.Errorf("failed to decode quota for author %d: %w", author, err)
			}
		case status.Code(err) == codes.NotFound:
			// No pre-existing document
		default:
			return fmt.Errorf("failed to read quota for author %d: %w", author, err)
		}

		newMinutesPerDay := make(map[string]int64)
		var total int64
		for i := uint(0); i < r.maxDays; i++ {
			day := now.AddDate(0, 0, -int(i)).Format(time.DateOnly)
			if n, ok := prevDoc.MinutesPerDay[day]; ok {
				newMinutesPerDay[day] = n
				total += n
			}
			if limit, ok := r.limits[i+1]; ok && total+minutes > int64(limit) {
				exceededDays, exceededQuota = i+1, limit
			}
		}
		if exceededDays > 0 {
			// Out of quota: commit without writing anything.
			return nil
		}
		newMinutesPerDay[now.Format(time.DateOnly)] += minutes
		newDoc := quotaDoc{MinutesPerDay: newMinutesPerDay}

		// Replace the document.
		if err := tx.Set(ref, newDoc); err != nil {
			return err
		}
		allowed = true
		return nil
	})
	if err != nil {
		return false, 0, 0, err
	}
	return allowed, exceededDays, exceededQuota, nil
}

// UnaccountForTime reverses an accounting of the given duration for the
// given author.
//
// UnaccountForTime may only be called after AccountForTime was called
// with the same parameters and returned true.
func (r *RateLimitController) UnaccountForTime(ctx context.Context, author authorID, now time.Time, duration time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, firestoreTimeout)
	defer cancel()

	minutes := toMinutes(duration)
	day := now.UTC().Format(time.DateOnly)
	ref := r.client.Collection(r.collection).Doc(strconv.FormatUint(uint64(author), 10))

	_, err := ref.Update(ctx, []firestore.Update{{
		FieldPath: firestore.FieldPath{"minutesPerDay", day},
		Value:     firestore.Increment(-minutes),
	}})
	if err != nil {
		return fmt.Errorf("failed to unaccount for %d minutes for author %d: %w", minutes, author, err)
	}
	return nil
}

// toMinutes returns the duration in minutes, rounded up.
func toMinutes(d time.Duration) int64 {
	return int64((d + time.Minute - 1) / time.Minute)
}
