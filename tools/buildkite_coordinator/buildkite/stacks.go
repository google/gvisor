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

package buildkite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// MaxPageSize is the largest page of scheduled jobs the Stacks API returns.
const MaxPageSize = 1000

// MaxBatchSize is the most job UUIDs a batch reservation or job acquisition
// token request may contain.
const MaxBatchSize = 1000

// RegisterStackRequest is the body of a stack registration.
type RegisterStackRequest struct {
	Key      string            `json:"key"`
	Type     string            `json:"type"`
	QueueKey string            `json:"queue_key"`
	Metadata map[string]string `json:"metadata"`
}

// Stack is a registered stack.
type Stack struct {
	ID              string            `json:"id"`
	Key             string            `json:"key"`
	Type            string            `json:"type"`
	ClusterQueueKey string            `json:"cluster_queue_key"`
	Metadata        map[string]string `json:"metadata"`
	State           string            `json:"state"`
}

// ScheduledJob is a job in the scheduled-jobs listing.
type ScheduledJob struct {
	ID              string    `json:"id"`
	Priority        int       `json:"priority"`
	AgentQueryRules []string  `json:"agent_query_rules"`
	ScheduledAt     time.Time `json:"scheduled_at"`
	RunnableAt      time.Time `json:"runnable_at"`
	Pipeline        struct {
		Slug string `json:"slug"`
		UUID string `json:"uuid"`
	} `json:"pipeline"`
	Build struct {
		Number int    `json:"number"`
		Branch string `json:"branch"`
		UUID   string `json:"uuid"`
	} `json:"build"`
	Step struct {
		Key string `json:"key"`
	} `json:"step"`
}

// PageInfo is the pagination state of a listing.
type PageInfo struct {
	HasNextPage bool   `json:"has_next_page"`
	EndCursor   string `json:"end_cursor"`
}

// ClusterQueue is the queue a listing is for.
type ClusterQueue struct {
	ID             string `json:"id"`
	DispatchPaused bool   `json:"dispatch_paused"`
}

// ScheduledJobs is a page of the scheduled-jobs listing.
type ScheduledJobs struct {
	Jobs         []ScheduledJob `json:"jobs"`
	PageInfo     PageInfo       `json:"page_info"`
	ClusterQueue ClusterQueue   `json:"cluster_queue"`
}

// Job is a job's full definition.
type Job struct {
	ID      string            `json:"id"`
	Env     map[string]string `json:"env"`
	Command string            `json:"command"`
}

// RegisterStack registers a stack, or updates it if it already exists.
func (c *Client) RegisterStack(ctx context.Context, req RegisterStackRequest) (Stack, error) {
	var stack Stack
	err := c.call(ctx, http.MethodPost, "/stacks/register", req, &stack)
	return stack, err
}

// DeregisterStack deregisters the stack with the given key.
func (c *Client) DeregisterStack(ctx context.Context, key string) error {
	return c.call(ctx, http.MethodPost, "/stacks/"+key+"/deregister", nil, nil)
}

// ListScheduledJobs returns a page of up to limit scheduled jobs on the given
// queue, starting after the given cursor (or "" for the first page).
func (c *Client) ListScheduledJobs(ctx context.Context, key, queueKey string, limit uint, after string) (ScheduledJobs, error) {
	params := url.Values{
		"queue_key": {queueKey},
		"limit":     {strconv.FormatUint(uint64(limit), 10)},
	}
	if after != "" {
		params.Set("after", after)
	}
	var jobs ScheduledJobs
	err := c.call(ctx, http.MethodGet, "/stacks/"+key+"/scheduled-jobs?"+params.Encode(), nil, &jobs)
	return jobs, err
}

// GetJob returns the full definition of the given job.
func (c *Client) GetJob(ctx context.Context, key, jobID string) (Job, error) {
	var job Job
	err := c.call(ctx, http.MethodGet, "/stacks/"+key+"/jobs/"+jobID, nil, &job)
	return job, err
}

// ReserveJobsRequest is the body of a batch job reservation.
type ReserveJobsRequest struct {
	JobUUIDs                 []string `json:"job_uuids"`
	ReservationExpirySeconds int      `json:"reservation_expiry_seconds,omitempty"`
}

// ReserveJobsResponse is the result of a batch job reservation.
type ReserveJobsResponse struct {
	Reserved    []string `json:"reserved"`
	NotReserved []string `json:"not_reserved"`
}

// JobAcquisitionToken is a short-lived credential that lets an agent register
// and acquire a single job.
type JobAcquisitionToken struct {
	JobUUID   string    `json:"job_uuid"`
	Token     string    `json:"job_acquisition_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// String describes the token without printing it.
func (t JobAcquisitionToken) String() string {
	return fmt.Sprintf("job acquisition token for job %s (expires %s)", t.JobUUID, t.ExpiresAt.Format(time.RFC3339))
}

// IssueJobAcquisitionTokensRequest is the body of a batch job acquisition
// token request.
type IssueJobAcquisitionTokensRequest struct {
	JobUUIDs             []string `json:"job_uuids"`
	TokenLifetimeSeconds int      `json:"token_lifetime_seconds,omitempty"`
}

// IssueJobAcquisitionTokensResponse is the result of a batch job acquisition
// token request.
type IssueJobAcquisitionTokensResponse struct {
	Tokens []JobAcquisitionToken `json:"job_acquisition_tokens"`
	// NotIssued lists the jobs no token was issued for. Its element format
	// isn't documented.
	NotIssued []json.RawMessage `json:"not_issued"`
}

// ReserveJobs reserves the given jobs for the stack and returns the IDs of
// the jobs that were successfully reserved.
// If an expiry of zero is provided, Buildkite's default is used.
func (c *Client) ReserveJobs(ctx context.Context, key string, jobIDs []string, expiry time.Duration) ([]string, error) {
	req := ReserveJobsRequest{
		JobUUIDs:                 jobIDs,
		ReservationExpirySeconds: int(expiry.Seconds()),
	}
	var resp ReserveJobsResponse
	if err := c.call(ctx, http.MethodPut, "/stacks/"+key+"/scheduled-jobs/batch-reserve", req, &resp); err != nil {
		return nil, err
	}
	return resp.Reserved, nil
}

// GetJobAcquisitionTokens issues job acquisition tokens for the given jobs
// (which must be reserved) and returns the tokens that were successfully issued.
// If a lifetime of zero is provided, Buildkite's default is used.
func (c *Client) GetJobAcquisitionTokens(ctx context.Context, key string, jobIDs []string, lifetime time.Duration) ([]JobAcquisitionToken, error) {
	req := IssueJobAcquisitionTokensRequest{
		JobUUIDs:             jobIDs,
		TokenLifetimeSeconds: int(lifetime.Seconds()),
	}
	var resp IssueJobAcquisitionTokensResponse
	if err := c.call(ctx, http.MethodPost, "/stacks/"+key+"/job-acquisition-tokens", req, &resp); err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

// GetJobStatesRequest is the body of a batch job state request.
type GetJobStatesRequest struct {
	JobUUIDs []string `json:"job_uuids"`
}

// GetJobStatesResponse is the result of a batch job state request.
type GetJobStatesResponse struct {
	// States maps job UUIDs to their states, e.g. "reserved", "accepted",
	// "finished" or "canceled".
	States map[string]string `json:"states"`
}

// GetJobStates returns the states of the given jobs, by job UUID.
func (c *Client) GetJobStates(ctx context.Context, key string, jobIDs []string) (map[string]string, error) {
	req := GetJobStatesRequest{JobUUIDs: jobIDs}
	var resp GetJobStatesResponse
	if err := c.call(ctx, http.MethodPost, "/stacks/"+key+"/jobs/get-states", req, &resp); err != nil {
		return nil, err
	}
	return resp.States, nil
}
