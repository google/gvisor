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

// Lock order: JobPool.mu -> BuildkiteStack.mu

package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"sync"
	"time"

	compute "google.golang.org/api/compute/v1"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/tools/buildkite_coordinator/buildkite"
)

const (
	// reservationExpiry is how long jobs are reserved for.
	reservationExpiry = 10 * time.Minute

	// tokenMinLifetime is how long a token must live for to be kept in the pool.
	tokenMinLifetime = 15 * time.Second
)

// BuildUUID represents a Buildkite build UUID.
type BuildUUID string

// JobUUID represents a Buildkite job UUID.
type JobUUID string

// JobAcquisitionToken represents an active JAT issued by Buildkite.
// A JAT is associated with a specific job UUID.
type JobAcquisitionToken struct {
	// token stores the JAT.
	token string

	// expiresAt stores the approximate time at which the JAT will expire.
	// Stored for the purposes of avoiding handing expired JATs to agents.
	expiresAt time.Time
}

const (
	buildSourceWebhook    = "webhook"
	buildSourceAPI        = "api"
	buildSourceUI         = "ui"
	buildSourceTriggerJob = "trigger_job"
	buildSourceSchedule   = "schedule"
)

// BuildMetadata stores metadata about a build on Buildkite, in particular
// information about its author.
type BuildMetadata struct {
	// source stores the BUILDKITE_SOURCE variable from this build.
	source string

	// nonPR indicates whether this build did not originate from a pull request.
	//
	// nonPR is only valid if source is one of "webhook", "api", or "ui".
	nonPR bool

	// prNumber stores the PR number associated with this build, or 0
	// if the build did not originate from a pull request.
	//
	// prNumber is only valid if source is one of "webhook", "api", or "ui".
	prNumber int

	// authorKnown indicates whether the author of the build is known.
	// It can be false if an error was encountered while fetching it.
	authorKnown bool

	// author stores the author ID associated with this build, as verified
	// from GitHub.
	//
	// author is only valid if authorKnown is true.
	author authorID
}

// Build represents a Buildkite build as part of a JobPool.
type Build struct {
	BuildMetadata

	// reservedJobs stores all the jobs that have been reserved in Buildkite,
	// along with their JATs.
	//
	// len(reservedJobs) may occasionally exceed JobPool.jobsPerBuild. This is
	// permitted to allow for more efficient concurrent error handling.
	reservedJobs map[JobUUID]JobAcquisitionToken
}

// Queue represents a Buildkite queue as part of a JobPool.
//
// Data is split across trusted and untrusted builds. Note that if fetching
// a build's author fails once and succeeds on a subsequent retry, a build
// may end up in both maps.
type Queue struct {
	// untrustedBuilds stores all builds with untrusted or unknown authors
	untrustedBuilds map[BuildUUID]Build

	// trustedBuilds stores all builds with trusted authors
	trustedBuilds map[BuildUUID]Build
}

// JobPool holds the jobs we have reserved and have JATs ready for.
//
// Safe for concurrent use.
type JobPool struct {
	// jobsPerBuild determines how many jobs per build we aim to maintain JATs
	// for.
	// It is immutable.
	jobsPerBuild uint

	// trustedAuthors lists author IDs whose builds will be placed in trustedBuilds.
	// It is immutable.
	trustedAuthors map[authorID]struct{}

	// mu protects queues.
	mu sync.Mutex

	// queues stores pool data associated with each queue.
	// queues is protected by mu.
	queues map[string]Queue
}

// NewJobPool returns an empty job pool.
func NewJobPool(jobsPerBuild uint, queues map[string]struct{}, trustedAuthors map[authorID]struct{}) *JobPool {
	p := &JobPool{
		jobsPerBuild:   jobsPerBuild,
		trustedAuthors: trustedAuthors,
		queues:         make(map[string]Queue),
	}
	for queue := range queues {
		p.queues[queue] = Queue{
			untrustedBuilds: make(map[BuildUUID]Build),
			trustedBuilds:   make(map[BuildUUID]Build),
		}
	}
	return p
}

// countLocked returns how many jobs from the given build on the given queue are in
// the pool.
//
// p.mu must be held.
func (p *JobPool) countLocked(queue string, uuid BuildUUID) uint {
	q := p.queues[queue]
	return uint(len(q.trustedBuilds[uuid].reservedJobs) + len(q.untrustedBuilds[uuid].reservedJobs))
}

// addLocked adds a reserved job and its token to the pool.
//
// p.mu must be held.
func (p *JobPool) addLocked(queue string, uuid BuildUUID, metadata BuildMetadata, jobID JobUUID, token JobAcquisitionToken) {
	q := p.queues[queue]
	builds := q.untrustedBuilds
	if p.trusted(metadata) {
		builds = q.trustedBuilds
	}
	b, ok := builds[uuid]
	if !ok {
		b = Build{BuildMetadata: metadata, reservedJobs: make(map[JobUUID]JobAcquisitionToken)}
		builds[uuid] = b
	}
	b.reservedJobs[jobID] = token
}

// jobIDsLocked returns a list of all jobs present in the pool.
func (p *JobPool) jobIDsLocked() []JobUUID {
	var jobIDs []JobUUID
	for _, q := range p.queues {
		for _, builds := range []map[BuildUUID]Build{q.trustedBuilds, q.untrustedBuilds} {
			for _, b := range builds {
				for jobID := range b.reservedJobs {
					jobIDs = append(jobIDs, jobID)
				}
			}
		}
	}
	return jobIDs
}

// trusted returns whether a build with the given metadata may run on trusted
// agents.
func (p *JobPool) trusted(metadata BuildMetadata) bool {
	switch metadata.source {
	case buildSourceSchedule:
		// Scheduled builds run from branches configured by pipeline admins,
		// so treat as trusted
		return true

	case buildSourceWebhook, buildSourceAPI, buildSourceUI:
		if metadata.nonPR {
			// Trust builds that do not originate from PRs
			return true
		}
		if !metadata.authorKnown {
			// If the PR author is unknown, treat as untrusted
			return false
		}
		// Otherwise, check if the author is in the trusted authors set
		_, ok := p.trustedAuthors[metadata.author]
		return ok

	default:
		return false
	}
}

// assignJob removes a job suitable for the given agent from the pool, and
// returns it along with its token and the agent as it is after taking the job:
//
//   - A trusted agent takes a job from any trusted build.
//   - An untrusted agent takes a job only from the build it is pinned to.
//   - An unassigned agent is pinned before it is handed a job.
//
// Returns nil job and token if no suitable job is available.
func (p *JobPool) assignJob(ctx context.Context, svc *compute.Service, a agent) (*JobUUID, *JobAcquisitionToken, agent, error) {
	queue := a.getQueue()

	p.mu.Lock()
	muCleanup := cleanup.Make(func() {
		p.mu.Unlock()
	})
	defer muCleanup.Clean()

	q, ok := p.queues[queue]
	if !ok {
		return nil, nil, nil, fmt.Errorf("agent %v has invalid queue %v", a, queue)
	}

	// Choose the builds to take a job from, and the build within them. An
	// empty build UUID means any build is ok.
	var builds map[BuildUUID]Build
	var buildUUID BuildUUID
	var trusted bool
	switch agent := a.(type) {
	case *trustedAgent:
		builds, trusted = q.trustedBuilds, true
	case *untrustedAgent:
		builds, buildUUID, trusted = q.untrustedBuilds, agent.buildUUID, false
	case *unassignedAgent:
		if len(q.trustedBuilds) > 0 {
			builds, trusted = q.trustedBuilds, true
		} else {
			builds, trusted = q.untrustedBuilds, false
		}
	default:
		panic(fmt.Sprintf("agent %v has unknown type %T", a, a))
	}
	if buildUUID == "" {
		for buildUUID = range builds {
			break
		}
	}

	// Builds are removed from the pool once they have no jobs left, so any
	// build that is present has at least one.
	b, ok := builds[buildUUID]
	if !ok {
		return nil, nil, a, nil
	}
	var jobUUID JobUUID
	var token JobAcquisitionToken
	for jobUUID, token = range b.reservedJobs {
		break
	}
	delete(b.reservedJobs, jobUUID)
	if len(b.reservedJobs) == 0 {
		delete(builds, buildUUID)
	}
	muCleanup.Release()()

	unassigned, ok := a.(*unassignedAgent)
	if !ok {
		// Agent already pinned; skip pinning
		return &jobUUID, &token, a, nil
	}

	// Pin the agent to match the job. Structured to avoid holding p.mu
	// during this step
	var err error
	if trusted {
		var pinned trustedAgent
		pinned, err = unassigned.pinTrusted(ctx, svc)
		a = &pinned
	} else {
		var pinned untrustedAgent
		pinned, err = unassigned.pinToBuild(ctx, svc, buildUUID)
		a = &pinned
	}
	if err != nil {
		// Put the job back for another agent
		p.mu.Lock()
		defer p.mu.Unlock()
		p.addLocked(queue, buildUUID, b.BuildMetadata, jobUUID, token)
		return nil, nil, nil, err
	}
	return &jobUUID, &token, a, nil
}

// BuildkiteStack is a Buildkite stack: the coordinator's registration with the Stacks
// API, used to see and claim jobs on the cluster's queues.
//
// Safe for concurrent use.
type BuildkiteStack struct {
	// The following fields are immutable.
	key    string
	queues map[string]struct{}

	// Safe for concurrent use
	api *buildkite.Client
	gh  *githubClient

	// mu protects the below fields.
	mu sync.Mutex

	// metadataCache caches build metadata for each build UUID so we can avoid
	// re-fetching the metadata at every snapshot.
	metadataCache map[BuildUUID]BuildMetadata
}

// NewStack registers a stack with the given key.
func NewStack(ctx context.Context, key string, agentToken []byte, gh *githubClient, queues map[string]struct{}) (*BuildkiteStack, error) {
	if len(queues) == 0 {
		return nil, fmt.Errorf("stack must serve at least one queue")
	}
	s := &BuildkiteStack{
		key:    key,
		queues: queues,
		api:    buildkite.NewClient(agentToken),
		gh:     gh,
	}
	s.ClearCache()
	// Buildkite requires (but ignores) the specified queue.
	// Let's just specify the first alphabetically.
	queueKeys := make([]string, 0, len(queues))
	for q := range queues {
		queueKeys = append(queueKeys, q)
	}
	slices.Sort(queueKeys)
	if err := s.register(ctx, queueKeys[0]); err != nil {
		return nil, err
	}
	return s, nil
}

// Destroy deregisters the stack.
func (s *BuildkiteStack) Destroy(ctx context.Context) error {
	if err := s.api.DeregisterStack(ctx, s.key); err != nil {
		return fmt.Errorf("failed to deregister stack %q: %w", s.key, err)
	}
	return nil
}

// ClearCache clears and re-initializes the stack's caches.
func (s *BuildkiteStack) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metadataCache = make(map[BuildUUID]BuildMetadata)
}

// CleanupJobs removes jobs from the pool whose tokens will soon expire, or
// that are no longer reserved (e.g. because they were cancelled or their
// reservation lapsed), along with any builds left with no jobs. Job states are
// fetched in bulk.
//
// The pool is locked throughout, including while fetching job states, so the
// set of jobs checked is exactly the set pruned.
func (s *BuildkiteStack) CleanupJobs(ctx context.Context, pool *JobPool) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Fetch all jobs' states
	jobIDs := pool.jobIDsLocked()
	states, err := s.jobStates(ctx, jobIDs)
	if err != nil {
		return err
	}

	expiryCutoff := time.Now().Add(tokenMinLifetime)
	for _, q := range pool.queues {
		for _, builds := range []map[BuildUUID]Build{q.trustedBuilds, q.untrustedBuilds} {
			for uuid, b := range builds {
				for jobID, token := range b.reservedJobs {
					if state := states[jobID]; state != "reserved" {
						// Job was not reported by Buildkite as reserved; remove it
						delete(b.reservedJobs, jobID)
					} else if token.expiresAt.Before(expiryCutoff) {
						// Tokens that will expire soon will likely expire before an agent gets
						// around to fetching them, so we may as well re-generate them early
						delete(b.reservedJobs, jobID)
					}
				}
				if len(b.reservedJobs) == 0 {
					delete(builds, uuid)
				}
			}
		}
	}
	return nil
}

// Replenish replenishes pool so each build has the configured number of
// JATs queued.
func (s *BuildkiteStack) Replenish(ctx context.Context, pool *JobPool, listLimit uint) error {
	type candidate struct {
		queue    string
		build    BuildUUID
		metadata BuildMetadata
	}

	// List scheduled jobs on all queues before taking the pool lock
	jobsByQueue := make(map[string][]buildkite.ScheduledJob)
	for queue := range s.queues {
		jobs, err := s.scheduledJobs(ctx, queue, listLimit)
		if err != nil {
			return err
		}
		jobsByQueue[queue] = jobs
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	var jobIDs []JobUUID
	candidates := make(map[JobUUID]candidate)
	now := time.Now()
	for queue, jobs := range jobsByQueue {
		// needed is how many more jobs each build on this queue needs.
		needed := make(map[BuildUUID]uint)

		// Iterate over the list of candidate jobs fetched from Buildkite
		for _, job := range jobs {
			if !slices.Contains(job.AgentQueryRules, "stacktest=yes") {
				// TODO: for now, during development of the coordinator,
				// only activate on jobs containing `stacktest=yes`
				continue
			}
			if job.RunnableAt.After(now) {
				// Skip jobs not yet marked as runnable
				continue
			}
			buildUUID := BuildUUID(job.Build.UUID)

			n, ok := needed[buildUUID]
			if !ok {
				// How many more jobs does this build need?
				count := pool.countLocked(queue, buildUUID)
				if count < pool.jobsPerBuild {
					n = pool.jobsPerBuild - count
				}
				needed[buildUUID] = n
			}
			if n == 0 {
				// We already have jobsPerBuild JATs ready for this build
				continue
			}
			needed[buildUUID] = n - 1

			jobUUID := JobUUID(job.ID)
			metadata, err := s.GetBuildMetadata(ctx, buildUUID, jobUUID)
			if err != nil {
				log.Printf("Warning: failed to fetch metadata for build %s, treating as untrusted: %v", buildUUID, err)
			}
			candidates[jobUUID] = candidate{queue: queue, build: buildUUID, metadata: metadata}
			jobIDs = append(jobIDs, jobUUID)
		}
	}
	if len(jobIDs) == 0 {
		return nil
	}

	// Batch-reserve all the jobs
	reserved, err := s.reserveJobs(ctx, jobIDs)
	if err != nil {
		return err
	}
	// Batch-issue JATs for all the jobs
	tokens, err := s.issueJobAcquisitionTokens(ctx, reserved)
	if err != nil {
		return err
	}

	// Add every job to the pool
	for jobUUID, token := range tokens {
		c := candidates[jobUUID]
		pool.addLocked(c.queue, c.build, c.metadata, jobUUID, token)
	}
	log.Printf("Reserved %d jobs and added %d to the pool", len(reserved), len(tokens))

	return nil
}

// GetBuildMetadata returns the metadata of the given build, of which jobID must
// be one of the jobs.
//
// If the returned error is non-nil, the returned BuildMetadata will be treated as
// untrusted.
func (s *BuildkiteStack) GetBuildMetadata(ctx context.Context, uuid BuildUUID, jobID JobUUID) (BuildMetadata, error) {
	s.mu.Lock()
	metadata, ok := s.metadataCache[uuid]
	s.mu.Unlock()
	if ok {
		return metadata, nil
	}

	env, err := s.jobEnv(ctx, jobID)
	if err != nil {
		return BuildMetadata{}, err
	}
	if got := BuildUUID(env["BUILDKITE_BUILD_ID"]); got != uuid {
		return BuildMetadata{}, fmt.Errorf("job %s belongs to build %s, not %s", jobID, got, uuid)
	}

	source := env["BUILDKITE_SOURCE"]
	switch source {
	case buildSourceWebhook, buildSourceAPI, buildSourceUI:
		pr := env["BUILDKITE_PULL_REQUEST"]
		if pr == "" || pr == "false" {
			// builds without BUILDKITE_PULL_REQUEST did not originate from a PR
			// (e.g. pushed builds for webhook, manual retries for ui/api).
			metadata = BuildMetadata{source: source, nonPR: true}
			break
		}

		prNumber, err := strconv.Atoi(pr)
		if err != nil {
			return BuildMetadata{source: source}, fmt.Errorf("job %s has invalid BUILDKITE_PULL_REQUEST %q", jobID, pr)
		}
		author, err := s.gh.prAuthor(ctx, prNumber)
		if err != nil {
			return BuildMetadata{source: source}, err
		}
		metadata = BuildMetadata{
			source:      source,
			nonPR:       false,
			prNumber:    prNumber,
			authorKnown: true,
			author:      author,
		}

	default:
		// Other sources treated as author-unknown (for now)
		metadata = BuildMetadata{source: source}
	}

	s.mu.Lock()
	s.metadataCache[uuid] = metadata
	s.mu.Unlock()
	return metadata, nil
}

// register registers the stack.
func (s *BuildkiteStack) register(ctx context.Context, queue string) error {
	_, err := s.api.RegisterStack(ctx, buildkite.RegisterStackRequest{
		Key:      s.key,
		Type:     "custom",
		QueueKey: queue,
		Metadata: map[string]string{"implementation": "gvisor-buildkite-coordinator"},
	})
	if err != nil {
		return fmt.Errorf("failed to register stack %q: %w", s.key, err)
	}
	return nil
}

// scheduledJobs returns up to limit of the scheduled jobs on the given queue.
func (s *BuildkiteStack) scheduledJobs(ctx context.Context, queue string, limit uint) ([]buildkite.ScheduledJob, error) {
	var jobs []buildkite.ScheduledJob
	after := ""
	for uint(len(jobs)) < limit {
		pageSize := min(limit-uint(len(jobs)), buildkite.MaxPageSize)
		page, err := s.api.ListScheduledJobs(ctx, s.key, queue, pageSize, after)
		if err != nil {
			return nil, fmt.Errorf("failed to list scheduled jobs on queue %q: %w", queue, err)
		}
		// The Stacks API requires that no new jobs are started while dispatch
		// is paused on the queue.
		if page.ClusterQueue.DispatchPaused {
			return nil, nil
		}
		jobs = append(jobs, page.Jobs...)
		if !page.PageInfo.HasNextPage || page.PageInfo.EndCursor == "" {
			break
		}
		after = page.PageInfo.EndCursor
	}
	return jobs, nil
}

// jobEnv returns the environment of the given job.
func (s *BuildkiteStack) jobEnv(ctx context.Context, jobID JobUUID) (map[string]string, error) {
	job, err := s.api.GetJob(ctx, s.key, string(jobID))
	if err != nil {
		return nil, fmt.Errorf("failed to get job %s: %w", jobID, err)
	}
	return job.Env, nil
}

// reserveJobs reserves the given jobs for reservationExpiry, and returns the
// ones that were successfully reserved.
func (s *BuildkiteStack) reserveJobs(ctx context.Context, jobIDs []JobUUID) ([]JobUUID, error) {
	var reserved []JobUUID
	for chunk := range slices.Chunk(jobIDs, buildkite.MaxBatchSize) {
		ids, err := s.api.ReserveJobs(ctx, s.key, jobIDStrings(chunk), reservationExpiry)
		if err != nil {
			return nil, fmt.Errorf("failed to reserve jobs: %w", err)
		}
		for _, id := range ids {
			reserved = append(reserved, JobUUID(id))
		}
	}
	return reserved, nil
}

// issueJobAcquisitionTokens issues job acquisition tokens for the given reserved
// jobs, and returns the tokens that were successfully issued.
func (s *BuildkiteStack) issueJobAcquisitionTokens(ctx context.Context, jobIDs []JobUUID) (map[JobUUID]JobAcquisitionToken, error) {
	tokens := make(map[JobUUID]JobAcquisitionToken)
	for chunk := range slices.Chunk(jobIDs, buildkite.MaxBatchSize) {
		issued, err := s.api.GetJobAcquisitionTokens(ctx, s.key, jobIDStrings(chunk), reservationExpiry)
		if err != nil {
			return nil, fmt.Errorf("failed to get job acquisition tokens: %w", err)
		}
		for _, t := range issued {
			tokens[JobUUID(t.JobUUID)] = JobAcquisitionToken{token: t.Token, expiresAt: t.ExpiresAt}
		}
	}
	return tokens, nil
}

// jobStates returns the states of the given jobs, by job.
func (s *BuildkiteStack) jobStates(ctx context.Context, jobIDs []JobUUID) (map[JobUUID]string, error) {
	states := make(map[JobUUID]string)
	for chunk := range slices.Chunk(jobIDs, buildkite.MaxBatchSize) {
		got, err := s.api.GetJobStates(ctx, s.key, jobIDStrings(chunk))
		if err != nil {
			return nil, fmt.Errorf("failed to get job states: %w", err)
		}
		for id, state := range got {
			states[JobUUID(id)] = state
		}
	}
	return states, nil
}

// jobIDStrings converts a job UUID slice to strings.
func jobIDStrings(jobIDs []JobUUID) []string {
	ids := make([]string, len(jobIDs))
	for i, id := range jobIDs {
		ids[i] = string(id)
	}
	return ids
}
