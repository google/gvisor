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

// Package main implements the Buildkite coordinator.
//
// Currently WIP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	compute "google.golang.org/api/compute/v1"
	"gvisor.dev/gvisor/pkg/cleanup"
)

const (
	clearCacheInterval             = 4 * time.Hour
	buildkiteCleanupJobsInterval   = 3 * time.Second
	buildkiteReplenishJobsInterval = 10 * time.Second

	// buildkiteListMaxJobs is how many scheduled jobs are considered per
	// queue on each refresh.
	buildkiteListMaxJobs = 10_000

	// reservedJobsPerBuild is how many reserved jobs, with job acquisition
	// tokens, the pool keeps ready for each build on each queue.
	reservedJobsPerBuild = 10

	// httpShutdownTimeout and stackShutdownTimeout bound draining requests and
	// deregistering the stack at shutdown.
	httpShutdownTimeout  = 10 * time.Second
	stackShutdownTimeout = 10 * time.Second

	failedJobCancelTimeout = 5 * time.Second

	// artifactTokenTimeout bounds fetching a job's artifact token.
	artifactTokenTimeout = 10 * time.Second
)

type server struct {
	// stack is safe for concurrent use.
	stack *BuildkiteStack
	// tc is safe for concurrent use.
	tc *TimeoutController
	// rc is safe for concurrent use.
	rc *RateLimitController
	// artifactTokenController is safe for concurrent use.
	artifactTokenController *BucketTokenController

	// pool is safe for concurrent use.
	pool *JobPool

	// The following fields are immutable.
	cfg        config
	computeSvc *compute.Service
}

func newServer(ctx context.Context) *server {
	// Load the server config
	cfg, err := loadConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Expecting agent identity tokens with audience %s, service account %s, project %s",
		cfg.serviceURL, cfg.agentServiceAccount, cfg.project)

	// Fetch the Buildkite agent bkToken
	bkToken, err := accessSecret(ctx, cfg.bkTokenProject, cfg.bkTokenSecret)
	if err != nil {
		log.Fatalf("Failed to read Buildkite agent token: %v", err)
	}

	// Fetch the GitHub token
	ghToken, err := accessSecret(ctx, cfg.githubTokenProject, cfg.githubTokenSecret)
	if err != nil {
		log.Fatalf("Failed to read GitHub agent token: %v", err)
	}

	// Compute Engine client
	computeSvc, err := compute.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create compute client: %v", err)
	}

	// GitHub client
	ghClient := newGitHubClient(ghToken)

	// Create the Buildkite stack
	stack, err := NewStack(ctx, cfg.stackKey, bkToken, ghClient, cfg.queues)
	if err != nil {
		log.Fatalf("Failed to create Buildkite stack: %v", err)
	}

	// Create the instance timeout controller
	tc, err := NewTimeoutController(ctx, computeSvc, cfg.project, cfg.agentServiceAccount)
	if err != nil {
		log.Fatalf("Failed to create instance timeout controller: %v", err)
	}

	// Create the rate limiting controller
	rc, err := NewRateLimitController(ctx, cfg.project, cfg.rateLimitCollection, rateLimits)
	if err != nil {
		log.Fatalf("Failed to create rate limiting controller: %v", err)
	}

	// Create the artifact token issuer
	artifactTokenController, err := NewBucketTokenController(ctx, cfg.artifactBucket, artifactRoles)
	if err != nil {
		log.Fatalf("Failed to create artifact token issuer: %v", err)
	}

	return &server{
		cfg:                     cfg,
		computeSvc:              computeSvc,
		stack:                   stack,
		tc:                      tc,
		rc:                      rc,
		artifactTokenController: artifactTokenController,
		pool:                    NewJobPool(reservedJobsPerBuild, cfg.queues, cfg.trustedAuthors),
	}
}

// AgentRequestJobResponse represents a response from the coordinator to
// an agent requesting a job.
type AgentRequestJobResponse struct {
	JobUUID             string `json:"job_uuid"`
	JobAcquisitionToken string `json:"job_acquisition_token"`
	ArtifactToken       string `json:"artifact_token"`
}

func (s *server) handleAgentRequestJob(w http.ResponseWriter, r *http.Request) {
	idToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	id, err := verifyInstanceIdentity(r.Context(), s.cfg, idToken, s.cfg.serviceURL)
	if err != nil {
		log.Printf("Rejected agent request: %v", err)
		http.Error(w, "invalid identity token", http.StatusUnauthorized)
		return
	}

	// Get info about the agent
	agent, err := id.getAgent(r.Context(), s.computeSvc)
	if err != nil {
		log.Printf("Failed to get agent info for %v: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Try to pick a job for the agent
	jobAssignment, pinAgent := s.pool.assignJob(s.computeSvc, agent)
	if jobAssignment == nil {
		// No job currently available for this agent
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// failJob tries to fail the job in Buildkite, logging an error if it was unsuccessful.
	failJob := func(exitStatus int, detail string) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), failedJobCancelTimeout)
		defer cancel()
		err := s.stack.FailJob(ctx, jobAssignment.jobUUID, exitStatus, detail)
		if err != nil {
			log.Printf("Warning: failed to fail job %v in Buildkite: %v", jobAssignment.jobUUID, err)
		}
		return err
	}

	// Common error handling logic for all the below steps
	restoreJobToPoolCleanup := cleanup.Make(func() {
		// Restore the job back to the pool so it can be retried
		added := s.pool.add(jobAssignment.queue, jobAssignment.buildUUID, jobAssignment.metadata, jobAssignment.jobUUID, jobAssignment.jat)
		if !added {
			// If the job was not added back to the pool (e.g. because we ran out of retries),
			// fail the job in Buildkite.
			failJob(exitStatusInfraError, "Error provisioning infrastructure")
		}
	})
	defer restoreJobToPoolCleanup.Clean()

	// Try to get the job's timeout from Buildkite. Otherwise, default to jobTimeout.
	timeout := jobTimeout
	bkTimeout, err := s.stack.jobTimeout(r.Context(), jobAssignment.jobUUID)
	if err != nil {
		log.Printf("Warning: failed to fetch job timeout for job %v in Buildkite: %v", jobAssignment.jobUUID, err)
	} else if bkTimeout != nil && *bkTimeout > time.Duration(0) {
		// Add a small grace period to the Buildkite timeout to account for agent
		// setup, etc.
		timeout = *bkTimeout + setupGracePeriod
	}
	// Clamp the buildkite-specified timeout to jobTimeout
	timeout = min(timeout, jobTimeout)

	var unaccountCleanup *cleanup.Cleanup
	if !s.pool.trusted(jobAssignment.metadata) {
		// Account for the job for this author.
		author := jobAssignment.metadata.author
		now := time.Now()
		success, interval, quota, err := s.rc.AccountForTime(r.Context(), author, now, timeout)
		if err != nil {
			log.Printf("Failed to account for job for author %v: %v", author, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !success {
			// Author is rate-limited!

			// Fail the job in Buildkite.
			bkExitDetail := fmt.Sprintf("Author with GitHub ID %v has reached %v day quota of %v compute-minutes", author, interval, quota)
			err := failJob(exitStatusRateLimited, bkExitDetail)
			if err == nil {
				// If we successfully failed the job in Buildkite, don't retry at the
				// coordinator level.
				restoreJobToPoolCleanup.Release()
			}

			// Finally, indicate no available job to the agent
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// On failure, unaccount for the job
		c := cleanup.Make(func() {
			// The request may have been cancelled; unaccount regardless.
			err := s.rc.UnaccountForTime(context.WithoutCancel(r.Context()), author, now, timeout)
			if err != nil {
				log.Printf("Warning: failed to unaccount for job %v for author %v: %v", jobAssignment.jobUUID, author, err)
			}
		})
		defer c.Clean()
		unaccountCleanup = &c
	}

	// Get a token for the agent to upload artifacts with.
	tokenCtx, cancel := context.WithTimeout(r.Context(), artifactTokenTimeout)
	token, err := s.artifactTokenController.GetToken(tokenCtx, artifactPrefix(jobAssignment.buildUUID), timeout)
	cancel()
	if err != nil {
		log.Printf("Failed to get artifact token for job %v: %v", jobAssignment.jobUUID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	artifactToken := token.Value

	// Pin the agent
	agent, err = pinAgent(r.Context())
	if err != nil {
		log.Printf("Failed to pin %v: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Before assigning the job: register a job timeout to kill the agent if it's
	// not done.
	err = s.tc.RegisterTimeout(r.Context(), id, timeout)
	if err != nil {
		log.Printf("Failed to register timeout for %v: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Ideally, if any of the below steps fail, we would undo the per-author job
	// accounting we did since the job didn't run successfully.
	//
	// Unfortunately, we can't because once the timeout is reset, the author gets
	// access to another timeout worth of compute time regardless of the failure.
	//
	// So we account for a job even when the below steps fail. Oh well.
	if unaccountCleanup != nil {
		unaccountCleanup.Release()
	}

	// Assign the job to the agent
	log.Printf("Assigning job %v to %v", jobAssignment.jobUUID, agent)
	w.Header().Set("Content-Type", "application/json")
	response := AgentRequestJobResponse{
		JobUUID:             string(jobAssignment.jobUUID),
		JobAcquisitionToken: jobAssignment.jat.token,
		ArtifactToken:       artifactToken,
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to assign job %v to %v: %v", jobAssignment.jobUUID, agent, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	restoreJobToPoolCleanup.Release()
}

func (s *server) runClearCacheTicker() {
	ticker := time.Tick(clearCacheInterval)
	for {
		<-ticker
		s.stack.ClearCache()
	}
}
func (s *server) runBuildkiteCleanupJobsTicker(ctx context.Context) {
	ticker := time.Tick(buildkiteCleanupJobsInterval)
	for {
		<-ticker
		ctx, cancel := context.WithTimeout(ctx, buildkiteCleanupJobsInterval)
		err := s.stack.CleanupJobs(ctx, s.pool)
		cancel()
		if err != nil {
			log.Printf("Failed to cleanup jobs: %v", err)
		}
	}
}

func (s *server) runBuildkiteReplenishJobsTicker(ctx context.Context) {
	ticker := time.Tick(buildkiteReplenishJobsInterval)
	for ; true; <-ticker {
		ctx, cancel := context.WithTimeout(ctx, buildkiteReplenishJobsInterval)
		err := s.stack.Replenish(ctx, s.pool, buildkiteListMaxJobs)
		cancel()
		if err != nil {
			log.Printf("Failed to replenish reserved jobs: %v", err)
		}
	}
}

func main() {
	ctx := context.Background()
	s := newServer(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/request_job", s.handleAgentRequestJob)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {})
	srv := &http.Server{
		Addr:              ":" + s.cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}

	go s.runClearCacheTicker()
	go s.runBuildkiteCleanupJobsTicker(ctx)
	go s.runBuildkiteReplenishJobsTicker(ctx)

	// When the coordinator VM shuts down, SIGTERM is sent
	notifyContext, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		log.Printf("Listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server failed: %v", err)
		}
	}()
	<-notifyContext.Done()

	log.Printf("Shutting down")

	// Try to finish any in-flight HTTP requests
	httpCtx, cancel := context.WithTimeout(ctx, httpShutdownTimeout)
	if err := srv.Shutdown(httpCtx); err != nil {
		log.Printf("Failed to shut down HTTP server cleanly: %v", err)
	}
	cancel()

	// Unregister the stack on Buildkite
	stackCtx, cancel := context.WithTimeout(ctx, stackShutdownTimeout)
	defer cancel()
	if err := s.stack.Destroy(stackCtx); err != nil {
		log.Printf("Failed to deregister stack: %v", err)
		return
	}
	log.Printf("Deregistered stack %s", s.cfg.stackKey)
}
