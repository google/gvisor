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

	// httpShutdownTimeout and stackShutdownTimeout split Cloud Run's 10
	// second shutdown period between draining requests and deregistering the
	// stack.
	httpShutdownTimeout  = 3 * time.Second
	stackShutdownTimeout = 6 * time.Second

	failedJobCancelTimeout = 5 * time.Second
)

type server struct {
	// stack is safe for concurrent use.
	stack *BuildkiteStack
	// tc is safe for concurrent use.
	tc *TimeoutController
	// rc is safe for concurrent use.
	rc *RateLimitController

	// pool is safe for concurrent use.
	pool *JobPool

	// The following fields are immutable.
	cfg        config
	audience   string
	computeSvc *compute.Service
}

func newServer(ctx context.Context) *server {
	// Load the server config
	cfg, err := loadConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	audience, err := serviceURL(ctx)
	if err != nil {
		log.Fatalf("Failed to compute service URL: %v", err)
	}
	log.Printf("Expecting agent identity tokens with audience %s, service account %s, project %s",
		audience, cfg.agentServiceAccount, cfg.project)

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
	tc, err := NewTimeoutController(ctx, computeSvc, cfg.project)
	if err != nil {
		log.Fatalf("Failed to create instance timeout controller: %v", err)
	}

	// Create the rate limiting controller
	rc, err := NewRateLimitController(ctx, cfg.project, cfg.rateLimitCollection, rateLimits)
	if err != nil {
		log.Fatalf("Failed to create rate limiting controller: %v", err)
	}

	return &server{
		cfg:        cfg,
		audience:   audience,
		computeSvc: computeSvc,
		stack:      stack,
		tc:         tc,
		rc:         rc,
		pool:       NewJobPool(reservedJobsPerBuild, cfg.queues, cfg.trustedAuthors),
	}
}

// AgentRequestJobResponse represents a response from the coordinator to
// an agent requesting a job.
type AgentRequestJobResponse struct {
	JobUUID             string `json:"job_uuid"`
	JobAcquisitionToken string `json:"job_acquisition_token"`
}

func (s *server) handleAgentRequestJob(w http.ResponseWriter, r *http.Request) {
	idToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	id, err := verifyInstanceIdentity(r.Context(), s.cfg, idToken, s.audience)
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

	// Common error handling logic for all the below steps
	bkExitStatus := exitStatusInfraError
	bkExitDetail := "Error provisioning infrastructure"
	bkFailJobCleanup := cleanup.Make(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), failedJobCancelTimeout)
		defer cancel()
		err := s.stack.FailJob(ctx, jobAssignment.jobUUID, bkExitStatus, bkExitDetail)
		if err != nil {
			log.Printf("Warning: failed to fail job %v in Buildkite: %v", jobAssignment.jobUUID, err)
		}
	})
	defer bkFailJobCleanup.Clean()

	if !s.pool.trusted(jobAssignment.metadata) {
		// Account for a job for this author.
		author := jobAssignment.metadata.author
		success, interval, quota, err := s.rc.AccountForJob(r.Context(), jobAssignment.metadata.author)
		if err != nil {
			log.Printf("Failed to account for job for author %v: %v", author, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !success {
			// Author is rate-limited!
			w.WriteHeader(http.StatusNoContent)
			bkExitStatus = exitStatusRateLimited
			bkExitDetail = fmt.Sprintf("Author with GitHub ID %v has exceeded %v day quota of %v jobs", author, interval, quota)
			return
		}
	}

	// Ideally, if any of the below steps fail, we would undo the per-author job
	// accounting we just did, since the job didn't run successfully.
	//
	// Unfortunately, we can't because once the timeout is reset, the author gets
	// access to another jobTimeout worth of compute time regardless of the failure.
	//
	// So we account for a job even when the below steps fail. Oh well.

	// Before assigning the job: register a job timeout to kill the agent if it's
	// not done.
	err = s.tc.RegisterTimeout(r.Context(), id)
	if err != nil {
		log.Printf("Failed to register timeout for %v: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If all the above succeeds, pin the agent
	agent, err = pinAgent(r.Context())
	if err != nil {
		log.Printf("Failed to pin %v: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Assign the job to the agent
	log.Printf("Assigning job %v to %v", jobAssignment.jobUUID, agent)
	w.Header().Set("Content-Type", "application/json")
	response := AgentRequestJobResponse{
		JobUUID:             string(jobAssignment.jobUUID),
		JobAcquisitionToken: jobAssignment.jat.token,
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to assign job %v to %v: %v", jobAssignment.jobUUID, agent, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	bkFailJobCleanup.Release()
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
	srv := &http.Server{
		Addr:              ":" + s.cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}

	go s.runClearCacheTicker()
	go s.runBuildkiteCleanupJobsTicker(ctx)
	go s.runBuildkiteReplenishJobsTicker(ctx)

	// Cloud Run sends SIGTERM to allow for cleanup when the container is killed
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
