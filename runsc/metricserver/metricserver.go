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

// Package metricserver implements a Prometheus metric server for runsc data.
package metricserver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/metricserver/containermetrics"
	"gvisor.dev/gvisor/runsc/sandbox"
)

const (
	// metricsExportTimeout is the maximum amount of time that the metrics export process should take.
	metricsExportTimeout = 30 * time.Second

	// metricsExportPerSandboxTimeout is the maximum amount of time that we wait on any individual
	// sandbox when exporting its metrics.
	metricsExportPerSandboxTimeout = 8 * time.Second

	// exportParallelGoroutines is the maximum number of goroutines spawned during metrics export.
	exportParallelGoroutines = 8
)

// servedSandbox is a sandbox that we serve metrics from.
// A single metrics server will export data about multiple sandboxes.
type servedSandbox struct {
	rootContainerID container.FullID
	server          *metricServer
	extraLabels     map[string]string

	// mu protects the fields below.
	mu sync.Mutex

	// sandbox is the sandbox being monitored.
	// Once set, it is immutable.
	sandbox *sandbox.Sandbox

	// createdAt stores the time the sandbox was created.
	// It is loaded from the container state file.
	// Once set, it is immutable.
	createdAt time.Time

	// capabilities is the union of the capability set of the containers within `sandbox`.
	// It is used to export a per-sandbox metric representing which capabilities are in use.
	// For monitoring purposes, a capability added in a container means it is considered
	// added for the whole sandbox.
	capabilities []linux.Capability

	// specMetadataLabels is the set of label exported as part of the
	// `spec_metadata` metric.
	specMetadataLabels map[string]string

	// verifier allows verifying the data integrity of the metrics we get from this sandbox.
	// It is not always initialized when the sandbox is discovered, but rather upon first metrics
	// access to the sandbox. Metric registration data is loaded from the root container's
	// state file.
	// The server needs to load this registration data before any data from this sandbox is
	// served to HTTP clients. If there is no metric registration data within the Container
	// data, then metrics were not requested for this sandbox, and this servedSandbox should
	// be deleted from the server.
	// Once set, it is immutable.
	verifier *prometheus.Verifier

	// cleanupVerifier holds a reference to the cleanup function of the verifier.
	cleanupVerifier func()

	// extra contains additional per-sandbox data.
	extra sandboxData
}

// load loads the sandbox being monitored and initializes its metric verifier.
// If it returns an error other than container.ErrStateFileLocked, the sandbox is either
// non-existent, or has not requested instrumentation to be enabled, or does not have
// valid metric registration data. In any of these cases, the sandbox should be removed
// from this metrics server.
func (s *servedSandbox) load() (*sandbox.Sandbox, *prometheus.Verifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sandbox == nil {
		allContainers, err := container.LoadSandbox(s.server.rootDir, s.rootContainerID.SandboxID, container.LoadOpts{
			TryLock: container.TryAcquire,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load sandbox %q: %v", s.rootContainerID.SandboxID, err)
		}
		var rootContainer *container.Container
		for _, cont := range allContainers {
			if cont.IsSandboxRoot() {
				if rootContainer != nil {
					return nil, nil, fmt.Errorf("multiple root contains found for sandbox ID %q: %v and %v", s.rootContainerID.SandboxID, cont, rootContainer)
				}
				rootContainer = cont
			}
		}
		if rootContainer == nil {
			return nil, nil, fmt.Errorf("no root container found for sandbox ID %q", s.rootContainerID.SandboxID)
		}
		sandboxMetricAddr := strings.ReplaceAll(rootContainer.Sandbox.MetricServerAddress, "%RUNTIME_ROOT%", s.server.rootDir)
		if sandboxMetricAddr == "" {
			return nil, nil, errors.New("sandbox did not request instrumentation")
		}
		if sandboxMetricAddr != s.server.address {
			return nil, nil, fmt.Errorf("sandbox requested instrumentation by a metric server running at a different address (sandbox wants %q, this metric server serves %q)", sandboxMetricAddr, s.server.address)
		}
		// Update label data as read from the state file.
		// Do not store empty labels.
		authoritativeLabels, err := containermetrics.SandboxPrometheusLabels(rootContainer)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot compute Prometheus labels of sandbox: %v", err)
		}
		s.extraLabels = make(map[string]string, len(authoritativeLabels))
		for _, label := range []string{
			prometheus.SandboxIDLabel,
			prometheus.IterationIDLabel,
			prometheus.PodNameLabel,
			prometheus.NamespaceLabel,
		} {
			s.extraLabels[label] = authoritativeLabels[label]
			if s.extraLabels[label] == "" {
				delete(s.extraLabels, label)
			}
		}

		// Compute capability set.
		allCaps := linux.AllCapabilities()
		capSet := make([]linux.Capability, 0, len(allCaps))
		for _, cap := range allCaps {
			for _, cont := range allContainers {
				if cont.HasCapabilityInAnySet(cap) {
					capSet = append(capSet, cap)
					break
				}
			}
		}
		if len(capSet) > 0 {
			// Reallocate a slice with minimum size, since it will be long-lived.
			s.capabilities = make([]linux.Capability, len(capSet))
			for i, capLabels := range capSet {
				s.capabilities[i] = capLabels
			}
		}

		// Compute spec metadata.
		s.specMetadataLabels = containermetrics.ComputeSpecMetadata(allContainers)

		s.sandbox = rootContainer.Sandbox
		s.createdAt = rootContainer.CreatedAt
	}
	if s.verifier == nil {
		registeredMetrics, err := s.sandbox.GetRegisteredMetrics()
		if err != nil {
			return nil, nil, err
		}
		verifier, cleanup, err := prometheus.NewVerifier(registeredMetrics)
		if err != nil {
			return nil, nil, err
		}
		s.verifier = verifier
		s.cleanupVerifier = cleanup
	}
	if err := s.extra.load(s); err != nil {
		return nil, nil, err
	}
	return s.sandbox, s.verifier, nil
}

func (s *servedSandbox) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleanupVerifier != nil {
		s.cleanupVerifier()
	}
}

// querySandboxMetrics queries the sandbox for metrics data.
func querySandboxMetrics(ctx context.Context, sand *sandbox.Sandbox, verifier *prometheus.Verifier, metricsFilter string) (*prometheus.Snapshot, error) {
	ch := make(chan struct {
		snapshot *prometheus.Snapshot
		err      error
	}, 1)
	canceled := make(chan struct{}, 1)
	defer close(canceled)
	go func() {
		snapshot, err := sand.ExportMetrics(control.MetricsExportOpts{
			OnlyMetrics: metricsFilter,
		})
		select {
		case <-canceled:
		case ch <- struct {
			snapshot *prometheus.Snapshot
			err      error
		}{snapshot, err}:
			close(ch)
		}
	}()
	select {
	case <-ctx.Done():
		canceled <- struct{}{}
		return nil, ctx.Err()
	case ret := <-ch:
		if ret.err != nil {
			return nil, ret.err
		}
		if err := verifier.Verify(ret.snapshot); err != nil {
			return nil, err
		}
		return ret.snapshot, nil
	}
}

// metricServer implements the metric server.
type metricServer struct {
	rootDir                string
	pid                    int
	pidFile                string
	allowUnknownRoot       bool
	exposeProfileEndpoints bool
	address                string
	exporterPrefix         string
	startTime              time.Time
	srv                    http.Server

	// Size of the map of written metrics during the last /metrics export. Initially zero.
	// Used to efficiently reallocate a map of the right size during the next export.
	lastMetricsWrittenSize atomicbitops.Uint32

	// Pool of `prometheus.ReusableWriter`s. Used to avoid large buffer allocations for
	// successive snapshots.
	promWriterPool sync.Pool

	// mu protects the fields below.
	mu sync.Mutex

	// udsPath is a path to a Unix Domain Socket file on which the server is bound and which it owns.
	// This socket file will be deleted on server shutdown.
	// This field is not set if binding to a network port, or when the UDS already existed prior to
	// being bound by us (i.e. its ownership isn't ours), such that it isn't deleted in this case.
	// The field is unset once the file is successfully removed.
	udsPath string

	// sandboxes is the list of sandboxes we serve metrics for.
	sandboxes map[container.FullID]*servedSandbox

	// lastStateFileStat maps container full IDs to the last observed stat() of their state file.
	// This is used to monitor for sandboxes in the background. If a sandbox's state file matches this
	// info, we can assume that the last background scan already looked at it.
	lastStateFileStat map[container.FullID]os.FileInfo

	// lastValidMetricFilter stores the last value of the "runsc-sandbox-metrics-filter" parameter for
	// /metrics requests.
	// It represents the last-known compilable regular expression that was passed to /metrics.
	// It is used to avoid re-verifying this parameter in the common case where a single scraper
	// is consistently passing in the same value for this parameter in each successive request.
	lastValidMetricFilter string

	// lastValidCapabilityFilterStr stores the last value of the "runsc-capability-filter" parameter
	// for /metrics requests.
	// It represents the last-known compilable regular expression that was passed to /metrics.
	// It is used to avoid re-verifying this parameter in the common case where a single scraper
	// is consistently passing in the same value for this parameter in each successive request.
	lastValidCapabilityFilterStr string

	// lastValidCapabilityFilterReg is the compiled regular expression corresponding to
	// lastValidCapabilityFilterStr.
	lastValidCapabilityFilterReg *regexp.Regexp

	// numSandboxes counts the number of sandboxes that have ever been registered on this server.
	// Used to distinguish between the case where this metrics serve has sat there doing nothing
	// because no sandbox ever registered against it (which is unexpected), vs the case where it has
	// done a good job serving sandbox metrics and it's time for it to gracefully die as there are no
	// more sandboxes to serve.
	// Also exported as a metric of total number of sandboxes started.
	numSandboxes int64

	// shuttingDown is flipped to true when the server shutdown process has started.
	// Used to deal with race conditions where a sandbox is trying to register after the server has
	// already started to go to sleep.
	shuttingDown bool

	// shutdownCh is written to when receiving the signal to shut down gracefully.
	shutdownCh chan os.Signal

	// extraData contains additional server-wide data.
	extra serverData
}

// sufficientlyEqualStats returns whether the given FileInfo's are sufficiently
// equal to assume the file they represent has not changed between the time
// each FileInfo was obtained.
func sufficientlyEqualStats(s1, s2 os.FileInfo) bool {
	if !s1.ModTime().Equal(s2.ModTime()) {
		return false
	}
	if s1.Size() != s2.Size() {
		return false
	}
	statT1, ok1 := s1.Sys().(*syscall.Stat_t)
	statT2, ok2 := s2.Sys().(*syscall.Stat_t)
	if ok1 != ok2 {
		return false
	}
	if ok1 && ok2 {
		if statT1.Dev != statT2.Dev {
			return false
		}
		if statT1.Ino != statT2.Ino {
			return false
		}
	}
	return true
}

// refreshSandboxesLocked removes sandboxes that are no longer running from m.sandboxes, and
// adds sandboxes found in the root directory that do request instrumentation.
// Preconditions: m.mu is locked.
func (m *metricServer) refreshSandboxesLocked() {
	if m.shuttingDown {
		// Do nothing to avoid log spam.
		return
	}
	sandboxIDs, err := container.ListSandboxes(m.rootDir)
	if err != nil {
		if !m.allowUnknownRoot {
			log.Warningf("Cannot list containers in root directory %s, it has likely gone away: %v.", m.rootDir, err)
		}
		return
	}
	for sandboxID, sandbox := range m.sandboxes {
		found := false
		for _, sid := range sandboxIDs {
			if sid == sandboxID {
				found = true
				break
			}
		}
		if !found {
			log.Warningf("Sandbox %s no longer exists but did not explicitly unregister. Removing it.", sandboxID)
			sandbox.cleanup()
			delete(m.sandboxes, sandboxID)
			continue
		}
		if _, _, err := sandbox.load(); err != nil && err != container.ErrStateFileLocked {
			log.Warningf("Sandbox %s cannot be loaded, deleting it: %v", sandboxID, err)
			sandbox.cleanup()
			delete(m.sandboxes, sandboxID)
			continue
		}
		if !sandbox.sandbox.IsRunning() {
			log.Infof("Sandbox %s is no longer running, deleting it.", sandboxID)
			sandbox.cleanup()
			delete(m.sandboxes, sandboxID)
			continue
		}
	}
	newSandboxIDs := make(map[container.FullID]bool, len(sandboxIDs))
	for _, sid := range sandboxIDs {
		if _, found := m.sandboxes[sid]; found {
			continue
		}
		newSandboxIDs[sid] = true
	}
	for sid := range m.lastStateFileStat {
		if _, found := newSandboxIDs[sid]; !found {
			delete(m.lastStateFileStat, sid)
		}
	}
	for sid := range newSandboxIDs {
		stateFile := container.StateFile{
			RootDir: m.rootDir,
			ID:      sid,
		}
		stat, err := stateFile.Stat()
		if err != nil {
			log.Warningf("Failed to stat() container state file for sandbox %q: %v", sid, err)
			continue
		}
		if existing, found := m.lastStateFileStat[sid]; found {
			// We already tried to stat this sandbox but decided not to pick it up.
			// Check if the state file changed since. If it didn't, we don't want to
			// try again.
			if sufficientlyEqualStats(existing, stat) {
				continue
			}
			log.Infof("State file for sandbox %q has changed since we last looked at it; will try to reload it.", sid)
			delete(m.lastStateFileStat, sid)
		}
		// If we get here, we either haven't seen this sandbox before, or we saw it
		// and it has disappeared (which means it is new in this iteration), or we
		// saw it before but its state file changed. Either way, we want to try
		// loading it and see if it wants instrumentation.
		cont, err := container.Load(m.rootDir, sid, container.LoadOpts{
			Exact:         true,
			SkipCheck:     true,
			TryLock:       container.TryAcquire,
			RootContainer: true,
		})
		if err != nil {
			if err == container.ErrStateFileLocked {
				// This error is OK and shouldn't generate log spam. The sandbox is probably in the middle
				// of being created.
				continue
			}
			log.Warningf("Cannot load state file for sandbox %q: %v", sid, err)
			continue
		}

		// This is redundant with one of the checks performed below in servedSandbox.load, but this
		// avoids log spam for the non-error case of sandboxes that didn't request instrumentation.
		sandboxMetricAddr := strings.ReplaceAll(cont.Sandbox.MetricServerAddress, "%RUNTIME_ROOT%", m.rootDir)
		if sandboxMetricAddr != m.address {
			m.lastStateFileStat[sid] = stat
			continue
		}

		// This case can be hit when there is a leftover state file for a sandbox that was `kill -9`'d
		// without an opportunity for it to clean up its state file. This results in a valid state file
		// but the sandbox PID is gone. We don't want to continuously load this sandbox's state file.
		if cont.Status == container.Running && !cont.Sandbox.IsRunning() {
			log.Warningf("Sandbox %q has state file in state Running, yet it isn't actually running. Ignoring it.", sid)
			m.lastStateFileStat[sid] = stat
			continue
		}

		m.numSandboxes++
		served := &servedSandbox{
			rootContainerID: sid,
			server:          m,
			extraLabels: map[string]string{
				prometheus.SandboxIDLabel: sid.SandboxID,
			},
		}
		// Best-effort attempt to load the state file instantly.
		// This may legitimately fail if it is locked, e.g. during sandbox startup.
		// If it fails for any other reason, then the sandbox went away between the time we listed the
		// sandboxes and now, so just delete it.
		if _, _, err := served.load(); err != nil && err != container.ErrStateFileLocked {
			log.Warningf("Sandbox %q cannot be loaded, ignoring it: %v", sid, err)
			m.lastStateFileStat[sid] = stat
			served.cleanup()
			continue
		}
		m.sandboxes[sid] = served
		log.Infof("Registered new sandbox found in root directory: %q", sid)
	}
}

// sandboxLoadResult contains the outcome of calling `load` on a `servedSandbox`.
// It is used as an intermediary type that contains all that we know about a
// sandbox after attempting to load its state file, but does not contain any
// metric data from the sandbox.
type sandboxLoadResult struct {
	served   *servedSandbox
	sandbox  *sandbox.Sandbox
	verifier *prometheus.Verifier
	err      error
}

// loadSandboxesLocked loads the state file data from all known sandboxes.
// It does so in parallel, and avoids reloading sandboxes for which we have
// already loaded data.
func (m *metricServer) loadSandboxesLocked(ctx context.Context) []sandboxLoadResult {
	m.refreshSandboxesLocked()

	numGoroutines := exportParallelGoroutines
	numSandboxes := len(m.sandboxes)
	if numSandboxes < numGoroutines {
		numGoroutines = numSandboxes
	}

	// First, load all the sandboxes in parallel. We need to do this while m.mu is held.
	loadSandboxCh := make(chan *servedSandbox, numSandboxes)
	loadedSandboxesCh := make(chan sandboxLoadResult, numSandboxes)
	loadedSandboxes := make([]sandboxLoadResult, 0, numSandboxes)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for served := range loadSandboxCh {
				sand, verifier, err := served.load()
				loadedSandboxesCh <- sandboxLoadResult{served, sand, verifier, err}
			}
		}()
	}
	for _, sandbox := range m.sandboxes {
		loadSandboxCh <- sandbox
	}
	close(loadSandboxCh)
	for i := 0; i < numSandboxes; i++ {
		loadedSandboxes = append(loadedSandboxes, <-loadedSandboxesCh)
	}
	close(loadedSandboxesCh)
	return loadedSandboxes
}

// sandboxMetricsResult is the result of calling querySandboxMetrics on a
// single sandbox. It contains all of `sandboxLoadResult` but also has current
// metric data (if querying metrics from the sandbox process succeeded).
type sandboxMetricsResult struct {
	sandboxLoadResult
	isRunning       bool
	isCheckpointed  bool
	isRestored      bool
	cpuTimeSavedMS  int64
	wallTimeSavedMS int64
	snapshot        *prometheus.Snapshot
	err             error
}

// queryMultiSandboxMetrics queries metric data from multiple loaded sandboxes.
// It does so in parallel and with random permutation ordering.
// Only metrics matching the `metricsFilter` regular expression are queried.
// For each sandbox, whether we were successful in querying its metrics or
// not, the `processSandbox` function is called. This may be done in parallel,
// so `processSandbox` should do its own locking so that multiple parallel
// instances of itself behave appropriately.
func queryMultiSandboxMetrics(ctx context.Context, loadedSandboxes []sandboxLoadResult, metricsFilter string, processSandbox func(sandboxMetricsResult)) {
	numSandboxes := len(loadedSandboxes)
	ctxDeadline, ok := ctx.Deadline()
	if !ok {
		panic("context had no deadline, this should never happen as it was created with a timeout")
	}
	exportStartTime := time.Now()
	requestTimeLeft := ctxDeadline.Sub(exportStartTime)
	perSandboxTime := requestTimeLeft
	if numSandboxes != 0 {
		perSandboxTime = requestTimeLeft / time.Duration(numSandboxes)
	}
	if perSandboxTime < metricsExportPerSandboxTimeout {
		perSandboxTime = metricsExportPerSandboxTimeout
	}
	loadedSandboxCh := make(chan sandboxLoadResult, numSandboxes)
	var wg sync.WaitGroup
	numGoroutines := exportParallelGoroutines
	if numSandboxes < numGoroutines {
		numGoroutines = numSandboxes
	}
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for s := range loadedSandboxCh {
				isRunning := false
				isCheckpointed := false
				isRestored := false
				cpuTimeSavedMS := int64(0)
				wallTimeSavedMS := int64(0)
				var snapshot *prometheus.Snapshot
				err := s.err
				if err == nil {
					queryCtx, queryCtxCancel := context.WithTimeout(ctx, perSandboxTime)
					snapshot, err = querySandboxMetrics(queryCtx, s.sandbox, s.verifier, metricsFilter)
					queryCtxCancel()
					isRunning = s.sandbox.IsRunning()
					isCheckpointed = s.sandbox.Checkpointed
					isRestored = s.sandbox.Restored
					cpuTimeSavedMS = s.sandbox.CPUTimeSaved.Milliseconds()
					wallTimeSavedMS = s.sandbox.WallTimeSaved.Milliseconds()
				}
				processSandbox(sandboxMetricsResult{
					sandboxLoadResult: s,
					isRunning:         isRunning,
					isCheckpointed:    isCheckpointed,
					isRestored:        isRestored,
					cpuTimeSavedMS:    cpuTimeSavedMS,
					wallTimeSavedMS:   wallTimeSavedMS,
					snapshot:          snapshot,
					err:               err,
				})
			}
		}()
	}
	// Iterate over all sandboxes.
	// Important: This must be done in random order.
	// A malicious/compromised sandbox may decide to stall when being asked for metrics.
	// If at least `numGoroutines` sandboxes do this, this will starve other sandboxes
	// from having their metrics exported, because all the goroutines will be stuck on
	// the stalled sandboxes.
	// One way to completely avoid this would be to spawn one goroutine per
	// sandbox, but this can amount to ~hundreds of goroutines, which is not desirable
	// for the metrics server.
	// Another way would be to have a very strict timeout on each sandbox's export
	// process, but in some cases a busy sandbox will take more than a decisecond
	// or so to export its data, so this would miss some data from legitimate (but
	// slow) sandboxes.
	// Instead, we take a middle-of-the-road approach: we use a timeout that's not
	// too strict but still ensures we make forward progress away from stalled
	// sandboxes, and we also iterate across sandboxes in a different random order at
	// each export. This ensures that all sandboxes eventually get a fair chance of
	// being part of the "first `numGoroutines` sandboxes in line" to get their
	// metric data loaded, such that a client repeatedly scraping metrics will
	// eventually get data from each sandbox.
	for _, sandboxIndex := range rand.Perm(len(loadedSandboxes)) {
		loadedSandboxCh <- loadedSandboxes[sandboxIndex]
	}
	close(loadedSandboxCh)
	wg.Wait()
}

// serveMetrics serves metrics requests.
func (m *metricServer) serveMetrics(w *httpResponseWriter, req *http.Request) httpResult {
	ctx, ctxCancel := context.WithTimeout(req.Context(), metricsExportTimeout)
	defer ctxCancel()

	metricsFilter := req.URL.Query().Get("runsc-sandbox-metrics-filter")
	var capabilityFilterReg *regexp.Regexp
	capabilityFilterStr := req.URL.Query().Get("runsc-capability-filter")

	m.mu.Lock()

	if metricsFilter != "" && metricsFilter != m.lastValidMetricFilter {
		_, err := regexp.Compile(metricsFilter)
		if err != nil {
			m.mu.Unlock()
			return httpResult{http.StatusBadRequest, errors.New("provided metric filter is not a valid regular expression")}
		}
		m.lastValidMetricFilter = metricsFilter
	}
	if capabilityFilterStr != "" {
		if capabilityFilterStr != m.lastValidCapabilityFilterStr {
			reg, err := regexp.Compile(capabilityFilterStr)
			if err != nil {
				m.mu.Unlock()
				return httpResult{http.StatusBadRequest, errors.New("provided capability filter is not a valid regular expression")}
			}
			m.lastValidCapabilityFilterStr = capabilityFilterStr
			m.lastValidCapabilityFilterReg = reg
			capabilityFilterReg = reg
		} else {
			capabilityFilterReg = m.lastValidCapabilityFilterReg
		}
	}

	loadedSandboxes := m.loadSandboxesLocked(ctx)
	numSandboxes := len(loadedSandboxes)
	numSandboxesTotal := m.numSandboxes
	m.mu.Unlock()

	// Used to prevent goroutines from accessing the shared variables below.
	var metricsMu sync.Mutex

	// Meta-metrics keep track of metrics to export about the metrics server itself.
	type metaMetrics struct {
		numRunningSandboxes      int64
		numCannotExportSandboxes int64
		numCheckpointedSandboxes int64
		numRestoredSandboxes     int64
	}
	meta := metaMetrics{}                   // Protected by metricsMu.
	selfMetrics := prometheus.NewSnapshot() // Protected by metricsMu.

	type snapshotAndOptions struct {
		snapshot *prometheus.Snapshot
		options  prometheus.SnapshotExportOptions
	}
	snapshotCh := make(chan snapshotAndOptions, numSandboxes)

	queryMultiSandboxMetrics(ctx, loadedSandboxes, metricsFilter, func(r sandboxMetricsResult) {
		metricsMu.Lock()
		defer metricsMu.Unlock()
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxPresenceMetric, nil, 1).SetExternalLabels(r.served.extraLabels))
		sandboxRunning := int64(0)
		sandboxCheckpointed := int64(0)
		sandboxRestored := int64(0)
		sandboxCPUTimeSavedMS := int64(0)
		sandboxWallTimeSavedMS := int64(0)
		if r.isRunning {
			sandboxRunning = 1
			meta.numRunningSandboxes++
		}
		if r.isCheckpointed {
			sandboxCheckpointed = 1
			meta.numCheckpointedSandboxes++
		}
		if r.isRestored {
			sandboxRestored = 1
			meta.numRestoredSandboxes++
			sandboxCPUTimeSavedMS = r.cpuTimeSavedMS
			sandboxWallTimeSavedMS = r.wallTimeSavedMS
		}
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxRunningMetric, nil, sandboxRunning).SetExternalLabels(r.served.extraLabels))
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxCheckpointedMetric, nil, sandboxCheckpointed).SetExternalLabels(r.served.extraLabels))
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxRestoredMetric, nil, sandboxRestored).SetExternalLabels(r.served.extraLabels))
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxCPUTimeSavedMSMetric, nil, sandboxCPUTimeSavedMS).SetExternalLabels(r.served.extraLabels))
		selfMetrics.Add(prometheus.LabeledIntData(&SandboxWallTimeSavedMSMetric, nil, sandboxWallTimeSavedMS).SetExternalLabels(r.served.extraLabels))
		if r.err == nil {
			selfMetrics.Add(prometheus.LabeledIntData(&SandboxMetadataMetric, r.sandbox.MetricMetadata, 1).SetExternalLabels(r.served.extraLabels))
			for _, cap := range r.served.capabilities {
				if capabilityFilterReg != nil && !capabilityFilterReg.MatchString(cap.String()) && !capabilityFilterReg.MatchString(cap.TrimmedString()) {
					continue
				}
				selfMetrics.Add(prometheus.LabeledIntData(&SandboxCapabilitiesMetric, map[string]string{
					SandboxCapabilitiesMetricLabel: cap.TrimmedString(),
				}, 1).SetExternalLabels(r.served.extraLabels))
			}
			selfMetrics.Add(prometheus.LabeledIntData(&SpecMetadataMetric, r.served.specMetadataLabels, 1).SetExternalLabels(r.served.extraLabels))
			createdAt := float64(r.served.createdAt.Unix()) + (float64(r.served.createdAt.Nanosecond()) / 1e9)
			selfMetrics.Add(prometheus.LabeledFloatData(&SandboxCreationMetric, nil, createdAt).SetExternalLabels(r.served.extraLabels))
		} else {
			// If the sandbox isn't running, it is normal that metrics are not exported for it, so
			// do not report this case as an error.
			if r.isRunning {
				meta.numCannotExportSandboxes++
				log.Warningf("Could not export metrics from sandbox %s: %v", r.served.rootContainerID.SandboxID, r.err)
			}
			return
		}
		snapshotCh <- snapshotAndOptions{
			snapshot: r.snapshot,
			options: prometheus.SnapshotExportOptions{
				ExporterPrefix: m.exporterPrefix,
				ExtraLabels:    r.served.extraLabels,
			},
		}
	})

	// Build the map of all snapshots we will be rendering.
	snapshotsToOptions := make(map[*prometheus.Snapshot]prometheus.SnapshotExportOptions, numSandboxes+2)
	snapshotsToOptions[selfMetrics] = prometheus.SnapshotExportOptions{
		ExporterPrefix: fmt.Sprintf("%s%s", m.exporterPrefix, prometheus.MetaMetricPrefix),
	}
	processMetrics := prometheus.NewSnapshot()
	processMetrics.Add(prometheus.NewFloatData(&prometheus.ProcessStartTimeSeconds, float64(m.startTime.Unix())+(float64(m.startTime.Nanosecond())/1e9)))
	snapshotsToOptions[processMetrics] = prometheus.SnapshotExportOptions{
		// These metrics must be written without any prefix.
	}

	// Aggregate all the snapshots from the sandboxes.
	close(snapshotCh)
	for snapshotAndOptions := range snapshotCh {
		snapshotsToOptions[snapshotAndOptions.snapshot] = snapshotAndOptions.options
	}

	// Add our own metrics.
	selfMetrics.Add(prometheus.NewIntData(&MetricServerPresenceMetric, 1))
	selfMetrics.Add(prometheus.NewIntData(&NumRunningSandboxesMetric, meta.numRunningSandboxes))
	selfMetrics.Add(prometheus.NewIntData(&NumCannotExportSandboxesMetric, meta.numCannotExportSandboxes))
	selfMetrics.Add(prometheus.NewIntData(&NumTotalSandboxesMetric, numSandboxesTotal))
	selfMetrics.Add(prometheus.NewIntData(&NumCheckpointedSandboxesMetric, meta.numCheckpointedSandboxes))
	selfMetrics.Add(prometheus.NewIntData(&NumRestoredSandboxesMetric, meta.numRestoredSandboxes))

	// Write out all data.
	lastMetricsWrittenSize := int(m.lastMetricsWrittenSize.Load())
	metricsWritten := make(map[string]bool, lastMetricsWrittenSize)
	commentHeader := fmt.Sprintf("Data for runsc metric server exporting data for sandboxes in root directory %s", m.rootDir)
	if metricsFilter != "" {
		commentHeader = fmt.Sprintf("%s (filtered using regular expression: %q)", commentHeader, metricsFilter)
	}
	promWriter := m.promWriterPool.Get().(*prometheus.ReusableWriter[*httpResponseWriter])
	written, err := promWriter.Write(w, prometheus.ExportOptions{
		CommentHeader:  commentHeader,
		MetricsWritten: metricsWritten,
	}, snapshotsToOptions)
	m.promWriterPool.Put(promWriter)
	if err != nil {
		if written == 0 {
			return httpResult{http.StatusServiceUnavailable, err}
		}
		// Note that we cannot return an HTTP error here because we have already started writing a
		// response, which means we've already responded with a 200 OK status code.
		// This probably means the client closed the connection before we could finish writing.
		return httpOK
	}
	if lastMetricsWrittenSize < len(metricsWritten) {
		m.lastMetricsWrittenSize.CompareAndSwap(uint32(lastMetricsWrittenSize), uint32(len(metricsWritten)))
	}
	return httpOK
}

// serveHealthCheck serves the healthcheck endpoint.
// Returns a response prefixed by "runsc-metrics:OK" on success.
// Clients can use this to assert that they are talking to the metrics server, as opposed to some
// other random HTTP server.
func (m *metricServer) serveHealthCheck(w *httpResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	w.WriteHeader(http.StatusOK)
	w.WriteString("runsc-metrics:OK")
	return httpOK
}

// servePID serves the PID of the metric server process.
func (m *metricServer) servePID(w *httpResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down")}
	}
	w.WriteString(strconv.Itoa(m.pid))
	return httpOK
}

// Server is the set of options to run a metric server.
// Initialize this struct and then call Run on it to run the metric server.
type Server struct {
	// Config is the main runsc configuration.
	Config *config.Config

	// ExporterPrefix is used as prefix for all metric names following Prometheus exporter convention.
	ExporterPrefix string

	// PIDFile, if set, will cause the metric server to write its own PID to this file after binding
	// to the requested address. The parent directory of this file must already exist.
	PIDFile string

	// ExposeProfileEndpoints, if true, exposes /runsc-metrics/profile-cpu and
	// /runsc-metrics/profile-heap to get profiling data about the metric server.
	ExposeProfileEndpoints bool

	// AllowUnknownRoot causes the metric server to keep running regardless of the existence of the
	// Config's root directory or the metric server's ability to access it.
	AllowUnknownRoot bool
}

// Run runs the metric server.
// It blocks until the server is instructed to exit, e.g. via signal.
func (s *Server) Run(ctx context.Context) error {
	ctx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	m := &metricServer{
		exporterPrefix:         s.ExporterPrefix,
		pidFile:                s.PIDFile,
		exposeProfileEndpoints: s.ExposeProfileEndpoints,
		allowUnknownRoot:       s.AllowUnknownRoot,
		promWriterPool: sync.Pool{
			New: func() any {
				return &prometheus.ReusableWriter[*httpResponseWriter]{}
			},
		},
	}
	conf := s.Config
	if conf.MetricServer == "" {
		return errors.New("config does not specify the metric server address (--metric-server)")
	}
	if _, err := container.ListSandboxes(conf.RootDir); err != nil {
		if !m.allowUnknownRoot {
			return fmt.Errorf("invalid root directory %q: tried to list sandboxes within it and got: %w", conf.RootDir, err)
		}
		log.Infof("Root directory %q: tried to list sandboxes within it and got: %v. Continuing anyway, as this is expected with --allow-unknown-root.", conf.RootDir, err)
	}
	// container.ListSandboxes uses a glob pattern, which doesn't error out on
	// permission errors. Double-check by actually listing the directory.
	if _, err := os.ReadDir(conf.RootDir); err != nil {
		if !m.allowUnknownRoot {
			return fmt.Errorf("invalid root directory %q: tried to list all entries within it and got: %w", conf.RootDir, err)
		}
		log.Infof("Root directory %q: tried to list all entries within it and got: %v. Continuing anyway, as this is expected with --allow-unknown-root.", conf.RootDir, err)
	}
	m.startTime = time.Now()
	m.rootDir = conf.RootDir
	if strings.Contains(conf.MetricServer, "%RUNTIME_ROOT%") {
		newAddr := strings.ReplaceAll(conf.MetricServer, "%RUNTIME_ROOT%", m.rootDir)
		log.Infof("Metric server address replaced %RUNTIME_ROOT%: %q -> %q", conf.MetricServer, newAddr)
		conf.MetricServer = newAddr
	}
	m.address = conf.MetricServer
	m.sandboxes = make(map[container.FullID]*servedSandbox)
	m.lastStateFileStat = make(map[container.FullID]os.FileInfo)
	m.pid = os.Getpid()
	m.shutdownCh = make(chan os.Signal, 1)
	signal.Notify(m.shutdownCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	var listener net.Listener
	var listenErr error
	if strings.HasPrefix(conf.MetricServer, fmt.Sprintf("%c", os.PathSeparator)) {
		beforeBindSt, beforeBindErr := os.Stat(conf.MetricServer)
		if listener, listenErr = (&net.ListenConfig{}).Listen(ctx, "unix", conf.MetricServer); listenErr != nil {
			return fmt.Errorf("cannot listen on unix domain socket %q: %w", conf.MetricServer, listenErr)
		}
		afterBindSt, afterBindErr := os.Stat(conf.MetricServer)
		if afterBindErr != nil {
			return fmt.Errorf("cannot stat our own unix domain socket %q: %w", conf.MetricServer, afterBindErr)
		}
		ownUDS := true
		if beforeBindErr == nil && beforeBindSt.Mode() == afterBindSt.Mode() {
			// Socket file existed and was a socket prior to us binding to it.
			if beforeBindSt.Sys() != nil && afterBindSt.Sys() != nil {
				beforeSt, beforeStOk := beforeBindSt.Sys().(*syscall.Stat_t)
				afterSt, afterStOk := beforeBindSt.Sys().(*syscall.Stat_t)
				if beforeStOk && afterStOk && beforeSt.Dev == afterSt.Dev && beforeSt.Ino == afterSt.Ino {
					// Socket file is the same before and after binding, so we should not consider ourselves
					// the owner of it.
					ownUDS = false
				}
			}
		}
		if ownUDS {
			log.Infof("Bound on socket file %s which we own. As such, this socket file will be deleted on server shutdown.", conf.MetricServer)
			m.udsPath = conf.MetricServer
			defer os.Remove(m.udsPath)
			os.Chmod(m.udsPath, 0777)
		} else {
			log.Infof("Bound on socket file %s which existed prior to this server's existence. As such, it will not be deleted on server shutdown.", conf.MetricServer)
		}
	} else {
		if strings.HasPrefix(conf.MetricServer, ":") {
			log.Warningf("Binding on all interfaces. This will allow anyone to list all containers on your machine!")
		}
		if listener, listenErr = (&net.ListenConfig{}).Listen(ctx, "tcp", conf.MetricServer); listenErr != nil {
			return fmt.Errorf("cannot listen on TCP address %q: %w", conf.MetricServer, listenErr)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/runsc-metrics/healthcheck", logRequest(m.serveHealthCheck))
	mux.HandleFunc("/runsc-metrics/pid", logRequest(m.servePID))
	if m.exposeProfileEndpoints {
		log.Warningf("Profiling HTTP endpoints are exposed; this should only be used for development!")
		mux.HandleFunc("/runsc-metrics/profile-cpu", logRequest(m.profileCPU))
		mux.HandleFunc("/runsc-metrics/profile-heap", logRequest(m.profileHeap))
	} else {
		// Disable memory profiling, since we don't expose it.
		runtime.MemProfileRate = 0
	}
	mux.HandleFunc("/metrics", logRequest(m.serveMetrics))
	mux.HandleFunc("/", logRequest(m.serveIndex))
	m.srv.Handler = mux
	m.srv.ReadTimeout = httpTimeout
	m.srv.WriteTimeout = httpTimeout
	if err := m.startVerifyLoop(ctx); err != nil {
		return fmt.Errorf("cannot start background loop: %w", err)
	}
	if m.pidFile != "" {
		if err := os.WriteFile(m.pidFile, []byte(fmt.Sprintf("%d", m.pid)), 0644); err != nil {
			return fmt.Errorf("cannot write PID to file %q: %w", m.pidFile, err)
		}
		defer os.Remove(m.pidFile)
		log.Infof("Wrote PID %d to file %v.", m.pid, m.pidFile)
	}

	// If not modified by the user from the environment, set the Go GC percentage lower than default.
	if _, hasEnv := os.LookupEnv("GOGC"); !hasEnv {
		debug.SetGCPercent(40)
	}

	// Run GC immediately to get rid of all the initialization-related memory bloat and start from
	// a clean slate.
	state.Release()
	runtime.GC()

	// Initialization complete.
	log.Infof("Server serving on %s for root directory %s.", conf.MetricServer, conf.RootDir)
	serveErr := m.srv.Serve(listener)
	log.Infof("Server has stopped accepting requests.")
	m.mu.Lock()
	defer m.mu.Unlock()
	if serveErr != nil {
		if serveErr == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("cannot serve on address %s: %w", conf.MetricServer, serveErr)
	}
	// Per documentation, http.Server.Serve can never return a nil error, so this is not a success.
	return fmt.Errorf("HTTP server Serve() did not return expected error")
}
