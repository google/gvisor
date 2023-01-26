// Copyright 2022 The gVisor Authors.
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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
)

const (
	// verifyLoopInterval is the interval at which we check whether there are any sandboxes we need
	// to serve metrics for. If there are none, the server exits.
	verifyLoopInterval = 20 * time.Second

	// httpTimeout is the timeout used for all connect/read/write operations of the HTTP server.
	httpTimeout = 1 * time.Minute

	// metricsExportTimeout is the maximum amount of time that the metrics export process should take.
	metricsExportTimeout = 30 * time.Second

	// metricsExportPerSandboxTimeout is the maximum amount of time that we wait on any individual
	// sandbox when exporting its metrics.
	metricsExportPerSandboxTimeout = 8 * time.Second

	// exportParallelGoroutines is the maximum number of goroutines spawned during metrics export.
	exportParallelGoroutines = 8
)

// Prometheus label names.
const (
	iterationIDLabel = "iterationid"
)

// servedSandbox is a sandbox that we serve metrics from.
// A single metrics server will export data about multiple sandboxes.
type servedSandbox struct {
	rootContainerID  container.FullID
	rootDir          string
	metricServerAddr string
	extraLabels      map[string]string

	// mu protects the fields below.
	mu sync.Mutex

	// sandbox is the sandbox being monitored.
	// Once set, it is immutable.
	sandbox *sandbox.Sandbox

	// labelsWithMetadata is the union of `extraLabels` and `sandbox.MetricMetadata`.
	// This is exported as the set of labels for the `sandbox_metadata` metric.
	// Once set, it is immutable.
	labelsWithMetadata map[string]string

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
		cont, err := container.Load(s.rootDir, s.rootContainerID, container.LoadOpts{
			Exact:         true,
			SkipCheck:     true,
			TryLock:       container.TryAcquire,
			RootContainer: true,
		})
		if err != nil {
			return nil, nil, err
		}
		sandboxMetricAddr := strings.ReplaceAll(cont.Sandbox.MetricServerAddress, "%RUNTIME_ROOT%", s.rootDir)
		if sandboxMetricAddr == "" {
			return nil, nil, errors.New("sandbox did not request instrumentation")
		}
		if sandboxMetricAddr != s.metricServerAddr {
			return nil, nil, fmt.Errorf("sandbox requested instrumentation by a metric server running at a different address (sandbox wants %q, this metric server serves %q)", sandboxMetricAddr, s.metricServerAddr)
		}
		// Update label data as read from the state file.
		// Do not store empty labels.
		authoritativeLabels := cont.Sandbox.PrometheusLabels()
		for _, label := range []string{sandbox.SandboxIDLabel, sandbox.PodNameLabel, sandbox.NamespaceLabel} {
			s.extraLabels[label] = authoritativeLabels[label]
			if s.extraLabels[label] == "" {
				delete(s.extraLabels, label)
			}
		}
		s.sandbox = cont.Sandbox
	}
	if s.verifier == nil {
		registeredMetrics, err := s.sandbox.GetRegisteredMetrics()
		if err != nil {
			return nil, nil, err
		}
		verifier, err := prometheus.NewVerifier(registeredMetrics)
		if err != nil {
			return nil, nil, err
		}
		s.verifier = verifier
	}
	s.labelsWithMetadata = make(map[string]string, len(s.extraLabels)+len(s.sandbox.MetricMetadata))
	for k, v := range s.extraLabels {
		s.labelsWithMetadata[k] = v
	}
	for k, v := range s.sandbox.MetricMetadata {
		s.labelsWithMetadata[k] = v
	}
	return s.sandbox, s.verifier, nil
}

// queryMetrics queries the sandbox for metrics data.
func queryMetrics(ctx context.Context, sand *sandbox.Sandbox, verifier *prometheus.Verifier) (*prometheus.Snapshot, error) {
	ch := make(chan struct {
		snapshot *prometheus.Snapshot
		err      error
	}, 1)
	defer close(ch)
	go func() {
		snapshot, err := sand.ExportMetrics()
		select {
		case ch <- struct {
			snapshot *prometheus.Snapshot
			err      error
		}{snapshot, err}:
		default:
		}
	}()
	select {
	case <-ctx.Done():
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

// MetricServer implements subcommands.Command for the "metric-server" command.
type MetricServer struct {
	rootDir        string
	address        string
	exporterPrefix string
	startTime      time.Time
	rand           *rand.Rand
	srv            http.Server

	// Size of the map of written metrics during the last /metrics export. Initially zero.
	// Used to efficiently reallocate a map of the right size during the next export.
	lastMetricsWrittenSize atomicbitops.Uint32

	// mu protects the fields below.
	mu sync.Mutex

	// udsPath is a path to a Unix Domain Socket file on which the server is bound and which it owns.
	// This socket file will be deleted on server shutdown.
	// This field is not set if binding to a network port, or when the UDS already existed prior to
	// being bound by us (i.e. its ownership isn't ours), such that it isn't deleted in this case.
	// The field is unset once the file is succesfully removed.
	udsPath string

	// sandboxes is the list of sandboxes we serve metrics for.
	sandboxes map[container.FullID]*servedSandbox

	// lastStateFileStat maps container full IDs to the last observed stat() of their state file.
	// This is used to monitor for sandboxes in the background. If a sandbox's state file matches this
	// info, we can assume that the last background scan already looked at it.
	lastStateFileStat map[container.FullID]os.FileInfo

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
}

// Name implements subcommands.Command.Name.
func (*MetricServer) Name() string {
	return "metric-server"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*MetricServer) Synopsis() string {
	return "implements Prometheus metrics HTTP endpoint"
}

// Usage implements subcommands.Command.Usage.
func (*MetricServer) Usage() string {
	return `-root=<root dir> -metric-server=<addr> [-metric-exporter-prefix=<prefix_>] metric-server`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricServer) SetFlags(f *flag.FlagSet) {}

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
func (m *MetricServer) refreshSandboxesLocked() {
	if m.shuttingDown {
		// Do nothing to avoid log spam.
		return
	}
	sandboxIDs, err := container.ListSandboxes(m.rootDir)
	if err != nil {
		log.Warningf("Cannot list containers in root directory %s, it has likely gone away: %v.", m.rootDir, err)
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
			delete(m.sandboxes, sandboxID)
		} else if _, _, err := sandbox.load(); err != nil && err != container.ErrStateFileLocked {
			log.Warningf("Sandbox %s cannot be loaded, deleting it: %v", sandboxID, err)
			delete(m.sandboxes, sandboxID)
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
		// This is redundant with one of the checks performed below in servedSandbox.load(), but this
		// avoids log spam for the non-error case of sandboxes that didn't request instrumentation.
		sandboxMetricAddr := strings.ReplaceAll(cont.Sandbox.MetricServerAddress, "%RUNTIME_ROOT%", m.rootDir)
		if sandboxMetricAddr != m.address {
			m.lastStateFileStat[sid] = stat
			continue
		}
		m.numSandboxes++
		served := &servedSandbox{
			rootContainerID:  sid,
			rootDir:          m.rootDir,
			metricServerAddr: m.address,
			extraLabels: map[string]string{
				sandbox.SandboxIDLabel: sid.SandboxID,
				iterationIDLabel:       fmt.Sprintf("%d", m.rand.Uint64()),
			},
		}
		// Best-effort attempt to load the state file instantly.
		// This may legitimately fail if it is locked, e.g. during sandbox startup.
		// If it fails for any other reason, then the sandbox went away between the time we listed the
		// sandboxes and now, so just delete it.
		if _, _, err := served.load(); err != nil && err != container.ErrStateFileLocked {
			log.Warningf("Sandbox %q cannot be loaded, ignoring it: %v", sid, err)
			m.lastStateFileStat[sid] = stat
			continue
		}
		m.sandboxes[sid] = served
		log.Infof("Registered new sandbox found in root directory: %q", sid)
	}
}

// httpResult is returned by HTTP handlers.
type httpResult struct {
	code int
	err  error
}

// httpOK is the "everything went fine" HTTP result.
var httpOK = httpResult{code: http.StatusOK}

// serveIndex serves the index page.
func (m *MetricServer) serveIndex(w http.ResponseWriter, req *http.Request) httpResult {
	if req.URL.Path != "/" {
		return httpResult{http.StatusNotFound, errors.New("path not found")}
	}
	fmt.Fprintf(w, "<html><head><title>runsc metrics</title></head><body>")
	fmt.Fprintf(w, "<p>You have reached the runsc metrics server page!</p>")
	fmt.Fprintf(w, `<p>To see actual metric data, head over to <a href="/metrics">/metrics</a>.</p>`)
	fmt.Fprintf(w, "</body></html>")
	return httpOK
}

// Metrics generated by the metrics server itself.
var (
	sandboxPresenceMetric = prometheus.Metric{
		Name: "sandbox_presence",
		Type: prometheus.TypeGauge,
		Help: "Boolean metric set to 1 for each known sandbox.",
	}
	sandboxRunningMetric = prometheus.Metric{
		Name: "sandbox_running",
		Type: prometheus.TypeGauge,
		Help: "Boolean metric set to 1 for each running sandbox.",
	}
	sandboxMetadataMetric = prometheus.Metric{
		Name: "sandbox_metadata",
		Type: prometheus.TypeGauge,
		Help: "Key-value pairs about per-sandbox metadata.",
	}
	numRunningSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_running",
		Type: prometheus.TypeGauge,
		Help: "Number of sandboxes running at present.",
	}
	numCannotExportSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_broken_metrics",
		Type: prometheus.TypeGauge,
		Help: "Number of sandboxes from which we cannot export metrics.",
	}
	numTotalSandboxesMetric = prometheus.Metric{
		Name: "num_sandboxes_total",
		Type: prometheus.TypeCounter,
		Help: "Counter of sandboxes that have ever been started.",
	}
	processStartTimeMetric = prometheus.Metric{
		Name: "process_start_time_seconds",
		Type: prometheus.TypeGauge,
		Help: "Unix timestamp at which the process started. Used by Prometheus for counter resets.",
	}
)

// serveMetrics serves metrics requests.
func (m *MetricServer) serveMetrics(w http.ResponseWriter, req *http.Request) httpResult {
	ctx, ctxCancel := context.WithTimeout(req.Context(), metricsExportTimeout)
	defer ctxCancel()
	m.mu.Lock()
	m.refreshSandboxesLocked()

	numGoroutines := exportParallelGoroutines
	numSandboxes := len(m.sandboxes)
	if numSandboxes < numGoroutines {
		numGoroutines = numSandboxes
	}

	// First, load all the sandboxes in parallel. We need to do this while m.mu is held.
	loadSandboxCh := make(chan *servedSandbox, numSandboxes)
	type sandboxLoadResult struct {
		served   *servedSandbox
		sandbox  *sandbox.Sandbox
		verifier *prometheus.Verifier
		err      error
	}
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
	m.mu.Unlock()

	// Now iterate over all sandboxes.
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

	// Used to prevent goroutines from accessing the shared variables below.
	var metricsMu sync.Mutex

	// Meta-metrics keep track of metrics to export about the metrics server itself.
	type metaMetrics struct {
		numRunningSandboxes      int64
		numCannotExportSandboxes int64
	}
	meta := metaMetrics{}                   // Protected by metricsMu.
	selfMetrics := prometheus.NewSnapshot() // Protected by metricsMu.

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
	type snapshotAndOptions struct {
		snapshot *prometheus.Snapshot
		options  prometheus.SnapshotExportOptions
	}
	snapshotCh := make(chan snapshotAndOptions, numSandboxes)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(metricsMu *sync.Mutex, meta *metaMetrics, selfMetrics *prometheus.Snapshot) {
			defer wg.Done()
			for s := range loadedSandboxCh {
				served, sand, verifier, err := s.served, s.sandbox, s.verifier, s.err
				isRunning := false
				var snapshot *prometheus.Snapshot
				if err == nil {
					queryCtx, queryCtxCancel := context.WithTimeout(ctx, perSandboxTime)
					snapshot, err = queryMetrics(queryCtx, sand, verifier)
					queryCtxCancel()
					isRunning = sand.IsRunning()
				}
				func() {
					metricsMu.Lock()
					defer metricsMu.Unlock()
					selfMetrics.Add(prometheus.LabeledIntData(&sandboxPresenceMetric, served.extraLabels, 1))
					selfMetrics.Add(prometheus.LabeledIntData(&sandboxMetadataMetric, served.labelsWithMetadata, 1))
					sandboxRunning := int64(0)
					if isRunning {
						sandboxRunning = 1
					}
					selfMetrics.Add(prometheus.LabeledIntData(&sandboxRunningMetric, served.extraLabels, sandboxRunning))
					if err != nil && !isRunning {
						// The sandbox either hasn't started running yet, or it ran and has gone away between the
						// start of the function and now. It is normal that metrics are not exported for this
						// sandbox in this case, so do not report this as an error.
						return
					}
					if err != nil {
						meta.numRunningSandboxes++
						meta.numCannotExportSandboxes++
						log.Warningf("Could not export metrics from sandbox %s: %v", served.rootContainerID.SandboxID, err)
						return
					}
					meta.numRunningSandboxes++
					snapshotCh <- snapshotAndOptions{
						snapshot: snapshot,
						options: prometheus.SnapshotExportOptions{
							ExporterPrefix: m.exporterPrefix,
							ExtraLabels:    served.extraLabels,
						},
					}
				}()
			}
		}(&metricsMu, &meta, selfMetrics)
	}
	// Feed the channel in random order:
	for _, sandboxIndex := range rand.Perm(len(loadedSandboxes)) {
		loadedSandboxCh <- loadedSandboxes[sandboxIndex]
	}
	close(loadedSandboxCh)

	// Meanwhile, build the map of all snapshots we will be rendering.
	snapshotsToOptions := make(map[*prometheus.Snapshot]prometheus.SnapshotExportOptions, numSandboxes+2)
	snapshotsToOptions[selfMetrics] = prometheus.SnapshotExportOptions{
		ExporterPrefix: fmt.Sprintf("%smeta_", m.exporterPrefix),
	}
	processMetrics := prometheus.NewSnapshot()
	processMetrics.Add(prometheus.NewFloatData(&processStartTimeMetric, float64(m.startTime.Unix())+(float64(m.startTime.Nanosecond())/1e9)))
	snapshotsToOptions[processMetrics] = prometheus.SnapshotExportOptions{
		// These metrics must be written without any prefix.
	}

	// Aggregate all the snapshots from the sandboxes.
	wg.Wait()
	close(snapshotCh)
	for snapshotAndOptions := range snapshotCh {
		snapshotsToOptions[snapshotAndOptions.snapshot] = snapshotAndOptions.options
	}

	// Write out all data.
	lastMetricsWrittenSize := int(m.lastMetricsWrittenSize.Load())
	metricsWritten := make(map[string]bool, lastMetricsWrittenSize)
	written, err := prometheus.Write(w, prometheus.ExportOptions{
		CommentHeader:  fmt.Sprintf("Data for runsc metric server exporting data for sandboxes in root directory %s", m.rootDir),
		MetricsWritten: metricsWritten,
	}, snapshotsToOptions)
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
func (m *MetricServer) serveHealthCheck(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shuttingDown {
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down already")}
	}
	if err := req.ParseForm(); err != nil {
		return httpResult{http.StatusBadRequest, err}
	}
	rootDir := req.Form.Get("root")
	if rootDir != m.rootDir {
		return httpResult{http.StatusBadRequest, fmt.Errorf("this metric server is configured to serve root directory: %s", m.rootDir)}
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "runsc-metrics:OK")
	return httpOK
}

// shutdownLocked shuts down the server. It assumes mu is held.
func (m *MetricServer) shutdownLocked(ctx context.Context) {
	log.Infof("Server shutting down.")
	m.shuttingDown = true
	if m.udsPath != "" {
		if err := os.Remove(m.udsPath); err != nil {
			log.Warningf("Cannot remove UDS at %s: %v", m.udsPath, err)
		} else {
			m.udsPath = ""
		}
	}
	m.srv.Shutdown(ctx)
}

// logRequest wraps an HTTP handler and adds logging to it.
func logRequest(f func(w http.ResponseWriter, req *http.Request) httpResult) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Infof("Request: %s %s", req.Method, req.URL.Path)
		defer func() {
			if r := recover(); r != nil {
				log.Warningf("Request: %s %s: Panic:\n%v", req.Method, req.URL.Path, r)
			}
		}()
		result := f(w, req)
		if result.err != nil {
			http.Error(w, result.err.Error(), result.code)
			log.Warningf("Request: %s %s: Failed with HTTP code %d: %v", req.Method, req.URL.Path, result.code, result.err)
		}
	}
}

// verify is one iteration of verifyLoop.
// It runs in a loop in the background which checks all sandboxes for liveness, tries to load
// their metadata if that hasn't been loaded yet, and tries to pick up new sandboxes that
// failed to register for whatever reason.
func (m *MetricServer) verify(ctx context.Context) {
	_, err := container.ListSandboxes(m.rootDir)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		log.Warningf("Cannot list sandboxes in root directory %s, it has likely gone away: %v. Server shutting down.", m.rootDir, err)
		m.shutdownLocked(ctx)
		return
	}
	m.refreshSandboxesLocked()
}

// verifyLoop runs in the background and periodically calls verify.
func (m *MetricServer) verifyLoop(ctx context.Context) {
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
}

// Execute implements subcommands.Command.Execute.
func (m *MetricServer) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	ctx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	conf := args[0].(*config.Config)
	if conf.MetricServer == "" || conf.RootDir == "" {
		f.Usage()
		return subcommands.ExitUsageError
	}
	if strings.Contains(conf.MetricServer, "%ID%") {
		return util.Errorf("Metric server address contains '%%ID%%': %v. This should have been replaced by the parent process.", conf.MetricServer)
	}
	if _, err := container.ListSandboxes(conf.RootDir); err != nil {
		return util.Errorf("Invalid root directory %q: tried to list sandboxes within it and got: %v", conf.RootDir, err)
	}
	// container.ListSandboxes uses a glob pattern, which doesn't error out on
	// permission errors. Double-check by actually listing the directory.
	if _, err := ioutil.ReadDir(conf.RootDir); err != nil {
		return util.Errorf("Invalid root directory %q: tried to list all entries within it and got: %v", conf.RootDir, err)
	}
	m.startTime = time.Now()
	m.rand = rand.New(rand.NewSource(m.startTime.UnixNano()))
	m.rootDir = conf.RootDir
	m.exporterPrefix = conf.MetricExporterPrefix
	if strings.Contains(conf.MetricServer, "%RUNTIME_ROOT%") {
		newAddr := strings.ReplaceAll(conf.MetricServer, "%RUNTIME_ROOT%", m.rootDir)
		log.Infof("Metric server address replaced %RUNTIME_ROOT%: %q -> %q", conf.MetricServer, newAddr)
		conf.MetricServer = newAddr
	}
	m.address = conf.MetricServer
	m.sandboxes = make(map[container.FullID]*servedSandbox)
	m.lastStateFileStat = make(map[container.FullID]os.FileInfo)

	var listener net.Listener
	var listenErr error
	if strings.HasPrefix(conf.MetricServer, fmt.Sprintf("%c", os.PathSeparator)) {
		beforeBindSt, beforeBindErr := os.Stat(conf.MetricServer)
		if listener, listenErr = (&net.ListenConfig{}).Listen(ctx, "unix", conf.MetricServer); listenErr != nil {
			return util.Errorf("Cannot listen on unix domain socket %q: %v", conf.MetricServer, listenErr)
		}
		afterBindSt, afterBindErr := os.Stat(conf.MetricServer)
		if afterBindErr != nil {
			return util.Errorf("Cannot stat our own unix domain socket %q: %v", conf.MetricServer, afterBindErr)
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
			return util.Errorf("Cannot listen on TCP address %q: %v", conf.MetricServer, listenErr)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/runsc-metrics/healthcheck", logRequest(m.serveHealthCheck))
	mux.HandleFunc("/metrics", logRequest(m.serveMetrics))
	mux.HandleFunc("/", logRequest(m.serveIndex))
	m.srv.Handler = mux
	m.srv.ReadTimeout = httpTimeout
	m.srv.WriteTimeout = httpTimeout
	m.shutdownCh = make(chan os.Signal, 1)
	log.Infof("Server serving on %s for root directory %s.", conf.MetricServer, conf.RootDir)

	go m.verifyLoop(ctx)
	signal.Notify(m.shutdownCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	serveErr := m.srv.Serve(listener)
	log.Infof("Server has stopped accepting requests.")
	m.mu.Lock()
	defer m.mu.Unlock()
	if serveErr != nil {
		if serveErr == http.ErrServerClosed {
			return subcommands.ExitSuccess
		}
		return util.Errorf("Cannot serve on address %s: %v", conf.MetricServer, serveErr)
	}
	// Per documentation, http.Server.Serve can never return a nil error, so this is not a success.
	return util.Errorf("HTTP server Serve() did not return expected error")
}
