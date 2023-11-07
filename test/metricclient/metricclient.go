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

// Package metricclient provides utility functions to start, stop, and talk to a metric server.
package metricclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/prometheus/common/expfmt"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
)

// MetricClient implements an HTTP client that can spawn and connect to a running runsc metrics
// server process and register/unregister sandbox metrics.
type MetricClient struct {
	addr    string
	rootDir string
	dialer  net.Dialer
	client  http.Client
	mu      sync.Mutex
	server  *exec.Cmd
}

// NewMetricClient creates a new MetricClient that can talk to the metric server at address addr.
func NewMetricClient(addr, rootDir string) *MetricClient {
	c := &MetricClient{
		addr:    strings.ReplaceAll(addr, "%RUNTIME_ROOT%", rootDir),
		rootDir: rootDir,
		dialer: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		client: http.Client{
			Transport: &http.Transport{
				// We only talk over the local network, so no need to spend CPU on compression.
				DisableCompression:    true,
				MaxIdleConns:          1,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
			},
			Timeout: 30 * time.Second,
		},
	}
	// In order to support talking HTTP over Unix domain sockets, we use a custom dialer
	// which knows how to dial the right address.
	// The HTTP address passed as URL to the client is ignored.
	c.client.Transport.(*http.Transport).DialContext = c.dialContext
	return c
}

// dialContext dials the metric server. It ignores whatever address is given to it.
func (c *MetricClient) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	network := "tcp"
	if strings.HasPrefix(c.addr, fmt.Sprintf("%c", os.PathSeparator)) {
		network = "unix"
	}
	return c.dialer.DialContext(ctx, network, c.addr)
}

// Close closes any idle HTTP connection.
func (c *MetricClient) Close() {
	c.client.CloseIdleConnections()
}

// req performs an HTTP request against the metrics server.
// It returns an http.Response, and a function to close out the request that should be called when
// the response is no longer necessary.
func (c *MetricClient) req(ctx context.Context, timeout time.Duration, method, endpoint string, params map[string]string) (*http.Response, func(), error) {
	cancelFunc := context.CancelFunc(func() {})
	if timeout != 0 {
		ctx, cancelFunc = context.WithTimeout(ctx, timeout)
	}
	var bodyBytes io.Reader
	var getSuffix string
	if len(params) != 0 {
		switch method {
		case http.MethodGet:
			getParams := url.Values{}
			for k, v := range params {
				getParams.Add(k, v)
			}
			getSuffix = fmt.Sprintf("?%s", getParams.Encode())
		case http.MethodPost:
			values := url.Values{}
			for k, v := range params {
				values.Set(k, v)
			}
			bodyBytes = strings.NewReader(values.Encode())
		default:
			cancelFunc()
			return nil, nil, fmt.Errorf("unsupported method: %v", method)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("http://runsc-metrics%s%s", endpoint, getSuffix), bodyBytes)
	if err != nil {
		cancelFunc()
		return nil, nil, fmt.Errorf("cannot create request object: %v", err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		cancelFunc()
		return nil, nil, err
	}
	return resp, func() {
		resp.Body.Close()
		cancelFunc()
	}, err
}

// HealthCheck pokes the metrics server and checks that it is running.
func (c *MetricClient) HealthCheck(ctx context.Context) error {
	// There are multiple scenarios here:
	//  - The server isn't running. We'll get a "connection failed" error.
	//  - There is an HTTP server bound to the address, but it is not the metric server.
	//    We'll fail the /runsc-metrics/healthcheck request with an HTTP error code.
	//  - There is a server bound to the address, but it is not the metric server and doesn't speak
	//    HTTP. We'll fail the request if that's the case.
	//  - There is a server bound to the address, it is the metric server, but it is not serving the
	//    same root directory. The server will reject the request if that's the case.
	//  - The server is running, and the /runsc-metrics/healthcheck request succeeds.
	//  - The server is running, but it is shutting down. The metrics server will fail the
	//    /runsc-metrics/healthcheck request in this case.
	resp, closeReq, err := c.req(ctx, 5*time.Second, http.MethodPost, "/runsc-metrics/healthcheck", map[string]string{
		"root": c.rootDir,
	})
	if err != nil {
		return err
	}
	defer closeReq()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return err
	}
	if !strings.HasPrefix(buf.String(), "runsc-metrics:OK") {
		return errors.New("server responded to request but not with the expected prefix")
	}
	return nil
}

// SpawnServer starts a metric server at the expected address.
// It blocks until it responds to healthchecks, or the context expires.
// Fails if the server fails to start or to bind within the context.
// Callers should call ShutdownServer to stop the server.
// A running server must be stopped before a new one can be successfully started.
// baseConf is used for passing other flags to the server, e.g. debug log directory.
func (c *MetricClient) SpawnServer(ctx context.Context, baseConf *config.Config, extraArgs ...string) error {
	metricServerBinPath, err := testutil.FindFile("runsc/cmd/metricserver/metricserver_bin")
	if err != nil {
		return fmt.Errorf("cannot find metricserver_bin: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server != nil {
		return errors.New("this metric client already has a server associated with it")
	}
	bindCtx, bindCancel := context.WithTimeout(ctx, 20*time.Second)
	defer bindCancel()
	launchBackoff := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Millisecond,
		Multiplier:          1.5,
		MaxInterval:         250 * time.Millisecond,
		RandomizationFactor: 0.1,
		Clock:               backoff.SystemClock,
	}, bindCtx)
	// Overriden metric server address with the address this metric client is configured to use.
	// This should be the same but may contain string replacements (e.g. "%ID%").
	overriddenConf := *baseConf
	overriddenConf.MetricServer = c.addr
	overriddenConf.RootDir = c.rootDir
	c.server = exec.Command(metricServerBinPath, overriddenConf.ToFlags()...)
	cu := cleanup.Make(func() {
		c.server = nil
	})
	defer cu.Clean()
	c.server.SysProcAttr = &unix.SysProcAttr{
		// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
		// when re-parented.
		Setsid: true,
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0755)
	if err != nil {
		return fmt.Errorf("cannot open devnull at %s: %w", os.DevNull, err)
	}
	defer devnull.Close() // Don't leak file descriptors.
	c.server.Stdin = devnull
	c.server.Stdout = devnull
	c.server.Stderr = devnull
	// Set Args[0] to make easier to spot the sandbox process. Otherwise it's
	// shown as `exe`.
	c.server.Args[0] = "runsc-metrics"
	c.server.Args = append(c.server.Args, "metric-server")
	c.server.Args = append(c.server.Args, extraArgs...)
	if err := c.server.Start(); err != nil {
		return fmt.Errorf("cannot start metrics server: %w", err)
	}
	launchBackoff.Reset()
	for bindCtx.Err() == nil && c.HealthCheck(bindCtx) != nil {
		nextBackoff := launchBackoff.NextBackOff()
		if nextBackoff == backoff.Stop {
			break
		}
		time.Sleep(nextBackoff)
	}
	if err := unix.Kill(c.server.Process.Pid, 0); err != nil {
		return fmt.Errorf("metrics server crashed: %w", c.server.Wait())
	}
	if bindCtx.Err() != nil {
		return fmt.Errorf("metrics server did not bind to %s in time: %w", c.addr, bindCtx.Err())
	}
	cu.Release()
	return nil
}

// ShutdownServer asks the metrics server to shut itself down.
// It blocks until the server process has exitted or the context expires.
func (c *MetricClient) ShutdownServer(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server == nil {
		return errors.New("server not started")
	}
	c.Close()
	// The server will shut itself down ASAP after it gets SIGTERM.
	if err := c.server.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("cannot send signal to metrics server: %w", err)
	}
	// Wait for the process to exit.
	if err := c.server.Wait(); err != nil {
		// When used in tests that use testutil.Reaper, it's possible that the metric server
		// has already been reaped by it. In this case, do not treat this as an error.
		if strings.Contains(err.Error(), "no child process") {
			c.server = nil
			return nil
		}
		return fmt.Errorf("failed to wait for metrics server to exit: %w", err)
	}
	c.server = nil
	return nil
}

// MetricData is the raw contents returned by GetMetrics, with helper functions
// to extract single values out of it.
type MetricData string

// GetMetrics returns the raw Prometheus-formatted metric data from the metric server.
// `urlParams` may contain a special parameter with the empty string as the key.
// If this is set, that string is used to override the request path from its default
// value of `/metrics`.
func (c *MetricClient) GetMetrics(ctx context.Context, urlParams map[string]string) (MetricData, error) {
	path := "/metrics"
	if overridePath, found := urlParams[""]; found {
		path = overridePath
		delete(urlParams, "")
	}
	resp, closeReq, err := c.req(ctx, 10*time.Second, http.MethodGet, path, urlParams)
	if err != nil {
		return "", fmt.Errorf("cannot get /metrics: %v", err)
	}
	defer closeReq()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", fmt.Errorf("cannot read from response body: %v", err)
	}
	return MetricData(buf.String()), nil
}

// GetPrometheusInteger returns the integer value of a Prometheus metric with given name and labels.
func (m MetricData) GetPrometheusInteger(metricName string, wantLabels map[string]string) (int64, time.Time, error) {
	// Parse raw Prometheus-formatted data.
	var buf bytes.Buffer
	buf.WriteString(string(m))
	parsed, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf)
	if err != nil {
		return 0, time.Time{}, err
	}
	// See if there is any data for the given metric name.
	metricData, found := parsed[metricName]
	if !found {
		return 0, time.Time{}, fmt.Errorf("metric %q not found", metricName)
	}
	// See if we can find exactly one data point for which the labels match `wantLabels`.
	// foundIndex is the index within `metricData.Metric` of the most-recently-found data point
	// that matches `wantLabels`.
	foundIndex := -1
	for i, data := range metricData.GetMetric() {
		// Convert data.Label (which is a list of key-value tuples) into a Go map.
		dataLabels := make(map[string]string, len(data.GetLabel()))
		for _, label := range data.GetLabel() {
			dataLabels[label.GetName()] = label.GetValue()
		}
		// Check if `wantLabels` is a subset of `dataLabels`.
		allMatching := true
		for wantLabel, wantValue := range wantLabels {
			if dataLabels[wantLabel] != wantValue {
				allMatching = false
				break
			}
		}
		if !allMatching {
			// This data point is for a different label combination than the one we want.
			continue
		}
		// Record the index at which we found this data point within `metricData.Metric`.
		// If this index isn't -1, this means we found multiple such indexes.
		// This could happen if the metric has multiple data points with `wantLabels` + an
		// additional label which isn't in `wantLabels` and which takes on multiple distinct
		// values. This function doesn't support retrieving data for such cases.
		if foundIndex != -1 {
			return 0, time.Time{}, fmt.Errorf("found multiple metric data matching requested labels %v", wantLabels)
		}
		foundIndex = i
	}
	if foundIndex == -1 {
		return 0, time.Time{}, fmt.Errorf("no metric data matching requested labels %v", wantLabels)
	}
	// We've found exactly one data point.
	data := metricData.GetMetric()[foundIndex]
	// Convert the value of this data point to an int regardless of its underlying Prometheus type.
	var floatValue float64
	if data.GetCounter() != nil && data.GetCounter().Value != nil {
		floatValue = data.GetCounter().GetValue()
	} else if data.GetGauge() != nil && data.GetGauge().Value != nil {
		floatValue = data.GetGauge().GetValue()
	} else {
		return 0, time.Time{}, fmt.Errorf("metric is not numerical: %v", data)
	}
	if math.Floor(floatValue) != floatValue {
		return 0, time.Time{}, fmt.Errorf("value %v cannot be rounded to an integer", floatValue)
	}
	return int64(math.Floor(floatValue)), time.UnixMilli(data.GetTimestampMs()), nil
}

// WantMetric designates the metadata required to select a single metric from a single sandbox.
type WantMetric struct {
	// Metric is the name of the metric to get.
	Metric string
	// Sandbox is the ID of the sandbox to look up the metric for.
	Sandbox string
	// Pod and Namespace are the pod and namespace labels associated with the sandbox.
	// Leave empty if the sandbox metadata doesn't contain this information.
	Pod, Namespace string
	// ExtraLabels are additional key-value labels that must match.
	ExtraLabels map[string]string
}

// GetPrometheusContainerInteger returns the integer value of a Prometheus metric from the
// given WantMetric data.
func (m MetricData) GetPrometheusContainerInteger(want WantMetric) (int64, time.Time, error) {
	labels := map[string]string{
		"sandbox": want.Sandbox,
	}
	if want.Pod != "" {
		labels["pod_name"] = want.Pod
	}
	if want.Namespace != "" {
		labels["namespace_name"] = want.Namespace
	}
	for k, v := range want.ExtraLabels {
		labels[k] = v
	}
	return m.GetPrometheusInteger(want.Metric, labels)
}

// GetSandboxMetadataMetric returns the labels attached to the metadata metric for a given sandbox.
func (m MetricData) GetSandboxMetadataMetric(want WantMetric) (map[string]string, error) {
	var buf bytes.Buffer
	buf.WriteString(string(m))
	parsed, err := (&expfmt.TextParser{}).TextToMetricFamilies(&buf)
	if err != nil {
		return nil, err
	}
	metricData, found := parsed[want.Metric]
	if !found {
		return nil, fmt.Errorf("metric %q not found", want.Metric)
	}
	foundIndex := -1
	for i, data := range metricData.GetMetric() {
		dataLabels := make(map[string]string, len(data.GetLabel()))
		for _, label := range data.GetLabel() {
			dataLabels[label.GetName()] = label.GetValue()
		}
		allMatching := true
		for wantLabel, wantValue := range map[string]string{
			prometheus.SandboxIDLabel: want.Sandbox,
			prometheus.NamespaceLabel: want.Namespace,
			prometheus.PodNameLabel:   want.Pod,
		} {
			if dataLabels[wantLabel] != wantValue {
				allMatching = false
				break
			}
		}
		if allMatching {
			if foundIndex != -1 {
				return nil, errors.New("found multiple metadata metrics matching requested labels")
			}
			foundIndex = i
		}
	}
	if foundIndex == -1 {
		return nil, errors.New("no metadata metric matching requested labels")
	}
	data := metricData.GetMetric()[foundIndex]
	metadataLabels := make(map[string]string, len(data.GetLabel()))
	for _, label := range data.GetLabel() {
		if label.GetName() == prometheus.SandboxIDLabel || label.GetName() == prometheus.NamespaceLabel || label.GetName() == prometheus.PodNameLabel {
			continue
		}
		metadataLabels[label.GetName()] = label.GetValue()
	}
	return metadataLabels, nil
}
