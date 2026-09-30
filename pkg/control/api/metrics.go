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

package api

import (
	"fmt"
	"regexp"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sync"
)

// GetRegisteredMetricsOpts contains metric registration query options.
type GetRegisteredMetricsOpts struct{}

// MetricsRegistrationResponse contains metric registration data.
type MetricsRegistrationResponse struct {
	RegisteredMetrics *pb.MetricRegistration
}

// MetricsExportOpts contains metric exporting options.
type MetricsExportOpts struct {
	// If set, this is a regular expression that is used to filter the set of
	// exported metrics.
	OnlyMetrics string `json:"only_metrics"`
}

var (
	lastOnlyMetricsMu sync.Mutex

	// lastOnlyMetricsStr is the last value of the "only_metrics" parameter passed to
	// MetricsExport. It is used to avoid re-compiling the regular expression on every
	// request in the common case where a single metric scraper is scraping the sandbox
	// metrics using the same filter in each request.
	//
	// +checklocks:lastOnlyMetricsMu
	lastOnlyMetricsStr string

	// lastOnlyMetrics is the compiled version of lastOnlyMetricsStr.
	//
	// +checklocks:lastOnlyMetricsMu
	lastOnlyMetrics *regexp.Regexp
)

// FilterFunc returns a filter function to filter relevant Prometheus metric
// names.
func (m *MetricsExportOpts) FilterFunc() (func(*prometheus.Metric) bool, error) {
	if m.OnlyMetrics == "" {
		return nil, nil
	}
	lastOnlyMetricsMu.Lock()
	defer lastOnlyMetricsMu.Unlock()
	onlyMetricsReg := lastOnlyMetrics
	if m.OnlyMetrics != lastOnlyMetricsStr {
		reg, err := regexp.Compile(m.OnlyMetrics)
		if err != nil {
			return nil, fmt.Errorf("cannot compile regexp %q: %v", m.OnlyMetrics, err)
		}
		lastOnlyMetricsStr = m.OnlyMetrics
		lastOnlyMetrics = reg
		onlyMetricsReg = reg
	}
	return func(m *prometheus.Metric) bool {
		return onlyMetricsReg.MatchString(m.Name)
	}, nil
}

// Verify verifies that the given exported data is compliant with the export
// options. This should be run client-side to double-check results.
func (m *MetricsExportOpts) Verify(data *MetricsExportData) error {
	filterFunc, err := m.FilterFunc()
	if err != nil {
		return err
	}
	if filterFunc != nil && data.Snapshot != nil {
		for _, data := range data.Snapshot.Data {
			if !filterFunc(data.Metric) {
				return fmt.Errorf("metric %v violated the filter set in export options", data.Metric)
			}
		}
	}
	return nil
}

// MetricsExportData contains data for all metrics being exported.
type MetricsExportData struct {
	Snapshot *prometheus.Snapshot `json:"snapshot"`
}
