// Copyright 2024 The gVisor Authors.
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

// Package metricsviz charts profiling metrics data and renders them to HTML.
package metricsviz

import (
	"fmt"
	"hash/adler32"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"gvisor.dev/gvisor/pkg/metric"
	mpb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

// MetricName is the name of a metric.
type MetricName string

// Metric is the full metadata about a metric.
type Metric struct {
	// Name is the name of the metric.
	Name MetricName
	// Metadata is the metadata of the metric.
	Metadata *mpb.MetricMetadata
}

// MetricAndFields is a metric name and a set of field values.
type MetricAndFields struct {
	// MetricName is the name of the metric.
	MetricName MetricName
	// FieldValues is the comma-concatenated version of the field values.
	FieldValues string
}

// Point is a single data point at a given time within a time series.
type Point struct {
	// When is the time at which the value was measured.
	When time.Time
	// Value is the value that was measured at that time.
	Value uint64
}

// TimeSeries describes the evolution of a metric (for a given set of field
// values) over time.
type TimeSeries struct {
	// Metric is the metric being measured.
	Metric *Metric
	// Fields is the set of field values of the metric.
	FieldValues map[string]string
	// Data is the timestamped set of data points for this metric and field
	// values.
	Data []Point
}

// Data maps metrics and field values to timeseries.
type Data struct {
	data map[MetricAndFields]*TimeSeries
}

// Parse parses metrics data out of the given logs containing
// profiling metrics data.
// If `hasPrefix`, only lines prefixed with `metric.MetricsPrefix`
// will be parsed. If false, all lines will be parsed, and the
// prefix will be stripped if it is found.
func Parse(logs string, hasPrefix bool) (*Data, error) {
	data := &Data{make(map[MetricAndFields]*TimeSeries)}
	var header []MetricAndFields
	metricsMeta := make(map[MetricName]*Metric)
	h := adler32.New()
	checkedHash := false
	var startTime time.Time
	for _, line := range strings.Split(logs, "\n") {
		if hasPrefix && !strings.HasPrefix(line, metric.MetricsPrefix) {
			continue
		}
		lineData := strings.TrimPrefix(line, metric.MetricsPrefix)

		// Check for hash match.
		if strings.HasPrefix(lineData, metric.MetricsHashIndicator) {
			hash := strings.TrimPrefix(lineData, metric.MetricsHashIndicator)
			wantHashInt64, err := strconv.ParseUint(strings.TrimPrefix(hash, "0x"), 16, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid hash line: %q: %w", line, err)
			}
			wantHash := uint32(wantHashInt64)
			if gotHash := h.Sum32(); gotHash != wantHash {
				return nil, fmt.Errorf("hash mismatch: computed 0x%x, logs said it should be 0x%x", gotHash, wantHash)
			}
			checkedHash = true
			continue
		}

		// If it's not a hash line, add it to the hash regardless of which other
		// type of line it is.
		h.Write([]byte(lineData))
		h.Write([]byte("\n"))

		if strings.HasPrefix(lineData, metric.MetricsMetaIndicator) {
			lineMetadata := strings.TrimPrefix(lineData, metric.MetricsMetaIndicator)
			components := strings.Split(lineMetadata, "\t")
			if len(components) != 2 {
				return nil, fmt.Errorf("invalid meta line: %q", line)
			}
			name := MetricName(components[0])
			var metadata mpb.MetricMetadata
			if err := protojson.Unmarshal([]byte(components[1]), &metadata); err != nil {
				return nil, fmt.Errorf("invalid metric metadata line: %q", line)
			}
			metricsMeta[name] = &Metric{
				Name:     name,
				Metadata: &metadata,
			}
			continue
		}

		if strings.HasPrefix(lineData, metric.MetricsStartTimeIndicator) {
			timestamp, err := strconv.ParseUint(strings.TrimPrefix(lineData, metric.MetricsStartTimeIndicator), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid start time line: %q: %w", line, err)
			}
			const nanosPerSecond = 1_000_000_000
			startTime = time.Unix(int64(timestamp/nanosPerSecond), int64(timestamp%nanosPerSecond))
			continue
		}

		// Check for the header line.
		if header == nil {
			// Assume the first non-metadata line is the header.
			headerCells := strings.Split(lineData, "\t")
			if headerCells[0] != metric.TimeColumn {
				return nil, fmt.Errorf("invalid header line: %q", line)
			}
			for _, cell := range headerCells[1:] {
				// If metric fields were to be implemented, they would be part of
				// the header cell here. For now we just assume that the header
				// cells are just metric names.
				name := MetricName(cell)
				if _, ok := metricsMeta[name]; !ok {
					return nil, fmt.Errorf("invalid header line: %q (unknown metric %q)", line, name)
				}
				maf := MetricAndFields{MetricName: name}
				header = append(header, maf)
				data.data[maf] = &TimeSeries{Metric: metricsMeta[name]}
			}
			if len(header) != len(metricsMeta) {
				return nil, fmt.Errorf("invalid header line: %q (header has %d metrics (%+v), but %d metrics were found in metadata: %v)", line, len(header), header, len(metricsMeta), metricsMeta)
			}
			continue
		}

		// Regular lines.
		tabularData := strings.Split(lineData, "\t")
		if len(tabularData) != len(header)+1 {
			return nil, fmt.Errorf("invalid data line: %q with %d components which does not match header %v which has %d components", line, len(tabularData), header, len(header))
		}
		offsetNanos, err := strconv.ParseUint(tabularData[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid data line: %q (bad timestamp: %w)", line, err)
		}
		timestamp := startTime.Add(time.Duration(offsetNanos) * time.Nanosecond)
		for i, cell := range tabularData[1:] {
			timeseries := data.data[header[i]]
			value, err := strconv.ParseUint(cell, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid data line: %q (bad value in column %d: %q: %w)", line, i, cell, err)
			}
			timeseries.Data = append(timeseries.Data, Point{When: timestamp, Value: value})
		}
	}
	if startTime.IsZero() {
		return nil, fmt.Errorf("no start time found in logs")
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("no header found in logs")
	}
	if hasPrefix && !checkedHash {
		return nil, fmt.Errorf("no hash data found in logs")
	}
	return data, nil
}
