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

// Package prometheus contains Prometheus-compliant metric data structures and utilities.
// It can export data in Prometheus data format, documented at:
// https://prometheus.io/docs/instrumenting/exposition_formats/
package prometheus

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"
)

// timeNow is the time.Now() function. Can be mocked in tests.
var timeNow = time.Now

// Type is a Prometheus metric type.
type Type int

// List of supported Prometheus metric types.
const (
	TypeUntyped = Type(iota)
	TypeGauge
	TypeCounter
	TypeHistogram
)

// Metric is a Prometheus metric metadata.
type Metric struct {
	// Name is the Prometheus metric name.
	Name string `json:"name"`

	// Type is the type of the metric.
	Type Type `json:"type"`

	// Help is an optional helpful string explaining what the metric is about.
	Help string `json:"help"`
}

// writeHeaderTo writes the metric comment header to the given writer.
func (m *Metric) writeHeaderTo(w io.Writer, options SnapshotExportOptions) error {
	if m.Help != "" {
		// Prometheus metric description escape rules: Only backslashes and line breaks need escaping.
		if _, err := io.WriteString(w, fmt.Sprintf("# HELP %s%s %s\n", options.ExporterPrefix, m.Name, strings.ReplaceAll(strings.ReplaceAll(m.Help, "\\", "\\\\"), "\n", "\\n"))); err != nil {
			return err
		}
	}
	var metricType string
	switch m.Type {
	case TypeGauge:
		metricType = "gauge"
	case TypeCounter:
		metricType = "counter"
	case TypeHistogram:
		metricType = "histogram"
	case TypeUntyped:
		metricType = "untyped"
	}
	if metricType != "" {
		if _, err := io.WriteString(w, fmt.Sprintf("# TYPE %s%s %s\n", options.ExporterPrefix, m.Name, metricType)); err != nil {
			return err
		}
	}
	return nil
}

// Number represents a numerical value.
// In Prometheus, all numbers are float64s.
// However, for the purpose of usage of this library, we support expressing numbers as integers,
// which makes things like counters much easier and more precise.
// At data export time (i.e. when written out in Prometheus data format), it is coallesced into
// a float.
type Number struct {
	// Float is the float value of this number.
	// Mutually exclusive with Int.
	Float float64 `json:"float,omitempty"`

	// Int is the integer value of this number.
	// Mutually exclusive with Float.
	Int int64 `json:"int,omitempty"`
}

// IsInteger returns whether this number contains an integer value.
// This is defined as either having the `Float` part set to zero (in which case the `Int` part takes
// precedence), or having `Float` be a value equal to its own rounding and not a special float.
func (n *Number) IsInteger() bool {
	if n.Float == 0 {
		return true
	}
	if math.IsNaN(n.Float) || n.Float == math.Inf(-1) || n.Float == math.Inf(1) {
		return false
	}
	return math.Round(n.Float) == n.Float
}

// String returns a string representation of this number.
func (n *Number) String() string {
	var s strings.Builder
	if err := n.writeTo(&s); err != nil {
		panic(err)
	}
	return s.String()
}

// SameType returns true if `n` and `other` are either both floating-point or both integers.
// If a `Number` is zero, it is considered of the same type as any other zero `Number`.
func (n *Number) SameType(other *Number) bool {
	// Within `n` and `other`, at least one of `Int` or `Float` must be set to zero.
	// Therefore, this verifies that there is at least one shared zero between the two.
	return n.Float == other.Float || n.Int == other.Int
}

// GreaterThan returns true if n > other.
// Precondition: n.SameType(other) is true. Panics otherwise.
func (n *Number) GreaterThan(other *Number) bool {
	if !n.SameType(other) {
		panic("tried to compare two numbers of different types")
	}
	if n.IsInteger() {
		return n.Int > other.Int
	}
	return n.Float > other.Float
}

// writeTo writes the number to the given writer.
func (n *Number) writeTo(w io.Writer) error {
	var s string
	switch {
	// Zero case:
	case n.Int == 0 && n.Float == 0:
		s = "0"

		// Integer case:
	case n.Int != 0:
		s = fmt.Sprintf("%d", n.Int)

	// Special float cases:
	case n.Float == math.Inf(-1):
		s = "-Inf"
	case n.Float == math.Inf(1):
		s = "+Inf"
	case math.IsNaN(n.Float):
		s = "NaN"

	// Regular float case:
	default:
		s = fmt.Sprintf("%f", n.Float)
	}
	_, err := io.WriteString(w, s)
	return err
}

// Bucket is a single histogram bucket.
type Bucket struct {
	// UpperBound is the upper bound of the bucket.
	// The lower bound of the bucket is the largest UpperBound within other Histogram Buckets that
	// is smaller than this bucket's UpperBound.
	// The bucket with the smallest UpperBound within a Histogram implicitly has -Inf as lower bound.
	// This should be set to +Inf to mark the "last" bucket.
	UpperBound Number `json:"le"`

	// Samples is the number of samples in the bucket.
	// Note: When exported to Prometheus, they are exported cumulatively, i.e. the count of samples
	// exported in Bucket i is actually sum(histogram.Buckets[j].Samples for 0 <= j <= i).
	Samples uint64 `json:"n,omitempty"`
}

// Histogram contains data about histogram values.
type Histogram struct {
	// Total is the sum of sample values across all buckets.
	Total Number `json:"total"`
	// Buckets contains per-bucket data.
	// A distribution with n finite-boundary buckets should have n+2 entries here.
	// The 0th entry is the underflow bucket (i.e. the one with -inf as lower bound),
	// and the last aka (n+1)th entry is the overflow bucket (i.e. the one with +inf as upper bound).
	Buckets []Bucket `json:"buckets,omitempty"`
}

// Data is an observation of the value of a single metric at a certain point in time.
type Data struct {
	// Metric is the metric for which the value is being reported.
	Metric *Metric `json:"metric"`

	// Labels is a key-value pair representing the labels set on this metric.
	// This may be merged with other labels during export.
	Labels map[string]string `json:"labels,omitempty"`

	// At most one of the fields below may be set.
	// Which one depends on the type of the metric.

	// Number is used for all numerical types.
	Number *Number `json:"val,omitempty"`

	// Histogram is used for histogram-typed metrics.
	HistogramValue *Histogram `json:"histogram,omitempty"`
}

// NewIntData returns a new Data struct with the given metric and value.
func NewIntData(metric *Metric, val int64) *Data {
	return &Data{Metric: metric, Number: &Number{Int: val}}
}

// LabeledIntData returns a new Data struct with the given metric, labels, and value.
func LabeledIntData(metric *Metric, labels map[string]string, val int64) *Data {
	return &Data{Metric: metric, Labels: labels, Number: &Number{Int: val}}
}

// NewFloatData returns a new Data struct with the given metric and value.
func NewFloatData(metric *Metric, val float64) *Data {
	return &Data{Metric: metric, Number: &Number{Float: val}}
}

// ExportOptions contains options that control how metric data is exported in Prometheus format.
type ExportOptions struct {
	// CommentHeader is prepended as a comment before any metric data is exported.
	CommentHeader string

	// MetricsWritten memoizes written metric preambles (help/type comments)
	// by metric name.
	// If specified, this map can be used to avoid duplicate preambles across multiple snapshots.
	// Note that this map is modified in-place during the writing process.
	MetricsWritten map[string]bool
}

// SnapshotExportOptions contains options that control how metric data is exported for an
// individual Snapshot.
type SnapshotExportOptions struct {
	// ExporterPrefix is prepended to all metric names.
	ExporterPrefix string

	// ExtraLabels is added as labels for all metric values.
	ExtraLabels map[string]string
}

// writeMetricPreambleTo writes the metric name to the io.Writer. It may also
// write unwritten help and type comments of the metric if they haven't been
// written to the io.Writer yet.
func (d *Data) writeMetricPreambleTo(w io.Writer, options SnapshotExportOptions, metricsWritten map[string]bool) error {
	// Metric header, if we haven't printed it yet.
	if !metricsWritten[d.Metric.Name] {
		// Extra newline before each preamble for aesthetic reasons.
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		if err := d.Metric.writeHeaderTo(w, options); err != nil {
			return err
		}
		metricsWritten[d.Metric.Name] = true
	}

	// Metric name.
	if options.ExporterPrefix != "" {
		if _, err := io.WriteString(w, options.ExporterPrefix); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, d.Metric.Name); err != nil {
		return err
	}
	return nil
}

// OrderedLabels returns the list of 'label_key="label_value"' in sorted order, except "le" which is
// a reserved Prometheus label name and should go last.
func OrderedLabels(labels ...map[string]string) ([]string, error) {
	var le string
	totalLabels := 0
	for _, labelMap := range labels {
		if leVal, found := labelMap["le"]; found {
			le = leVal
			totalLabels += len(labelMap) - 1
		} else {
			totalLabels += len(labelMap)
		}
	}
	if le != "" {
		totalLabels++
	}
	keys := make(map[string]struct{}, totalLabels)
	for _, labelMap := range labels {
		for label := range labelMap {
			if _, found := keys[label]; found {
				return nil, fmt.Errorf("duplicate label name %q", label)
			}
			keys[label] = struct{}{}
		}
	}
	orderedKeys := make([]string, 0, totalLabels)
	for _, labelMap := range labels {
		for k, v := range labelMap {
			if k != "le" {
				orderedKeys = append(orderedKeys, fmt.Sprintf("%s=%q", k, v))
			}
		}
	}
	sort.Strings(orderedKeys)
	if le != "" {
		orderedKeys = append(orderedKeys, fmt.Sprintf("le=%q", le))
	}
	return orderedKeys, nil
}

// writeLabelsTo writes a set of metric labels.
func (d *Data) writeLabelsTo(w io.Writer, extraLabels map[string]string, leLabel *Number) error {
	if (d.Labels != nil && len(d.Labels) != 0) || (extraLabels != nil && len(extraLabels) != 0) || leLabel != nil {
		if _, err := io.WriteString(w, "{"); err != nil {
			return err
		}
		var orderedLabels []string
		var err error
		if leLabel != nil {
			orderedLabels, err = OrderedLabels(d.Labels, extraLabels, map[string]string{"le": leLabel.String()})
		} else {
			orderedLabels, err = OrderedLabels(d.Labels, extraLabels)
		}
		if err != nil {
			return err
		}
		for i, keyVal := range orderedLabels {
			if i != 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, keyVal); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "}"); err != nil {
			return err
		}
	}
	return nil
}

// writeMetricLine writes a single line with a single number (val) to w.
func (d *Data) writeMetricLine(w io.Writer, metricSuffix string, val *Number, when time.Time, options SnapshotExportOptions, leLabel *Number, metricsWritten map[string]bool) error {
	if err := d.writeMetricPreambleTo(w, options, metricsWritten); err != nil {
		return err
	}
	if metricSuffix != "" {
		if _, err := io.WriteString(w, metricSuffix); err != nil {
			return err
		}
	}
	if err := d.writeLabelsTo(w, options.ExtraLabels, leLabel); err != nil {
		return err
	}
	if _, err := io.WriteString(w, " "); err != nil {
		return err
	}
	if err := val.writeTo(w); err != nil {
		return err
	}
	if _, err := io.WriteString(w, fmt.Sprintf(" %d\n", when.UnixMilli())); err != nil {
		return err
	}
	return nil
}

// writeTo writes the Data to the given writer in Prometheus format.
func (d *Data) writeTo(w io.Writer, when time.Time, options SnapshotExportOptions, metricsWritten map[string]bool) error {
	switch d.Metric.Type {
	case TypeUntyped, TypeGauge, TypeCounter:
		return d.writeMetricLine(w, "", d.Number, when, options, nil, metricsWritten)
	case TypeHistogram:
		// Write an empty line before and after histograms to easily distinguish them from
		// other metric lines.
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		var numSamples uint64
		var samples Number
		for _, bucket := range d.HistogramValue.Buckets {
			numSamples += bucket.Samples
			samples.Int = int64(numSamples) // Prometheus distribution bucket counts are cumulative.
			if err := d.writeMetricLine(w, "_bucket", &samples, when, options, &bucket.UpperBound, metricsWritten); err != nil {
				return err
			}
		}
		if err := d.writeMetricLine(w, "_sum", &d.HistogramValue.Total, when, options, nil, metricsWritten); err != nil {
			return err
		}
		samples.Int = int64(numSamples)
		if err := d.writeMetricLine(w, "_count", &samples, when, options, nil, metricsWritten); err != nil {
			return err
		}
		// Empty line after the histogram.
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown metric type for metric %s: %v", d.Metric.Name, d.Metric.Type)
	}
}

// Snapshot is a snapshot of the values of all the metrics at a certain point in time.
type Snapshot struct {
	// When is the timestamp at which the snapshot was taken.
	// Note that Prometheus ultimately encodes timestamps as millisecond-precision int64s from epoch.
	When time.Time `json:"when,omitempty"`

	// Data is the whole snapshot data.
	// Each Data must be a unique combination of (Metric, Labels) within a Snapshot.
	Data []*Data `json:"data,omitempty"`
}

// NewSnapshot returns a new Snapshot at the current time.
func NewSnapshot() *Snapshot {
	return &Snapshot{When: timeNow()}
}

// Add data point(s) to the snapshot.
// Returns itself for chainability.
func (s *Snapshot) Add(data ...*Data) *Snapshot {
	s.Data = append(s.Data, data...)
	return s
}

// countingWriter implements io.Writer, and counts the number of bytes written to it.
// Useful in this file to keep track of total number of bytes without having to plumb this
// everywhere in the writeX() functions in this file.
type countingWriter struct {
	w       *bufio.Writer
	written int
}

// Write implements io.Writer.Write.
func (w *countingWriter) Write(b []byte) (int, error) {
	written, err := w.w.Write(b)
	w.written += written
	return written, err
}

// Written returns the number of bytes written to the underlying writer (minus buffered writes).
func (w *countingWriter) Written() int {
	return w.written - w.w.Buffered()
}

// writeSingleMetric writes the data to the given writer in Prometheus format.
// It returns the number of bytes written.
func (s *Snapshot) writeSingleMetric(w io.Writer, options SnapshotExportOptions, metricName string, metricsWritten map[string]bool) error {
	if !strings.HasPrefix(metricName, options.ExporterPrefix) {
		return nil
	}
	wantMetricName := strings.TrimPrefix(metricName, options.ExporterPrefix)
	for _, d := range s.Data {
		if d.Metric.Name != wantMetricName {
			continue
		}
		if err := d.writeTo(w, s.When, options, metricsWritten); err != nil {
			return err
		}
	}
	return nil
}

// Write writes one or more snapshots to the writer.
// This ensures same-name metrics across different snapshots are printed together, per spec.
func Write(w io.Writer, options ExportOptions, snapshotsToOptions map[*Snapshot]SnapshotExportOptions) (int, error) {
	if len(snapshotsToOptions) == 0 {
		return 0, nil
	}
	cw := &countingWriter{w: bufio.NewWriter(w)}
	if options.CommentHeader != "" {
		for _, commentLine := range strings.Split(options.CommentHeader, "\n") {
			if _, err := io.WriteString(cw, "# "); err != nil {
				return cw.Written(), err
			}
			if _, err := io.WriteString(cw, commentLine); err != nil {
				return cw.Written(), err
			}
			if _, err := io.WriteString(cw, "\n"); err != nil {
				return cw.Written(), err
			}
		}
	}
	snapshots := make([]*Snapshot, 0, len(snapshotsToOptions))
	for snapshot := range snapshotsToOptions {
		snapshots = append(snapshots, snapshot)
	}
	switch len(snapshots) {
	case 1: // Single-snapshot case.
		if _, err := io.WriteString(cw, fmt.Sprintf("# Writing data from snapshot containing %d data points taken at %v.\n", len(snapshots[0].Data), snapshots[0].When)); err != nil {
			return cw.Written(), err
		}
	default: // Multi-snapshot case.
		// Provide a consistent ordering of snapshots.
		sort.Slice(snapshots, func(i, j int) bool {
			return reflect.ValueOf(snapshots[i]).Pointer() < reflect.ValueOf(snapshots[j]).Pointer()
		})
		if _, err := io.WriteString(cw, fmt.Sprintf("# Writing data from %d snapshots:\n", len(snapshots))); err != nil {
			return cw.Written(), err
		}
		for _, snapshot := range snapshots {
			if _, err := io.WriteString(cw, fmt.Sprintf("#   - Snapshot with %d data points taken at %v: %v\n", len(snapshot.Data), snapshot.When, snapshotsToOptions[snapshot].ExtraLabels)); err != nil {
				return cw.Written(), err
			}
		}
	}
	if _, err := io.WriteString(cw, "\n"); err != nil {
		return cw.Written(), err
	}
	if options.MetricsWritten == nil {
		options.MetricsWritten = make(map[string]bool)
	}
	metricNamesMap := make(map[string]bool, len(options.MetricsWritten))
	metricNames := make([]string, 0, len(options.MetricsWritten))
	for _, snapshot := range snapshots {
		for _, data := range snapshot.Data {
			metricName := snapshotsToOptions[snapshot].ExporterPrefix + data.Metric.Name
			if !metricNamesMap[metricName] {
				metricNamesMap[metricName] = true
				metricNames = append(metricNames, metricName)
			}
		}
	}
	sort.Strings(metricNames)
	for _, metricName := range metricNames {
		for _, snapshot := range snapshots {
			snapshot.writeSingleMetric(cw, snapshotsToOptions[snapshot], metricName, options.MetricsWritten)
		}
	}
	if _, err := io.WriteString(cw, "\n# End of metric data.\n"); err != nil {
		return cw.Written(), err
	}
	if err := cw.w.Flush(); err != nil {
		return cw.Written(), err
	}
	return cw.Written(), nil
}
