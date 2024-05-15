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
	"bytes"
	"errors"
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

// Prometheus label names used to identify each sandbox.
const (
	SandboxIDLabel   = "sandbox"
	PodNameLabel     = "pod_name"
	NamespaceLabel   = "namespace_name"
	IterationIDLabel = "iteration"
)

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

// writeMetricHeaderTo writes the metric comment header to the given writer.
func writeMetricHeaderTo[T io.StringWriter](w T, m *Metric, options SnapshotExportOptions) error {
	if m.Help != "" {
		// This writes each string component one by one (rather than using fmt.Sprintf)
		// in order to avoid allocating strings for each metric.
		if _, err := w.WriteString("# HELP "); err != nil {
			return err
		}
		if _, err := w.WriteString(options.ExporterPrefix); err != nil {
			return err
		}
		if _, err := w.WriteString(m.Name); err != nil {
			return err
		}
		if _, err := w.WriteString(" "); err != nil {
			return err
		}
		if _, err := writeEscapedString(w, m.Help, false); err != nil {
			return err
		}
		if _, err := w.WriteString("\n"); err != nil {
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
		if _, err := w.WriteString("# TYPE "); err != nil {
			return err
		}
		if _, err := w.WriteString(options.ExporterPrefix); err != nil {
			return err
		}
		if _, err := w.WriteString(m.Name); err != nil {
			return err
		}
		if _, err := w.WriteString(" "); err != nil {
			return err
		}
		if _, err := w.WriteString(metricType); err != nil {
			return err
		}
		if _, err := w.WriteString("\n"); err != nil {
			return err
		}
	}
	return nil
}

// Number represents a numerical value.
// In Prometheus, all numbers are float64s.
// However, for the purpose of usage of this library, we support expressing numbers as integers,
// which makes things like counters much easier and more precise.
// At data export time (i.e. when written out in Prometheus data format), it is coalesced into
// a float.
type Number struct {
	// Float is the float value of this number.
	// Mutually exclusive with Int.
	Float float64 `json:"float,omitempty"`

	// Int is the integer value of this number.
	// Mutually exclusive with Float.
	Int int64 `json:"int,omitempty"`
}

// Common numbers which are reused and don't need their own memory allocations.
var (
	zero        = Number{}
	intOne      = Number{Int: 1}
	floatOne    = Number{Float: 1.0}
	floatNaN    = Number{Float: math.NaN()}
	floatInf    = Number{Float: math.Inf(1)}
	floatNegInf = Number{Float: math.Inf(-1)}
)

// NewInt returns a new integer Number.
func NewInt(val int64) *Number {
	switch val {
	case 0:
		return &zero
	case 1:
		return &intOne
	default:
		return &Number{Int: val}
	}
}

// NewFloat returns a new floating-point Number.
func NewFloat(val float64) *Number {
	if math.IsNaN(val) {
		return &floatNaN
	}
	switch val {
	case 0:
		return &zero
	case 1.0:
		return &floatOne
	case math.Inf(1.0):
		return &floatInf
	case math.Inf(-1.0):
		return &floatNegInf
	default:
		return &Number{Float: val}
	}
}

// IsInteger returns whether this number contains an integer value.
// This is defined as either having the `Float` part set to zero (in which case the `Int` part takes
// precedence), or having `Float` be a value equal to its own rounding and not a special float.
//
//go:nosplit
func (n *Number) IsInteger() bool {
	if n.Float == 0 {
		return true
	}
	if math.IsNaN(n.Float) || n.Float == math.Inf(-1) || n.Float == math.Inf(1) {
		return false
	}
	return n.Float < float64(math.MaxInt64) && n.Float > float64(math.MinInt64) && math.Round(n.Float) == n.Float
}

// ToFloat returns this number as a floating-point number, regardless of which
// type the number was encoded as. An integer Number will have its value cast
// to a float, while a floating-point Number will have its value returned
// as-is.
//
//go:nosplit
func (n *Number) ToFloat() float64 {
	if n.Int != 0 {
		return float64(n.Int)
	}
	return n.Float
}

// String returns a string representation of this number.
func (n *Number) String() string {
	var s strings.Builder
	if err := writeNumberTo(&s, n); err != nil {
		panic(err)
	}
	return s.String()
}

// SameType returns true if `n` and `other` are either both floating-point or both integers.
// If a `Number` is zero, it is considered of the same type as any other zero `Number`.
//
//go:nosplit
func (n *Number) SameType(other *Number) bool {
	// Within `n` and `other`, at least one of `Int` or `Float` must be set to zero.
	// Therefore, this verifies that there is at least one shared zero between the two.
	return n.Float == other.Float || n.Int == other.Int
}

// GreaterThan returns true if n > other.
// Precondition: n.SameType(other) is true. Panics otherwise.
//
//go:nosplit
func (n *Number) GreaterThan(other *Number) bool {
	if !n.SameType(other) {
		panic("tried to compare two numbers of different types")
	}
	if n.IsInteger() {
		return n.Int > other.Int
	}
	return n.Float > other.Float
}

// WriteInteger writes the given integer to a writer without allocating strings.
//
//go:nosplit
func WriteInteger[T io.StringWriter](w T, val int64) (int, error) {
	const decimalDigits = "0123456789"
	if val == 0 {
		return w.WriteString(decimalDigits[0:1])
	}
	var written int
	if val < 0 {
		n, err := w.WriteString("-")
		written += n
		if err != nil {
			return written, err
		}
		val = -val
	}
	decimal := int64(1)
	for ; val/decimal != 0; decimal *= 10 {
	}
	for decimal /= 10; decimal > 0; decimal /= 10 {
		digit := (val / decimal) % 10
		n, err := w.WriteString(decimalDigits[digit : digit+1])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// WriteHex writes the given integer as hex to a writer
// without allocating strings.
//
//go:nosplit
func WriteHex[T io.StringWriter](w T, val uint64) (int, error) {
	const hexDigits = "0123456789abcdef"
	if val == 0 {
		return w.WriteString(hexDigits[0:1])
	}
	var written int
	hex := uint64(16)
	for ; val/hex != 0; hex <<= 4 {
	}
	for hex >>= 4; hex > 0; hex >>= 4 {
		digit := (val / hex) % 16
		n, err := w.WriteString(hexDigits[digit : digit+1])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeNumberTo writes the number to the given writer.
// This only causes heap allocations when the number is a non-zero, non-special float.
func writeNumberTo[T io.StringWriter](w T, n *Number) error {
	var s string
	switch {
	// Zero case:
	case n.Int == 0 && n.Float == 0:
		s = "0"

	// Integer case:
	case n.Int != 0:
		_, err := WriteInteger(w, n.Int)
		return err

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
	_, err := w.WriteString(s)
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
	// Min is the minimum sample ever recorded in this histogram.
	Min Number `json:"min"`
	// Max is the maximum sample ever recorded in this histogram.
	Max Number `json:"max"`
	// SumOfSquaredDeviations is the number of squared deviations of all samples.
	SumOfSquaredDeviations Number `json:"ssd"`
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

	// ExternalLabels are more labels merged together with `Labels`.
	// They can be set using SetExternalLabels.
	// They are useful in the case where a single Data needs labels from two sources:
	// labels specific to this data point (which should be in `Labels`), and labels
	// that are shared between multiple data points (stored in `ExternalLabels`).
	// This avoids allocating unique `Labels` maps for each Data struct, when
	// most of the actual labels would be shared between them.
	ExternalLabels map[string]string `json:"external_labels,omitempty"`

	// At most one of the fields below may be set.
	// Which one depends on the type of the metric.

	// Number is used for all numerical types.
	Number *Number `json:"val,omitempty"`

	// Histogram is used for histogram-typed metrics.
	HistogramValue *Histogram `json:"histogram,omitempty"`
}

// NewIntData returns a new Data struct with the given metric and value.
func NewIntData(metric *Metric, val int64) *Data {
	return LabeledIntData(metric, nil, val)
}

// LabeledIntData returns a new Data struct with the given metric, labels, and value.
func LabeledIntData(metric *Metric, labels map[string]string, val int64) *Data {
	return &Data{Metric: metric, Labels: labels, Number: NewInt(val)}
}

// NewFloatData returns a new Data struct with the given metric and value.
func NewFloatData(metric *Metric, val float64) *Data {
	return LabeledFloatData(metric, nil, val)
}

// LabeledFloatData returns a new Data struct with the given metric, labels, and value.
func LabeledFloatData(metric *Metric, labels map[string]string, val float64) *Data {
	return &Data{Metric: metric, Labels: labels, Number: NewFloat(val)}
}

// SetExternalLabels sets d.ExternalLabels. See its docstring for more information.
// Returns `d` for chainability.
func (d *Data) SetExternalLabels(externalLabels map[string]string) *Data {
	d.ExternalLabels = externalLabels
	return d
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

// writeEscapedString writes the given string in quotation marks and with some characters escaped,
// per Prometheus spec. It does this without string allocations.
// If `quoted` is true, quote characters will surround the string, and quote characters within `s`
// will also be escaped.
func writeEscapedString[T io.StringWriter](w T, s string, quoted bool) (int, error) {
	const (
		quote            = '"'
		backslash        = '\\'
		newline          = '\n'
		quoteStr         = `"`
		escapedQuote     = `\\"`
		escapedBackslash = "\\\\"
		escapedNewline   = "\\\n"
	)
	written := 0
	var n int
	var err error
	if quoted {
		n, err = w.WriteString(quoteStr)
		written += n
		if err != nil {
			return written, err
		}
	}
	for _, r := range s {
		switch r {
		case quote:
			if quoted {
				n, err = w.WriteString(escapedQuote)
			} else {
				n, err = w.WriteString(quoteStr)
			}
		case backslash:
			n, err = w.WriteString(escapedBackslash)
		case newline:
			n, err = w.WriteString(escapedNewline)
		default:
			n, err = w.WriteString(string(r))
		}
		written += n
		if err != nil {
			return written, err
		}
	}
	if quoted {
		n, err = w.WriteString(quoteStr)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeMetricPreambleTo writes the metric name to the writer. It may also
// write unwritten help and type comments of the metric if they haven't been
// written to the writer yet.
func writeMetricPreambleTo[T io.StringWriter](w T, d *Data, options SnapshotExportOptions, metricsWritten map[string]bool) error {
	// Metric header, if we haven't printed it yet.
	if !metricsWritten[d.Metric.Name] {
		// Extra newline before each preamble for aesthetic reasons.
		if _, err := w.WriteString("\n"); err != nil {
			return err
		}
		if err := writeMetricHeaderTo(w, d.Metric, options); err != nil {
			return err
		}
		metricsWritten[d.Metric.Name] = true
	}

	// Metric name.
	if options.ExporterPrefix != "" {
		if _, err := w.WriteString(options.ExporterPrefix); err != nil {
			return err
		}
	}
	if _, err := w.WriteString(d.Metric.Name); err != nil {
		return err
	}
	return nil
}

// keyVal is a key-value pair used in the function below.
type keyVal struct{ Key, Value string }

// sortedIterateLabels iterates through labels and outputs them to `out` in sorted key order,
// or stops when cancelCh is written to. It runs in O(n^2) time but makes no heap allocations.
func sortedIterateLabels(labels map[string]string, out chan<- keyVal, cancelCh <-chan struct{}) {
	defer close(out)
	if len(labels) == 0 {
		return
	}

	// smallestKey is the smallest key that we've already sent to `out`.
	// It starts as the empty string, which means we haven't sent anything to `out` yet.
	smallestKey := ""
	// Find the smallest key of the whole set and send it out.
	for k := range labels {
		if smallestKey == "" || k < smallestKey {
			smallestKey = k
		}
	}
	select {
	case out <- keyVal{smallestKey, labels[smallestKey]}:
	case <-cancelCh:
		return
	}

	// Iterate until we've sent as many items as we have as input to the output channel.
	// We start at 1 because the loop above already sent out the smallest key to `out`.
	for numOutput := 1; numOutput < len(labels); numOutput++ {
		// nextSmallestKey is the smallest key that is strictly larger than `smallestKey`.
		nextSmallestKey := ""
		for k := range labels {
			if k > smallestKey && (nextSmallestKey == "" || k < nextSmallestKey) {
				nextSmallestKey = k
			}
		}

		// Update smallestKey and send it out.
		smallestKey = nextSmallestKey
		select {
		case out <- keyVal{smallestKey, labels[smallestKey]}:
		case <-cancelCh:
			return
		}
	}
}

// LabelOrError is used in OrderedLabels.
// It represents either a key-value pair, or an error.
type LabelOrError struct {
	Key, Value string
	Error      error
}

// OrderedLabels streams the list of 'label_key="label_value"' in sorted order, except "le" which is
// a reserved Prometheus label name and should go last.
// If an error is encountered, it is returned as the Error field of LabelOrError, and no further
// messages will be sent on the channel.
func OrderedLabels(labels ...map[string]string) <-chan LabelOrError {
	// This function is quite hot on the metric-rendering path, and its naive "just put all the
	// strings in one map to ensure no dupes it, then in one slice and sort it" approach is very
	// allocation-heavy. This approach is more computation-heavy (it runs in
	// O(len(labels) * len(largest label map))), but the only heap allocations it does is for the
	// following tiny slices and channels. In practice, the number of label maps and the size of
	// each label map is tiny, so this is worth doing despite the theoretically-longer run time.

	// Initialize the channels we'll use.
	mapChannels := make([]chan keyVal, 0, len(labels))
	lastKeyVal := make([]keyVal, len(labels))
	resultCh := make(chan LabelOrError)
	var cancelCh chan struct{}
	// outputError is a helper function for when we have encountered an error mid-way.
	outputError := func(err error) {
		if cancelCh != nil {
			for range mapChannels {
				cancelCh <- struct{}{}
			}
			close(cancelCh)
		}
		resultCh <- LabelOrError{Error: err}
		close(resultCh)
	}

	// Verify that no label is the empty string. It's not a valid label name,
	// and we use the empty string later on in the function as a marker of having
	// finished processing all labels from a given label map.
	for _, labelMap := range labels {
		for label := range labelMap {
			if label == "" {
				go outputError(errors.New("got empty-string label"))
				return resultCh
			}
		}
	}

	// Each label map is processed in its own goroutine,
	// which will stream it back to this function in sorted order.
	cancelCh = make(chan struct{}, len(labels))
	for _, labelMap := range labels {
		ch := make(chan keyVal)
		mapChannels = append(mapChannels, ch)
		go sortedIterateLabels(labelMap, ch, cancelCh)
	}

	// This goroutine is the meat of this function; it iterates through
	// the results being streamed from each `sortedIterateLabels` goroutine
	// that we spawned earlier, until all of them are exhausted or until we
	// hit an error.
	go func() {
		// The "le" label is special and goes last, not in sorted order.
		// gotLe is the empty string if there is no "le" label,
		// otherwise it's the value of the "le" label.
		var gotLe string

		// numChannelsLeft tracks the number of channels that are still live.
		for numChannelsLeft := len(mapChannels); numChannelsLeft > 0; {
			// Iterate over all channels and ensure we have the freshest (smallest)
			// label from each of them.
			for i, ch := range mapChannels {
				// A nil channel is one that has been closed.
				if ch == nil {
					continue
				}
				// If we already have the latest value from this channel,
				// keep it there instead of getting a new one,
				if lastKeyVal[i].Key != "" {
					continue
				}
				// Otherwise, get a new label.
				kv, open := <-ch
				if !open {
					// Channel has been closed, no more to read from this one.
					numChannelsLeft--
					mapChannels[i] = nil
					continue
				}
				if kv.Key == "le" {
					if gotLe != "" {
						outputError(errors.New("got duplicate 'le' label"))
						return
					}
					gotLe = kv.Value
					continue
				}
				lastKeyVal[i] = kv
			}

			// We have one key-value pair from each still-active channel now.
			// Find the smallest one between them.
			smallestKey := ""
			indexForSmallest := -1
			for i, kv := range lastKeyVal {
				if kv.Key == "" {
					continue
				}
				if smallestKey == "" || kv.Key < smallestKey {
					smallestKey = kv.Key
					indexForSmallest = i
				} else if kv.Key == smallestKey {
					outputError(fmt.Errorf("got duplicate label %q", smallestKey))
					return
				}
			}

			if indexForSmallest == -1 {
				// There are no more key-value pairs to output. We're done.
				break
			}

			// Output the smallest key-value pairs out of all the channels.
			resultCh <- LabelOrError{
				Key:   smallestKey,
				Value: lastKeyVal[indexForSmallest].Value,
			}
			// Mark the last key-value pair from the channel that gave us the
			// smallest key-value pair as no longer present, so that we get a new
			// key-value pair from it in the next iteration.
			lastKeyVal[indexForSmallest] = keyVal{}
		}

		// Output the "le" label last.
		if gotLe != "" {
			resultCh <- LabelOrError{
				Key:   "le",
				Value: gotLe,
			}
		}
		close(resultCh)
		close(cancelCh)
	}()

	return resultCh
}

// writeLabelsTo writes a set of metric labels.
func writeLabelsTo[T io.StringWriter](w T, d *Data, extraLabels map[string]string, leLabel *Number) error {
	if len(d.Labels)+len(d.ExternalLabels)+len(extraLabels) != 0 || leLabel != nil {
		if _, err := w.WriteString("{"); err != nil {
			return err
		}
		var orderedLabels <-chan LabelOrError
		if leLabel != nil {
			orderedLabels = OrderedLabels(d.Labels, d.ExternalLabels, extraLabels, map[string]string{"le": leLabel.String()})
		} else {
			orderedLabels = OrderedLabels(d.Labels, d.ExternalLabels, extraLabels)
		}
		firstLabel := true
		var foundError error
		for labelOrError := range orderedLabels {
			if foundError != nil {
				continue
			}
			if labelOrError.Error != nil {
				foundError = labelOrError.Error
				continue
			}
			if !firstLabel {
				if _, err := w.WriteString(","); err != nil {
					return err
				}
			}
			firstLabel = false
			if _, err := w.WriteString(labelOrError.Key); err != nil {
				return err
			}
			if _, err := w.WriteString("="); err != nil {
				return err
			}
			if _, err := writeEscapedString(w, labelOrError.Value, true); err != nil {
				return err
			}
		}
		if foundError != nil {
			return foundError
		}
		if _, err := w.WriteString("}"); err != nil {
			return err
		}
	}
	return nil
}

// writeMetricLine writes a single Data line with a single number (val) to w.
func writeMetricLine[T io.StringWriter](w T, d *Data, metricSuffix string, val *Number, when time.Time, options SnapshotExportOptions, leLabel *Number, metricsWritten map[string]bool) error {
	if err := writeMetricPreambleTo(w, d, options, metricsWritten); err != nil {
		return err
	}
	if metricSuffix != "" {
		if _, err := w.WriteString(metricSuffix); err != nil {
			return err
		}
	}
	if err := writeLabelsTo(w, d, options.ExtraLabels, leLabel); err != nil {
		return err
	}
	if _, err := w.WriteString(" "); err != nil {
		return err
	}
	if err := writeNumberTo(w, val); err != nil {
		return err
	}
	if _, err := w.WriteString(" "); err != nil {
		return err
	}
	if _, err := WriteInteger(w, when.UnixMilli()); err != nil {
		return err
	}
	if _, err := w.WriteString("\n"); err != nil {
		return err
	}
	return nil
}

// writeDataTo writes the Data to the given writer in Prometheus format.
func writeDataTo[T io.StringWriter](w T, d *Data, when time.Time, options SnapshotExportOptions, metricsWritten map[string]bool) error {
	switch d.Metric.Type {
	case TypeUntyped, TypeGauge, TypeCounter:
		return writeMetricLine(w, d, "", d.Number, when, options, nil, metricsWritten)
	case TypeHistogram:
		// Write an empty line before and after histograms to easily distinguish them from
		// other metric lines.
		if _, err := w.WriteString("\n"); err != nil {
			return err
		}
		var numSamples uint64
		var samples Number
		for _, bucket := range d.HistogramValue.Buckets {
			numSamples += bucket.Samples
			samples.Int = int64(numSamples) // Prometheus distribution bucket counts are cumulative.
			if err := writeMetricLine(w, d, "_bucket", &samples, when, options, &bucket.UpperBound, metricsWritten); err != nil {
				return err
			}
		}
		if err := writeMetricLine(w, d, "_sum", &d.HistogramValue.Total, when, options, nil, metricsWritten); err != nil {
			return err
		}
		samples.Int = int64(numSamples)
		if err := writeMetricLine(w, d, "_count", &samples, when, options, nil, metricsWritten); err != nil {
			return err
		}
		if err := writeMetricLine(w, d, "_min", &d.HistogramValue.Min, when, options, nil, metricsWritten); err != nil {
			return err
		}
		if err := writeMetricLine(w, d, "_max", &d.HistogramValue.Max, when, options, nil, metricsWritten); err != nil {
			return err
		}
		if err := writeMetricLine(w, d, "_ssd", &d.HistogramValue.SumOfSquaredDeviations, when, options, nil, metricsWritten); err != nil {
			return err
		}
		// Empty line after the histogram.
		if _, err := w.WriteString("\n"); err != nil {
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

const counterWriterBufSize = 32768

// countingWriter implements io.StringWriter, and counts the number of bytes
// written to it.
// Useful in this file to keep track of total number of bytes without having
// to plumb this everywhere in the writeX() functions in this file.
type countingWriter[T io.StringWriter] struct {
	buf        *bytes.Buffer
	underlying T
	written    int
}

// WriteString implements io.StringWriter.WriteString.
// This avoids going into the slow, allocation-heavy path of io.WriteString.
func (w *countingWriter[T]) WriteString(s string) (int, error) {
	written, err := w.buf.WriteString(s)
	w.written += written
	if w.buf.Len() >= counterWriterBufSize {
		w.Flush()
	}
	return written, err
}

func (w *countingWriter[T]) Flush() error {
	if w.buf.Len() > 0 {
		_, err := w.underlying.WriteString(w.buf.String())
		w.buf.Reset()
		return err
	}
	return nil
}

// Written returns the number of bytes written to the underlying writer (minus buffered writes).
func (w *countingWriter[T]) Written() int {
	return w.written - w.buf.Len()
}

// writeSnapshotSingleMetric writes a single metric data from a snapshot to
// the given writer in Prometheus format.
// It returns the number of bytes written.
func writeSnapshotSingleMetric[T io.StringWriter](w T, s *Snapshot, options SnapshotExportOptions, metricName string, metricsWritten map[string]bool) error {
	if !strings.HasPrefix(metricName, options.ExporterPrefix) {
		return nil
	}
	wantMetricName := strings.TrimPrefix(metricName, options.ExporterPrefix)
	for _, d := range s.Data {
		if d.Metric.Name != wantMetricName {
			continue
		}
		if err := writeDataTo(w, d, s.When, options, metricsWritten); err != nil {
			return err
		}
	}
	return nil
}

// ReusableWriter is a writer that can be reused to efficiently write
// successive snapshots.
type ReusableWriter[T io.StringWriter] struct {
	// buf is the reusable buffer used for buffering writes.
	// It is reset after each write, but keeps the underlying byte buffer,
	// avoiding allocations on successive snapshot writes.
	buf bytes.Buffer
}

// Write writes one or more snapshots to the writer.
// This method may not be used concurrently for the same `ReusableWriter`.
func (rw *ReusableWriter[T]) Write(w T, options ExportOptions, snapshotsToOptions map[*Snapshot]SnapshotExportOptions) (int, error) {
	rw.buf.Reset()
	cw := &countingWriter[T]{
		buf:        &rw.buf,
		underlying: w,
	}
	return write(cw, options, snapshotsToOptions)
}

// Write writes one or more snapshots to the writer.
// This ensures same-name metrics across different snapshots are printed together, per spec.
// If the caller will call `Write` successively for multiple snapshots, it is more efficient
// to use the `ReusableWriter` type instead of this function.
func Write[T io.StringWriter](w T, options ExportOptions, snapshotsToOptions map[*Snapshot]SnapshotExportOptions) (int, error) {
	var b bytes.Buffer
	// Sane default buffer size.
	b.Grow(counterWriterBufSize)
	cw := &countingWriter[T]{
		buf:        &b,
		underlying: w,
	}
	return write(cw, options, snapshotsToOptions)
}

func write[T io.StringWriter](cw *countingWriter[T], options ExportOptions, snapshotsToOptions map[*Snapshot]SnapshotExportOptions) (int, error) {
	if len(snapshotsToOptions) == 0 {
		return 0, nil
	}
	if options.CommentHeader != "" {
		for _, commentLine := range strings.Split(options.CommentHeader, "\n") {
			if _, err := cw.WriteString("# "); err != nil {
				return cw.Written(), err
			}
			if _, err := cw.WriteString(commentLine); err != nil {
				return cw.Written(), err
			}
			if _, err := cw.WriteString("\n"); err != nil {
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
		if _, err := cw.WriteString(fmt.Sprintf("# Writing data from snapshot containing %d data points taken at %v.\n", len(snapshots[0].Data), snapshots[0].When)); err != nil {
			return cw.Written(), err
		}
	default: // Multi-snapshot case.
		// Provide a consistent ordering of snapshots.
		sort.Slice(snapshots, func(i, j int) bool {
			return reflect.ValueOf(snapshots[i]).Pointer() < reflect.ValueOf(snapshots[j]).Pointer()
		})
		if _, err := cw.WriteString(fmt.Sprintf("# Writing data from %d snapshots:\n", len(snapshots))); err != nil {
			return cw.Written(), err
		}
		for _, snapshot := range snapshots {
			if _, err := cw.WriteString(fmt.Sprintf("#   - Snapshot with %d data points taken at %v: %v\n", len(snapshot.Data), snapshot.When, snapshotsToOptions[snapshot].ExtraLabels)); err != nil {
				return cw.Written(), err
			}
		}
	}
	if _, err := cw.WriteString("\n"); err != nil {
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
			writeSnapshotSingleMetric(cw, snapshot, snapshotsToOptions[snapshot], metricName, options.MetricsWritten)
		}
	}
	if _, err := cw.WriteString("\n# End of metric data.\n"); err != nil {
		return cw.Written(), err
	}
	if err := cw.Flush(); err != nil {
		return cw.Written(), err
	}
	return cw.Written(), nil
}
