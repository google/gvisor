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

package metric

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/prometheus"
)

const (
	// snapshotBufferSize is the number of snapshots within one item of the
	// ringbuffer. Increasing this number means less context-switching
	// overhead between collector and writer goroutines, but worse time
	// precision, as the precise time is refreshed every this many snapshots.
	snapshotBufferSize = 1024
	// snapshotRingbufferSize is the number of items in the ringbuffer.
	// Increasing this number means the writer has more slack to catch up
	// if it falls behind, but it also means that the collector may need
	// to wait for longer intervals when the writer does fall behind,
	// adding more variance to the time gaps between collections.
	snapshotRingbufferSize = 128
	// MetricsPrefix is prepended before every metrics line.
	MetricsPrefix = "GVISOR_METRICS\t"
	// MetricsHashIndicator is prepended before the hash of the metrics
	// data at the end of the metrics stream.
	MetricsHashIndicator = "ADLER32\t"
	// TimeColumn is the column header for the time column.
	TimeColumn = "Time (ns)"
	// MetricsMetaIndicator is prepended before every metrics metadata line
	// after metricsPrefix.
	MetricsMetaIndicator = "META\t"
	// MetricsStartTimeIndicator is prepended before the start time of the
	// metrics collection.
	MetricsStartTimeIndicator = "START_TIME\t"
)

var (
	// profilingMetricsStarted indicates whether StartProfilingMetrics has
	// been called.
	profilingMetricsStarted atomicbitops.Bool
	// stopProfilingMetrics is used to signal to the profiling metrics
	// goroutine to stop recording and writing metrics.
	stopProfilingMetrics atomicbitops.Bool
	// doneProfilingMetrics is used to signal that the profiling metrics
	// goroutines are finished.
	doneProfilingMetrics chan bool
	// definedProfilingMetrics is the set of metrics known to be created for
	// profiling (see condmetric_profiling.go).
	definedProfilingMetrics []string
)

// snapshots is used to as temporary storage of metric data
// before it's written to the writer.
type snapshots struct {
	numMetrics int
	// startTime is the time at which collection started in nanoseconds.
	startTime int64
	// ringbuffer is used to store metric data.
	ringbuffer [][]uint64
	// curWriterIndex is the ringbuffer index currently being read by the
	// writer. It should not be used by the collector.
	curWriterIndex atomicbitops.Int32
}

// writeReq is the message sent between from the collector to the writer.
type writeReq struct {
	ringbufferIdx int
	// numLines indicates how many data lines are filled in the buffer.
	numLines int
}

// ProfilingMetricsWriter is the interface for profiling metrics sinks.
type ProfilingMetricsWriter interface {
	// WriteString from the io.StringWriter interface.
	io.StringWriter

	// Close closes the writer.
	Close() error
}

// ProfilingMetricsOptions is the set of options to profile metrics.
type ProfilingMetricsOptions[T ProfilingMetricsWriter] struct {
	// Sink is the sink to write the profiling metrics data to.
	Sink T

	// Lossy specifies whether the sink is lossy, i.e. data may be dropped from
	// too large logging volume. In this case, data integrity is desirable at the
	// expense of extra CPU cost at data-writing time. The data will be prefixed
	// with `MetricsPrefix` and the hash of the data will be appended at the end.
	Lossy bool

	// Metrics is the comma-separated list of metrics to profile.
	Metrics string

	// Rate is the rate at which the metrics are collected.
	Rate time.Duration
}

// StartProfilingMetrics checks the ProfilingMetrics runsc flags and creates
// goroutines responsible for outputting the profiling metric data.
//
// Preconditions:
//   - All metrics are registered.
//   - Initialize/Disable has been called.
func StartProfilingMetrics[T ProfilingMetricsWriter](opts ProfilingMetricsOptions[T]) error {
	if !initialized.Load() {
		// Wait for initialization to complete to make sure that all
		// metrics are registered.
		return errors.New("metric initialization is not complete")
	}

	var values []func(fieldValues ...*FieldValue) uint64
	var headers []string
	var columnHeaders strings.Builder
	columnHeaders.WriteString(TimeColumn)
	numMetrics := 0

	if len(opts.Metrics) > 0 {
		metrics := strings.Split(opts.Metrics, ",")
		numMetrics = len(metrics)

		for _, name := range metrics {
			name := strings.TrimSpace(name)
			m, ok := allMetrics.uint64Metrics[name]
			if !ok {
				return fmt.Errorf("given profiling metric name '%s' does not correspond to a registered Uint64 metric", name)
			}
			if len(m.fields) > 0 {
				// TODO(b/240280155): Add support for field values.
				return fmt.Errorf("will not profile metric '%s' because it has metric fields which are not supported", name)
			}
			var metricMetadataHeader strings.Builder
			metricMetadataHeader.WriteString(MetricsMetaIndicator)
			metricMetadataHeader.WriteString(name)
			metricMetadataHeader.WriteRune('\t')
			metricMetadata, err := protojson.MarshalOptions{Multiline: false}.Marshal(m.metadata)
			if err != nil {
				return fmt.Errorf("failed to marshal metric schema for metric %q: %w", name, err)
			}
			metricMetadataHeader.Write(metricMetadata)
			headers = append(headers, metricMetadataHeader.String())
			columnHeaders.WriteRune('\t')
			columnHeaders.WriteString(name)
			values = append(values, m.value)
		}
		if opts.Lossy {
			columnHeaders.WriteString("\tChecksum")
		}
	} else {
		if len(definedProfilingMetrics) > 0 {
			return fmt.Errorf("a value for --profiling-metrics was not specified; consider using a subset of '--profiling-metrics=%s'", strings.Join(definedProfilingMetrics, ","))
		}
		return fmt.Errorf("a value for --profiling-metrics was not specified; also no conditionally compiled metrics found, consider compiling runsc with --go_tag=condmetric_profiling")
	}
	headers = append(
		headers,
		fmt.Sprintf("%s%d", MetricsStartTimeIndicator, time.Now().UnixNano()),
		columnHeaders.String(),
	)

	if !profilingMetricsStarted.CompareAndSwap(false, true) {
		return errors.New("profiling metrics have already been started")
	}
	s := snapshots{
		numMetrics: numMetrics,
		ringbuffer: make([][]uint64, snapshotRingbufferSize),
		// curWriterIndex is initialized to a valid index so that the
		// collector cannot use up all indices before the writer even has
		// a chance to start (as unlikely as that is).
		curWriterIndex: atomicbitops.FromInt32(snapshotRingbufferSize - 1),
	}
	for i := 0; i < snapshotRingbufferSize; i++ {
		s.ringbuffer[i] = make([]uint64, snapshotBufferSize*(numMetrics+1))
	}

	stopProfilingMetrics = atomicbitops.FromBool(false)
	doneProfilingMetrics = make(chan bool, 1)
	writeCh := make(chan writeReq, snapshotRingbufferSize)
	s.startTime = time.Now().UnixNano()
	cheapStartTime := CheapNowNano()
	go collectProfilingMetrics(&s, values, cheapStartTime, opts.Rate, writeCh)
	if opts.Lossy {
		lossySink := newLossyBufferedWriter(opts.Sink)
		go writeProfilingMetrics[*lossyBufferedWriter[T]](lossySink, &s, headers, writeCh)
	} else {
		bufferedSink := newBufferedWriter(opts.Sink)
		go writeProfilingMetrics[*bufferedWriter[T]](bufferedSink, &s, headers, writeCh)
	}
	log.Infof("Profiling metrics started.")

	return nil
}

// collectProfilingMetrics will send metrics to the writeCh until it receives a
// signal via the stopProfilingMetrics channel.
func collectProfilingMetrics(s *snapshots, values []func(fieldValues ...*FieldValue) uint64, cheapStartTime int64, profilingRate time.Duration, writeCh chan<- writeReq) {
	defer close(writeCh)

	numEntries := s.numMetrics + 1 // to account for the timestamp
	ringbufferIdx := 0
	curSnapshot := 0

	// If we write faster than the writer can keep up, we back off.
	// The backoff factor starts small but increases exponentially
	// each time we find that we are still faster than the writer.
	const (
		// How much slower than the profiling rate we sleep for, as a
		// multiplier for the profiling rate.
		initialBackoffFactor = 1.0

		// The exponential factor by which the backoff factor increases.
		backoffFactorGrowth = 1.125

		// The maximum backoff factor, i.e. the maximum multiplier of
		// the profiling rate for which we sleep.
		backoffFactorMax = 256.0
	)
	backoffFactor := initialBackoffFactor

	// To keep track of time cheaply, we use `CheapNowNano`.
	// However, this can drift as it has poor precision.
	// To get something more precise, we periodically call `time.Now`
	// and `CheapNowNano` and use these two variables to track both.
	// This way, we can compute a more precise time by using
	// `CheapNowNano() - cheapTime + preciseTime`.
	preciseTime := s.startTime
	cheapTime := cheapStartTime

	stopCollecting := false
	for nextCollection := s.startTime; !stopCollecting; nextCollection += profilingRate.Nanoseconds() {

		// For small durations, just spin. Otherwise sleep.
		for {
			const (
				wakeUpNanos   = 10
				spinMaxNanos  = 250
				yieldMaxNanos = 1_000
			)
			now := CheapNowNano() - cheapTime + preciseTime
			nanosToNextCollection := nextCollection - now
			if nanosToNextCollection <= 0 {
				// Collect now.
				break
			}
			if nanosToNextCollection < spinMaxNanos {
				continue // Spin.
			}
			if nanosToNextCollection < yieldMaxNanos {
				// Yield then spin.
				runtime.Gosched()
				continue
			}
			// Sleep.
			time.Sleep(time.Duration(nanosToNextCollection-wakeUpNanos) * time.Nanosecond)
		}

		if stopProfilingMetrics.Load() {
			stopCollecting = true
			// Collect one last time before stopping.
		}

		collectStart := CheapNowNano() - cheapTime + preciseTime
		timestamp := time.Duration(collectStart - s.startTime)
		base := curSnapshot * numEntries
		ringBuf := s.ringbuffer[ringbufferIdx]
		ringBuf[base] = uint64(timestamp)
		for i := 1; i < numEntries; i++ {
			ringBuf[base+i] = values[i-1]()
		}
		curSnapshot++

		if curSnapshot == snapshotBufferSize {
			writeCh <- writeReq{ringbufferIdx: ringbufferIdx, numLines: curSnapshot}
			curSnapshot = 0
			// Block until the writer indicates that this part of the ringbuffer
			// is available for writing.
			for ringbufferIdx = (ringbufferIdx + 1) % snapshotRingbufferSize; ringbufferIdx == int(s.curWriterIndex.Load()); {
				// Going too fast, stop collecting for a bit.
				backoffSleep := profilingRate * time.Duration(backoffFactor)
				log.Warningf("Profiling metrics collector exhausted the entire ringbuffer... backing off for %v to let writer catch up.", backoffSleep)
				time.Sleep(backoffSleep)
				backoffFactor = min(backoffFactor*backoffFactorGrowth, backoffFactorMax)
			}
			// Refresh precise time.
			preciseTime = time.Now().UnixNano()
			cheapTime = CheapNowNano()
		}
	}
	if curSnapshot != 0 {
		writeCh <- writeReq{ringbufferIdx: ringbufferIdx, numLines: curSnapshot}
	}
}

// bufferedMetricsWriter is a ProfilingMetricsWriter that buffers data
// before writing it to some underlying writer.
type bufferedMetricsWriter interface {
	// We inherit from the ProfilingMetricsWriter interface.
	// Note however that calls to WriteString should *not* contain any
	// newline character, unless called through NewLine.
	ProfilingMetricsWriter

	// NewLine writes a newline character to the buffer.
	// The writer may decide to flush the buffer at this point.
	NewLine()

	// Flush flushes the buffer to the underlying writer.
	Flush()
}

const (
	// Buffer size reasonable to use for a single line of metric data.
	lineBufSize = 4 * 1024 // 4 KiB

	// Buffer size for a buffered write to an underlying sink.
	bufSize = 984 * 1024 // 984 KiB

	// Number of lines to buffer before flushing to the underlying sink
	// by a line-buffered writer.
	bufferedLines = bufSize / lineBufSize
)

// bufferedWriter is a buffered metrics writer that wraps an underlying
// ProfilingMetricsWriter.
// It implements `bufferedMetricsWriter`.
type bufferedWriter[T ProfilingMetricsWriter] struct {
	buf        bytes.Buffer
	underlying T
}

func newBufferedWriter[T ProfilingMetricsWriter](underlying T) *bufferedWriter[T] {
	w := &bufferedWriter[T]{underlying: underlying}
	w.buf.Grow(bufSize + lineBufSize)
	return w
}

// WriteString implements bufferedMetricsWriter.WriteString.
func (w *bufferedWriter[T]) WriteString(s string) (int, error) {
	return w.buf.WriteString(s)
}

// NewLine implements bufferedMetricsWriter.NewLine.
func (w *bufferedWriter[T]) NewLine() {
	w.buf.WriteString("\n")
	if w.buf.Len() >= bufSize {
		w.Flush()
	}
}

// Flush implements bufferedMetricsWriter.Flush.
func (w *bufferedWriter[T]) Flush() {
	w.underlying.WriteString(w.buf.String())
	w.buf.Reset()
}

// Close implements bufferedMetricsWriter.Close.
func (w *bufferedWriter[T]) Close() error {
	w.Flush()
	return w.underlying.Close()
}

// lossyBufferedWriter writes to an underlying ProfilingMetricsWriter
// and buffers data on a per-line basis. It adds a prefix to every line,
// and keeps track of the checksum of the data it has written (which is then
// also written to the underlying writer on `Close()`).
// The checksum covers all of the per-line data written after the line prefix,
// including the newline character of these lines, with the exception of
// the checksum data line itself.
// All lines are also checksummed individually, with the checksum covering
// the contents of the line after the line prefix but before the tab and
// line checksum itself at the end of the line.
// `lossyBufferedWriter` implements `bufferedMetricsWriter`.
type lossyBufferedWriter[T ProfilingMetricsWriter] struct {
	lineBuf       bytes.Buffer
	flushBuf      bytes.Buffer
	lineHasher    hash.Hash32
	overallHasher hash.Hash32
	lines         int
	longestLine   int
	underlying    T
}

// newLossyBufferedWriter creates a new lossyBufferedWriter.
func newLossyBufferedWriter[T ProfilingMetricsWriter](underlying T) *lossyBufferedWriter[T] {
	w := &lossyBufferedWriter[T]{
		underlying:    underlying,
		lineHasher:    adler32.New(),
		overallHasher: adler32.New(),
		longestLine:   lineBufSize,
	}
	w.lineBuf.Grow(lineBufSize)

	// `lineBufSize + 1` to account for the newline at the end of each line.
	// `+ 2` to account for the newline at the beginning and end of each flush.
	w.flushBuf.Grow((lineBufSize+1)*bufferedLines + 2)

	w.flushBuf.WriteString("\n")
	return w
}

// WriteString implements bufferedMetricsWriter.WriteString.
func (w *lossyBufferedWriter[T]) WriteString(s string) (int, error) {
	return w.lineBuf.WriteString(s)
}

// Flush implements bufferedMetricsWriter.Flush.
func (w *lossyBufferedWriter[T]) Flush() {
	if w.lines > 0 {
		// Ensure that we write a complete line atomically, as this
		// may get parsed while being mixed with other logs that may not
		// have clean line endings a the time we print this.
		w.flushBuf.WriteString("\n")
		w.underlying.WriteString(w.flushBuf.String())
		if f, isFile := any(w.underlying).(*os.File); isFile {
			// If we're dealing with a file, also call `sync(2)`.
			f.Sync()
		}
		w.flushBuf.Reset()
		w.flushBuf.WriteString("\n")
		w.lines = 0
	}
}

// NewLine implements bufferedMetricsWriter.NewLine.
func (w *lossyBufferedWriter[T]) NewLine() {
	if lineLen := w.lineBuf.Len(); lineLen > w.longestLine {
		wantTotalSize := (lineLen+1)*bufferedLines + 2
		if growBy := wantTotalSize - w.flushBuf.Len(); growBy > 0 {
			w.flushBuf.Grow(growBy)
		}
		w.longestLine = lineLen
	}
	line := w.lineBuf.String()
	w.lineHasher.Reset()
	w.lineHasher.Write([]byte(line))
	lineHash := w.lineHasher.Sum32()
	w.lineBuf.Reset()
	w.flushBuf.WriteString(MetricsPrefix)
	beforeLineIndex := w.flushBuf.Len()
	w.flushBuf.WriteString(line)
	w.flushBuf.WriteString("\t0x")
	prometheus.WriteHex(&w.flushBuf, uint64(lineHash))
	w.flushBuf.WriteString("\n")
	afterLineIndex := w.flushBuf.Len()
	// We ignore the effects that partial writes on the underlying writer
	// would have on the hash computation here.
	// This is OK because the goal of this writer is speed over correctness,
	// and correctness is enforced by the reader of this data checking the
	// hash at the end.
	w.overallHasher.Write(w.flushBuf.Bytes()[beforeLineIndex:afterLineIndex])
	w.lineBuf.Reset()
	w.lines++
	if w.lines >= bufferedLines || w.flushBuf.Len() >= bufSize {
		w.Flush()
	}
}

// Close implements bufferedMetricsWriter.Close.
// It writes the checksum of the data written to the underlying writer.
func (w *lossyBufferedWriter[T]) Close() error {
	w.Flush()
	w.flushBuf.WriteString(MetricsPrefix)
	w.flushBuf.WriteString(MetricsHashIndicator)
	w.flushBuf.WriteString("0x")
	prometheus.WriteHex(&w.flushBuf, uint64(w.overallHasher.Sum32()))
	w.flushBuf.WriteString("\n")
	w.underlying.WriteString(w.flushBuf.String())
	w.overallHasher.Reset()
	w.lineBuf.Reset()
	w.flushBuf.Reset()
	return w.underlying.Close()
}

// writeProfilingMetrics will write to the ProfilingMetricsWriter on every
// request via writeReqs, until writeReqs is closed.
func writeProfilingMetrics[T bufferedMetricsWriter](sink T, s *snapshots, headers []string, writeReqs <-chan writeReq) {
	numEntries := s.numMetrics + 1
	for _, header := range headers {
		sink.WriteString(header)
		sink.NewLine()
	}
	for req := range writeReqs {
		s.curWriterIndex.Store(int32(req.ringbufferIdx))
		ringBuf := s.ringbuffer[req.ringbufferIdx]
		for i := 0; i < req.numLines; i++ {
			base := i * numEntries
			// Write the time
			prometheus.WriteInteger(sink, int64(ringBuf[base]))
			// Then everything else
			for j := 1; j < numEntries; j++ {
				sink.WriteString("\t")
				prometheus.WriteInteger(sink, int64(ringBuf[base+j]))
			}
			sink.NewLine()
		}
	}
	sink.Close()

	doneProfilingMetrics <- true
	close(doneProfilingMetrics)
	profilingMetricsStarted.Store(false)
}

// StopProfilingMetrics stops the profiling metrics goroutines. Call to make sure
// all metric data has been flushed.
// Note that calling this function prior to StartProfilingMetrics has no effect.
func StopProfilingMetrics() {
	if !profilingMetricsStarted.Load() {
		return
	}
	if stopProfilingMetrics.CompareAndSwap(false, true) {
		<-doneProfilingMetrics
	}
	// If the CAS fails, this means the signal was already sent,
	// so don't wait on doneProfilingMetrics.
}
