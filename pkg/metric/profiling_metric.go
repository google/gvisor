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
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/prometheus"
)

const (
	snapshotBufferSize     = 1000
	snapshotRingbufferSize = 16
)

var (
	// ProfilingMetricWriter is the output destination to which
	// ProfilingMetrics will be written to in TSV format.
	ProfilingMetricWriter *os.File
	// profilingMetricsStarted indicates whether StartProfilingMetrics has
	// been called.
	profilingMetricsStarted atomicbitops.Bool
	// stopProfilingMetrics is used to signal to the profiling metrics
	// goroutine to stop recording and writing metrics.
	stopProfilingMetrics chan bool
	// doneProfilingMetrics is used to signal that the profiling metrics
	// goroutines are finished.
	doneProfilingMetrics chan bool
	// definedProfilingMetrics is the set of metrics known to be created for
	// profiling (see condmetric_profiling.go).
	definedProfilingMetrics []string
)

// snapshots is used to as temporary storage of metric data
// before it's written to the ProfilingMetricWriter.
type snapshots struct {
	numMetrics int
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

// StartProfilingMetrics checks the ProfilingMetrics runsc flags and creates
// goroutines responsible for outputting the profiling metric data.
//
// Preconditions:
//   - All metrics are registered.
//   - Initialize/Disable has been called.
func StartProfilingMetrics(profilingMetrics string, profilingRate time.Duration) error {
	if !initialized.Load() {
		// Wait for initialization to complete to make sure that all
		// metrics are registered.
		return errors.New("metric initialization is not complete")
	}
	if ProfilingMetricWriter == nil {
		return errors.New("tried to initialize profiling metrics without log file")
	}

	var values []func(fieldValues ...*FieldValue) uint64
	header := strings.Builder{}
	header.WriteString("Time (ns)")
	numMetrics := 0

	if len(profilingMetrics) > 0 {
		metrics := strings.Split(profilingMetrics, ",")
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
			header.WriteRune('\t')
			header.WriteString(name)
			values = append(values, m.value)
		}

		header.WriteRune('\n')
	} else {
		if len(definedProfilingMetrics) > 0 {
			return fmt.Errorf("a value for --profiling-metrics was not specified; consider using a subset of '--profiling-metrics=%s'", strings.Join(definedProfilingMetrics, ","))
		}
		return fmt.Errorf("a value for --profiling-metrics was not specified; also no conditionally compiled metrics found, consider compiling runsc with --go_tag=condmetric_profiling")
	}

	if !profilingMetricsStarted.CompareAndSwap(0, 1) {
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

	stopProfilingMetrics = make(chan bool, 1)
	doneProfilingMetrics = make(chan bool, 1)
	writeCh := make(chan writeReq, snapshotRingbufferSize)
	go collectProfilingMetrics(&s, values, profilingRate, writeCh)
	go writeProfilingMetrics(&s, header.String(), writeCh)

	return nil
}

// collectProfilingMetrics will send metrics to the writeCh until it receives a
// signal via the stopProfilingMetrics channel.
func collectProfilingMetrics(s *snapshots, values []func(fieldValues ...*FieldValue) uint64, profilingRate time.Duration, writeCh chan<- writeReq) {
	defer close(writeCh)

	numEntries := s.numMetrics + 1 // to account for the timestamp
	ringbufferIdx := 0
	curSnapshot := 0
	startTime := CheapNowNano()
	// getNewRingbufferIdx will block until the writer indicates that some part
	// of the ringbuffer is available for writing.
	getNewRingbufferIdx := func() {
		for {
			nextIdx := (ringbufferIdx + 1) % snapshotRingbufferSize
			if nextIdx != int(s.curWriterIndex.Load()) {
				ringbufferIdx = nextIdx
				break
			}
			// Going too fast, stop collecting for a bit.
			log.Warningf("Profiling metrics collector exhausted the entire ringbuffer... backing off to let writer catch up.")
			time.Sleep(profilingRate * 100)
		}
	}

	stopCollecting := false
	for nextCollection := CheapNowNano() + profilingRate.Nanoseconds(); !stopCollecting; nextCollection += profilingRate.Nanoseconds() {
		now := CheapNowNano()
		if now < nextCollection {
			time.Sleep(time.Duration(nextCollection-now) * time.Nanosecond)
		} else {
			// Skip collection since we just did one anyway.
			continue
		}

		select {
		case <-stopProfilingMetrics:
			stopCollecting = true
			// Collect one last time before stopping.
		default:
		}

		collectStart := CheapNowNano()
		timestamp := time.Duration(collectStart - startTime)
		base := curSnapshot * numEntries
		s.ringbuffer[ringbufferIdx][base] = uint64(timestamp)
		for i := 1; i < numEntries; i++ {
			s.ringbuffer[ringbufferIdx][base+i] = values[i-1]()
		}
		curSnapshot++

		if curSnapshot == snapshotBufferSize {
			writeCh <- writeReq{ringbufferIdx: ringbufferIdx, numLines: curSnapshot}
			curSnapshot = 0
			getNewRingbufferIdx()
		}
	}
	if curSnapshot != 0 {
		writeCh <- writeReq{ringbufferIdx: ringbufferIdx, numLines: curSnapshot}
	}
}

// writeProfilingMetrics will write to the ProfilingMetricsWriter on every
// request via writeReqs, until writeReqs is closed.
func writeProfilingMetrics(s *snapshots, header string, writeReqs <-chan writeReq) {
	numEntries := s.numMetrics + 1

	out := bufio.NewWriter(ProfilingMetricWriter)
	out.WriteString(header)

	for req := range writeReqs {
		s.curWriterIndex.Store(int32(req.ringbufferIdx))

		for i := 0; i < req.numLines; i++ {
			base := i * numEntries
			// Write the time
			prometheus.WriteInteger(out, int64(s.ringbuffer[req.ringbufferIdx][base]))
			// Then everything else
			for j := 1; j < numEntries; j++ {
				out.WriteRune('\t')
				prometheus.WriteInteger(out, int64(s.ringbuffer[req.ringbufferIdx][base+j]))
			}
			out.WriteRune('\n')
		}
	}

	out.Flush()
	ProfilingMetricWriter.Close()
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

	select {
	case stopProfilingMetrics <- true:
		<-doneProfilingMetrics
	default: // Stop signal was already sent
	}
}
