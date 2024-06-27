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

package systrap

import (
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/metric"
)

// This file contains all logic related to context switch latency metrics.
//
// Latency metrics are the main method by which fastpath for both stub threads
// and the sentry is enabled and disabled. We measure latency in CPU cycles.
//
// The high level overview of metric collection looks like this:
//   1a) When a context is switched from the sentry to the stub, the sentry
//   records the time it was put into the context queue.
//   1b) When a stub thread picks up the context from the context queue, the stub
//   thread records the time when it's about to switch back to user code.
//   Getting the diff between these timestamps gives us the stub-bound latency.
//
//   2a) When a stub thread gives back a context to the sentry for handling,
//   it records the time just before notifying the sentry task goroutine.
//   2b) When the task goroutine sees that it has been notified, it records the
//   time.
//   Getting the diff between these timestamps gives us the sentry-bound latency.
//
//   3) Both latencies are recorded at once via recordLatency(). This means
//   there is a delay on getting stubBoundLatencies. In practice this should not
//   matter that much due to our relatively large latency measurement periods.
//
//   There is a bucket array for each latency type, where each bucket is of size
//   `bucketIncrements`. Latencies are collected in time periods of length
//   `recordingPeriod`, and  measurements for the current period are stored
//   in the `latencies` variable.

type latencyBuckets [numLatencyBuckets]atomicbitops.Uint64
type cpuTicks uint64

const (
	numLatencyBuckets = 80
	bucketIncrements  = 2048

	// minNecessaryRecordings defines the minimum amount of recordings we
	// want to see in latencyBuckets in order to get a reasonable median.
	minNecessaryRecordings = 5
)

// neverEnableFastPath is used for completely disabling the fast path.
// It is set once so doesn't need any synchronizations.
var neverEnableFastPath bool

// latencyRecorder is used to collect latency metrics.
type latencyRecorder struct {
	stubBound   latencyBuckets
	sentryBound latencyBuckets
}

// latencies stores the latency counts for the current measurement period.
var latencies latencyRecorder

// record increments the correct bucket assigned to the given latency l.
//
//go:nosplit
func (b *latencyBuckets) record(l cpuTicks) {
	bucket := l / bucketIncrements
	if bucket >= numLatencyBuckets {
		bucket = numLatencyBuckets - 1
	}
	b[bucket].Add(1)
}

// getMedian returns a latency measure in the range of
// [bucketIncrements, numLatencyBuckets * bucketIncrements], or 0 if unable to
// find a median in the latencyBuckets.
func (b *latencyBuckets) getMedian() cpuTicks {
	i := 0
	j := numLatencyBuckets - 1
	var totalForwards, totalBackwards uint64
	for i <= j {
		if totalForwards < totalBackwards {
			totalForwards += b[i].Load()
			i++
		} else {
			totalBackwards += b[j].Load()
			j--
		}
	}
	if totalForwards+totalBackwards < minNecessaryRecordings {
		return 0
	}
	return cpuTicks(max(uint64(i), 1) * bucketIncrements)
}

// merge combines two latencyBuckets instances.
func (b *latencyBuckets) merge(other *latencyBuckets) {
	for i := 0; i < numLatencyBuckets; i++ {
		b[i].Add(other[i].Load())
	}
}

// reset zeroes all buckets.
func (b *latencyBuckets) reset() {
	for i := 0; i < numLatencyBuckets; i++ {
		b[i].Store(0)
	}
}

// recordLatency records the latency of both the sentry->stub and the
// stub->sentry context switches.
// For the stub->sentry context switch, the final timestamp is taken by this
// function.
// Preconditions:
//   - ctx.isAcked() is true.
//
//go:nosplit
func (sc *sharedContext) recordLatency() {
	// Record stub->sentry latency.
	sentryBoundLatency := sc.getStateChangedTimeDiff()
	if sentryBoundLatency != 0 {
		latencies.sentryBound.record(sentryBoundLatency)
	}

	// Record sentry->stub latency.
	stubBoundLatency := sc.getAckedTimeDiff()
	if stubBoundLatency != 0 {
		latencies.stubBound.record(stubBoundLatency)
	}

	updateDebugMetrics(stubBoundLatency, sentryBoundLatency)
}

// When a measurement period ends, the latencies are used to determine the fast
// path state. Fastpath is independently enabled for both the sentry and stub
// threads, and is modeled as the following state machine:
//
//                  +----------StubFPOff,SentryFPOff-------+
//                  |          ^                  ^        |
//                  V          |                  |        V
//      +-->StubFPOn,SentryFPOff                StubFPOff,SentryFPOn<--+
//      |        |     ^                                 |     ^       |
//      |        V     |                                 V     |       |
//      |   StubFPOn,SentryFPOn                 StubFPOn,SentryFPOn    |
//      |   LastEnabledSentryFP                   LastEnabledStubFP    |
//      |           |                                       |          |
//      |           |                                       |          |
//      |           +---------> StubFPOn,SentryFPOn <-------+          |
//      |                              |   |                           |
//      |______________________________|   |___________________________|
//
// The default state is to have both stub and sentry fastpath OFF.
// A state transition to enable one fastpath is done when
// fpState.(stub|sentry)FPBackoff reaches 0. (stub|sentry)FPBackoff is
// decremented every recording period that the corresponding fastpath is
// disabled.
// A state transition to disable one fastpath is decided through the predicates
// shouldDisableStubFP or shouldDisableSentryFP, and activated with
// disableStubFP or disableSentryFP.
//
// Why have 3 states for both FPs being ON? The logic behind that is to do with
// the fact that fastpaths are interdependent. Enabling one fastpath can have
// negative effects on the latency metrics of the other in the event that there
// are not enough CPUs to run the fastpath. So it's very possible that the system
// finds itself in a state where it's beneficial to run one fastpath but not the
// other based on the workload it's doing. For this case, we need to remember
// what the last stable state was to return to, because the metrics will likely
// be bad enough for both sides to be eligible for being disabled.
//
// Once the system establishes that having both the stub and sentry fastpath ON
// is acceptable, it does prioritize disabling stub fastpath over disabling
// sentry fastpath, because the sentry fastpath at most takes one thread to spin.

const (
	recordingPeriod                = 400 * time.Microsecond
	fastPathBackoffMin             = 2
	maxRecentFPFailures            = 9
	numConsecutiveFailsToDisableFP = 2
)

// fastPathState is used to keep track of long term metrics that span beyond
// one measurement period.
type fastPathState struct {
	// stubBoundBaselineLatency and sentryBoundBaselineLatency record all
	// latency measures recorded during periods when their respective
	// fastpath was OFF.
	stubBoundBaselineLatency   latencyBuckets
	sentryBoundBaselineLatency latencyBuckets

	// stubFPBackoff and sentryFPBackoff are the periods remaining until
	// the system attempts to use the fastpath again.
	stubFPBackoff   int
	sentryFPBackoff int

	// stubFPRecentFailures and sentryFPRecentFailures are counters in the
	// range [0, maxRecentFPFailures] that are incremented by
	// disable(Stub|Sentry)FP and decremented by (stub|sentry)FPSuccess.
	// They are used to set the backoffs.
	stubFPRecentFailures   int
	sentryFPRecentFailures int

	consecutiveStubFPFailures   int
	consecutiveSentryFPFailures int

	_ [hostarch.CacheLineSize]byte
	// stubFastPathEnabled is a global flag referenced in other parts of
	// systrap to determine if the stub fast path is enabled or not.
	stubFastPathEnabled atomicbitops.Bool

	_ [hostarch.CacheLineSize]byte
	// sentryFastPathEnabled is a global flag referenced in other parts of
	// systrap to determine if the sentry fastpath is enabled or not.
	sentryFastPathEnabled atomicbitops.Bool

	_ [hostarch.CacheLineSize]byte
	// nrMaxAwakeStubThreads is the maximum number of awake stub threads over
	// all subprocesses at the this moment.
	nrMaxAwakeStubThreads atomicbitops.Uint32

	// usedStubFastPath and usedSentryFastPath are reset every recording
	// period, and are populated in case the system actually used the
	// fastpath (i.e. stub or dispatcher spun for some time without work).
	_                  [hostarch.CacheLineSize]byte
	usedStubFastPath   atomicbitops.Bool
	_                  [hostarch.CacheLineSize]byte
	usedSentryFastPath atomicbitops.Bool

	_ [hostarch.CacheLineSize]byte
	// curState is the current fastpath state function, which is called at
	// the end of every recording period.
	curState func(*fastPathState)
}

var (
	fastpath = fastPathState{
		stubFPBackoff:   fastPathBackoffMin,
		sentryFPBackoff: fastPathBackoffMin,
		curState:        sentryOffStubOff,
	}

	// fastPathContextLimit is the maximum number of contexts after which the fast
	// path in stub threads is disabled. Its value can be higher than the number of
	// CPU-s, because the Sentry is running with higher priority than stub threads,
	// deepSleepTimeout is much shorter than the Linux scheduler timeslice, so the
	// only thing that matters here is whether the Sentry handles syscall faster
	// than the overhead of scheduling another stub thread.
	//
	// It is set after maxSysmsgThreads is initialized.
	fastPathContextLimit = uint32(0)
)

// controlFastPath is used to spawn a goroutine when creating the Systrap
// platform.
func controlFastPath() {
	fastPathContextLimit = uint32(maxSysmsgThreads * 2)

	for {
		time.Sleep(recordingPeriod)

		fastpath.curState(&fastpath)
		// Reset FP trackers.
		fastpath.usedStubFastPath.Store(false)
		fastpath.usedSentryFastPath.Store(false)
	}
}

// getBackoff returns the number of recording periods that fastpath should remain
// disabled for, based on the num of recentFailures.
func getBackoff(recentFailures int) int {
	return 1 << recentFailures
}

//go:nosplit
func (s *fastPathState) sentryFastPath() bool {
	return s.sentryFastPathEnabled.Load()
}

//go:nosplit
func (s *fastPathState) stubFastPath() bool {
	return s.stubFastPathEnabled.Load() && (s.nrMaxAwakeStubThreads.Load() <= fastPathContextLimit)
}

// enableSentryFP is a wrapper to unconditionally enable sentry FP and increment
// a debug metric.
func (s *fastPathState) enableSentryFP() {
	s.sentryFastPathEnabled.Store(true)
	numTimesSentryFastPathEnabled.Increment()
}

// disableSentryFP returns true if the sentry fastpath was able to be disabled.
//
// It takes two calls to disableSentryFP without any calls to sentryFPSuccess in
// between to disable the sentry fastpath. This is done in order to mitigate the
// effects of outlier measures due to rdtsc inaccuracies.
func (s *fastPathState) disableSentryFP() bool {
	s.consecutiveSentryFPFailures++
	if s.consecutiveSentryFPFailures < numConsecutiveFailsToDisableFP {
		return false
	}
	s.consecutiveSentryFPFailures = 0
	s.sentryFastPathEnabled.Store(false)
	numTimesSentryFastPathDisabled.Increment()

	s.sentryFPBackoff = getBackoff(s.sentryFPRecentFailures)
	s.sentryFPRecentFailures = min(maxRecentFPFailures, s.sentryFPRecentFailures+1)
	return true
}

// enableStubFP is a wrapper to unconditionally enable stub FP and increment
// a debug metric.
func (s *fastPathState) enableStubFP() {
	s.stubFastPathEnabled.Store(true)
	numTimesStubFastPathEnabled.Increment()
}

// disableStubFP returns true if the stub fastpath was able to be disabled.
//
// It takes two calls to disableStubFP without any calls to stubFPSuccess in
// between to disable the stub fastpath. This is done in order to mitigate the
// effects of outlier measures due to rdtsc inaccuracies.
func (s *fastPathState) disableStubFP() bool {
	s.consecutiveStubFPFailures++
	if s.consecutiveStubFPFailures < numConsecutiveFailsToDisableFP {
		return false
	}
	s.consecutiveStubFPFailures = 0
	s.stubFastPathEnabled.Store(false)
	numTimesStubFastPathDisabled.Increment()

	s.stubFPBackoff = getBackoff(s.stubFPRecentFailures)
	s.stubFPRecentFailures = min(maxRecentFPFailures, s.stubFPRecentFailures+1)
	return true
}

func (s *fastPathState) sentryFPSuccess() {
	s.sentryFPRecentFailures = max(0, s.sentryFPRecentFailures-1)
	s.consecutiveSentryFPFailures = 0
}

func (s *fastPathState) stubFPSuccess() {
	s.stubFPRecentFailures = max(0, s.stubFPRecentFailures-1)
	s.consecutiveStubFPFailures = 0
}

// shouldDisableSentryFP returns true if the metrics indicate sentry fastpath
// should be disabled.
func (s *fastPathState) shouldDisableSentryFP(stubMedian, sentryMedian cpuTicks) bool {
	if !s.usedSentryFastPath.Load() {
		return false
	}
	stubBaseline := s.stubBoundBaselineLatency.getMedian()
	sentryBaseline := s.sentryBoundBaselineLatency.getMedian()
	if sentryMedian < sentryBaseline {
		// Assume the number of productive stubs is the core count on the
		// system, not counting the 1 core taken by the dispatcher for
		// the fast path.
		n := cpuTicks(maxSysmsgThreads - 1)
		// If the sentry fastpath is causing the stub latency to be
		// higher than normal, the point at which it's considered to be
		// too high is when the time saved via the sentry fastpath is
		// less than the time lost via higher stub latency (with some
		// error margin). Assume that all possible stub threads are
		// active for this comparison.
		diff := (sentryBaseline - sentryMedian) * n
		errorMargin := stubBaseline / 8
		return (stubMedian > stubBaseline) && (stubMedian-stubBaseline) > (diff+errorMargin)
	}
	// Running the fastpath resulted in higher sentry latency than baseline?
	// This does not happen often, but it is an indication that the fastpath
	// wasn't used to full effect: for example the dispatcher kept changing,
	// and that there was not enough CPU to place a new dispatcher fast
	// enough.
	//
	// If there isn't enough CPU we will most likely see large stub latency
	// regressions, and should disable the fastpath.
	return stubMedian > (stubBaseline + stubBaseline/2)
}

// shouldDisableStubFP returns true if the metrics indicate stub fastpath should
// be disabled.
func (s *fastPathState) shouldDisableStubFP(stubMedian, sentryMedian cpuTicks) bool {
	if !s.usedStubFastPath.Load() {
		return false
	}
	stubBaseline := s.stubBoundBaselineLatency.getMedian()
	sentryBaseline := s.sentryBoundBaselineLatency.getMedian()
	if stubMedian < stubBaseline {
		// If the stub fastpath is causing the sentry latency to be
		// higher than normal, the point at which it's considered to be
		// too high is when the time saved via the stub fastpath is
		// less than the time lost via higher sentry latency (with some
		// error margin). Unlike the stub latency, the sentry latency is
		// largely dependent on one thread (the dispatcher).
		diff := stubBaseline - stubMedian
		errorMargin := sentryBaseline / 8
		return (sentryMedian > sentryBaseline) && (sentryMedian-sentryBaseline) > (diff+errorMargin)
	}
	// Running the fastpath resulted in higher stub latency than baseline?
	// This is either an indication that there isn't enough CPU to schedule
	// stub threads to run the fastpath, or the user workload has changed to
	// be such that it returns less often to the sentry.
	//
	// If there isn't enough CPU we will most likely see large sentry latency
	// regressions, and should disable the fastpath.
	return sentryMedian > (sentryBaseline + sentryBaseline/2)
}

// The following functions are used for state transitions in the sentry/stub
// fastpath state machine described above.

func sentryOffStubOff(s *fastPathState) {
	if neverEnableFastPath {
		return
	}
	periodStubBoundMedian := latencies.stubBound.getMedian()
	s.stubBoundBaselineLatency.merge(&latencies.stubBound)
	latencies.stubBound.reset()
	if periodStubBoundMedian != 0 {
		s.stubFPBackoff = max(s.stubFPBackoff-1, 0)
	}

	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	s.sentryBoundBaselineLatency.merge(&latencies.sentryBound)
	latencies.sentryBound.reset()
	if periodSentryBoundMedian != 0 {
		s.sentryFPBackoff = max(s.sentryFPBackoff-1, 0)
	}

	if s.sentryFPBackoff == 0 {
		s.enableSentryFP()
		s.curState = sentryOnStubOff
	} else if s.stubFPBackoff == 0 {
		s.enableStubFP()
		s.curState = sentryOffStubOn
	}
}

func sentryOnStubOff(s *fastPathState) {
	periodStubBoundMedian := latencies.stubBound.getMedian()
	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	if periodStubBoundMedian == 0 || periodSentryBoundMedian == 0 {
		return
	}

	if s.shouldDisableSentryFP(periodStubBoundMedian, periodSentryBoundMedian) {
		if s.disableSentryFP() {
			s.curState = sentryOffStubOff
		}
	} else {
		s.sentryFPSuccess()
		// If we are going to keep sentry FP on that means stub latency
		// was fine; update the baseline.
		s.stubBoundBaselineLatency.merge(&latencies.stubBound)
		latencies.stubBound.reset()
		s.stubFPBackoff = max(s.stubFPBackoff-1, 0)
		if s.stubFPBackoff == 0 {
			s.enableStubFP()
			s.curState = sentryOnStubOnLastEnabledStub
		}
	}
	latencies.sentryBound.reset()
}

func sentryOffStubOn(s *fastPathState) {
	periodStubBoundMedian := latencies.stubBound.getMedian()
	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	if periodStubBoundMedian == 0 || periodSentryBoundMedian == 0 {
		return
	}

	if s.shouldDisableStubFP(periodStubBoundMedian, periodSentryBoundMedian) {
		if s.disableStubFP() {
			s.curState = sentryOffStubOff
		}
	} else {
		s.stubFPSuccess()

		s.sentryBoundBaselineLatency.merge(&latencies.sentryBound)
		latencies.sentryBound.reset()
		s.sentryFPBackoff = max(s.sentryFPBackoff-1, 0)
		if s.sentryFPBackoff == 0 {
			s.enableSentryFP()
			s.curState = sentryOnStubOnLastEnabledSentry
		}
	}
	latencies.stubBound.reset()
}

func sentryOnStubOnLastEnabledSentry(s *fastPathState) {
	periodStubBoundMedian := latencies.stubBound.getMedian()
	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	if periodStubBoundMedian == 0 || periodSentryBoundMedian == 0 {
		return
	}

	latencies.stubBound.reset()
	latencies.sentryBound.reset()

	if s.shouldDisableSentryFP(periodStubBoundMedian, periodSentryBoundMedian) {
		if s.disableSentryFP() {
			s.curState = sentryOffStubOn
		}
	} else {
		s.curState = sentryOnStubOn
		s.sentryFPSuccess()
		s.stubFPSuccess()
	}
}

func sentryOnStubOnLastEnabledStub(s *fastPathState) {
	periodStubBoundMedian := latencies.stubBound.getMedian()
	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	if periodStubBoundMedian == 0 || periodSentryBoundMedian == 0 {
		return
	}

	latencies.stubBound.reset()
	latencies.sentryBound.reset()

	if s.shouldDisableStubFP(periodStubBoundMedian, periodSentryBoundMedian) {
		if s.disableStubFP() {
			s.curState = sentryOnStubOff
		}
	} else {
		s.curState = sentryOnStubOn
		s.sentryFPSuccess()
		s.stubFPSuccess()
	}
}

func sentryOnStubOn(s *fastPathState) {
	periodStubBoundMedian := latencies.stubBound.getMedian()
	periodSentryBoundMedian := latencies.sentryBound.getMedian()
	if periodStubBoundMedian == 0 || periodSentryBoundMedian == 0 {
		return
	}

	latencies.stubBound.reset()
	latencies.sentryBound.reset()

	// Prioritize disabling stub fastpath over sentry fastpath, since sentry
	// only spins with one thread.
	if s.shouldDisableStubFP(periodStubBoundMedian, periodSentryBoundMedian) {
		if s.disableStubFP() {
			s.curState = sentryOnStubOff
		}
	} else if s.shouldDisableSentryFP(latencies.stubBound.getMedian(), latencies.sentryBound.getMedian()) {
		if s.disableSentryFP() {
			s.curState = sentryOffStubOn
		}
	} else {
		s.sentryFPSuccess()
		s.stubFPSuccess()
	}
}

// Profiling metrics intended for debugging purposes.
var (
	numTimesSentryFastPathDisabled = SystrapProfiling.MustCreateNewUint64Metric("/systrap/numTimesSentryFastPathDisabled", metric.Uint64Metadata{Cumulative: true})
	numTimesSentryFastPathEnabled  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/numTimesSentryFastPathEnabled", metric.Uint64Metadata{Cumulative: true})
	numTimesStubFastPathDisabled   = SystrapProfiling.MustCreateNewUint64Metric("/systrap/numTimesStubFastPathDisabled", metric.Uint64Metadata{Cumulative: true})
	numTimesStubFastPathEnabled    = SystrapProfiling.MustCreateNewUint64Metric("/systrap/numTimesStubFastPathEnabled", metric.Uint64Metadata{Cumulative: true})
	numTimesStubKicked             = SystrapProfiling.MustCreateNewUint64Metric("/systrap/numTimesStubKicked", metric.Uint64Metadata{Cumulative: true})

	stubLatWithin1kUS   = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatWithin1kUS", metric.Uint64Metadata{Cumulative: true})
	stubLatWithin5kUS   = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatWithin5kUS", metric.Uint64Metadata{Cumulative: true})
	stubLatWithin10kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatWithin10kUS", metric.Uint64Metadata{Cumulative: true})
	stubLatWithin20kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatWithin20kUS", metric.Uint64Metadata{Cumulative: true})
	stubLatWithin40kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatWithin40kUS", metric.Uint64Metadata{Cumulative: true})
	stubLatGreater40kUS = SystrapProfiling.MustCreateNewUint64Metric("/systrap/stubLatGreater40kUS", metric.Uint64Metadata{Cumulative: true})

	sentryLatWithin1kUS   = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatWithin1kUS", metric.Uint64Metadata{Cumulative: true})
	sentryLatWithin5kUS   = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatWithin5kUS", metric.Uint64Metadata{Cumulative: true})
	sentryLatWithin10kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatWithin10kUS", metric.Uint64Metadata{Cumulative: true})
	sentryLatWithin20kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatWithin20kUS", metric.Uint64Metadata{Cumulative: true})
	sentryLatWithin40kUS  = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatWithin40kUS", metric.Uint64Metadata{Cumulative: true})
	sentryLatGreater40kUS = SystrapProfiling.MustCreateNewUint64Metric("/systrap/sentryLatGreater40kUS", metric.Uint64Metadata{Cumulative: true})
)
