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

//go:build sentry_profiling
// +build sentry_profiling

package metric

import (
	"testing"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

func TestProfilingMetricsEnabled(t *testing.T) {
	defer resetTest()

	_, err := SentryProfiling.NewUint64Metric("/counterM", Uint64Metadata{
		Cumulative:  true,
		Description: "one uint64 metric",
	})
	if err != nil {
		t.Fatalf("NewUint64Metric got err %v want nil", err)
	}

	bucketer := NewExponentialBucketer(3, 2, 0, 1)
	_, err = SentryProfiling.NewDistributionMetric("/distribM", false, bucketer, pb.MetricMetadata_UNITS_NANOSECONDS, "One distribution metric")
	if err != nil {
		t.Fatalf("NewDistributionMetric got err %v want nil", err)
	}

	_, err = SentryProfiling.NewTimerMetric("/timerM", bucketer, "One timer metric")
	if err != nil {
		t.Fatalf("NewTimerMetric got err %v want nil", err)
	}

	if err := Initialize(); err != nil {
		t.Fatalf("Initialize(): %s", err)
	}

	if len(emitter) != 1 {
		t.Fatalf("Initialize emitted %d events want 1", len(emitter))
	}

	mr, ok := emitter[0].(*pb.MetricRegistration)
	if !ok {
		t.Fatalf("emitter %v got %T want pb.MetricRegistration", emitter[0], emitter[0])
	}

	if len(mr.Metrics) != 3 {
		t.Errorf("MetricRegistration got %d metrics want %d", len(mr.Metrics), 3)
	}
}
