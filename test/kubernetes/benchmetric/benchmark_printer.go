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

package benchmetric

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// benchmarkPrinter handles printing metrics in the format of golang's *testing.B benchmarks.
// The format is compatible with `benchstat`, and it is expected that the user use that executable
// to analyze results. We use this due to the need to use *testing.T for benchmarks so that we can
// run in parallel on multiple clusters at a time, something *testing.B does not do well.
type benchmarkPrinter struct{}

// newRecorder creates a benchmark `Recorder`.
func newRecorder(context.Context) (Recorder, error) {
	return &benchmarkPrinter{}, nil
}

// Record implements `Recorder.Record`.
func (b *benchmarkPrinter) Record(ctx context.Context, name string, values ...MetricValue) error {
	return b.RecordIters(ctx, name, 1, values...)
}

// printMutex is used to lock benchmark results printing across benchmarks.
// This avoids multiple parallel benchmarks from logging their data
// interleaved in the same log.
var printMutex sync.Mutex

// Record implements `Recorder.RecordIters`.
func (b *benchmarkPrinter) RecordIters(ctx context.Context, name string, iters int, values ...MetricValue) error {
	printMutex.Lock()
	defer printMutex.Unlock()
	if iters <= 0 {
		return fmt.Errorf("invalid value for iters: %d", iters)
	}
	content := []string{fmt.Sprintf("Benchmark%s\t%d", name, iters)}
	for _, m := range values {
		content = append(content, m.ToBenchstat())
	}
	out := strings.Join(content, "\t")
	fmt.Fprintf(os.Stderr, "%s\n", out)
	return nil
}
