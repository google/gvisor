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

// Package metricsviz_cli_test tests metricsviz_cli.
package metricsviz_cli_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/metricsviz"
)

func TestMetricsvizCLI(t *testing.T) {
	ctx := context.Background()
	cliPath, err := testutil.FindFile("test/metricsviz/metricsviz_cli/metricsviz_cli")
	if err != nil {
		t.Fatalf("Failed to find metricsviz_cli: %v", err)
	}
	const testMetricName = "/metricsviz_cli_test/counter"
	testVal1 := &metric.FieldValue{Value: "val1"}
	testVal2 := &metric.FieldValue{Value: "val2"}
	testVal3 := &metric.FieldValue{Value: "val3"}
	testVals := []*metric.FieldValue{testVal1, testVal2, testVal3}
	testMetric := metric.MustCreateNewUint64Metric(testMetricName, metric.Uint64Metadata{
		Cumulative:  true,
		Sync:        true,
		Description: fmt.Sprintf("test counter for %s", t.Name()),
		Fields:      []metric.Field{metric.NewField("field1", testVals...)},
	})
	if err := metric.Initialize(); err != nil {
		t.Fatalf("Failed to initialize metrics: %v", err)
	}
	tempDir := t.TempDir()
	for _, lossy := range []bool{true, false} {
		t.Run(fmt.Sprintf("lossy=%v", lossy), func(t *testing.T) {
			logFilePath := path.Join(tempDir, fmt.Sprintf("lossy=%v.log", lossy))
			logFile, err := os.Create(logFilePath)
			if err != nil {
				t.Fatalf("Failed to create log file %q: %v", logFilePath, err)
			}
			err = metric.StartProfilingMetrics(metric.ProfilingMetricsOptions[*os.File]{
				Sink:    logFile,
				Lossy:   lossy,
				Metrics: testMetricName,
				Rate:    time.Millisecond,
			})
			if err != nil {
				t.Fatalf("Failed to start profiling metrics: %v", err)
			}

			// Generate some counter increments for 25ms.
			waitCtx, waitCancel := context.WithTimeout(ctx, 25*time.Millisecond)
			defer waitCancel()
			for waitCtx.Err() == nil {
				testMetric.Increment(testVals[rand.IntN(len(testVals))])
				select {
				case <-waitCtx.Done():
				case <-time.After(time.Millisecond):
					if lossy {
						// Also inject some crap in the logs to verify that it can deal
						// with text being written in the middle of metrics data.
						randomLogs := [][]byte{
							[]byte("some log"),
							[]byte("some log with a newline\n"),
							[]byte("a log with\rcarriage return in the middle"),
							[]byte("a log with\nmultiple\nnewlines"),
							{0x01, 0x02, 0x00, 0x03}, // Non-ASCII bytes.
						}
						if _, err := logFile.Write(randomLogs[rand.IntN(len(randomLogs))]); err != nil {
							t.Fatalf("Failed to write random log: %v", err)
						}
					}
				}
			}

			metric.StopProfilingMetrics()
			logFileContents, err := os.ReadFile(logFilePath)
			if err != nil {
				t.Fatalf("Failed to read log file %q: %v", logFilePath, err)
			}
			if len(logFileContents) == 0 {
				t.Fatalf("Log file %q is empty", logFilePath)
			}
			t.Logf("Log file %q contents:\n%s\n(end of log file contents)", logFilePath, string(logFileContents))

			if output, err := exec.CommandContext(ctx, cliPath, logFilePath).CombinedOutput(); err != nil {
				t.Fatalf("Failed to run metricsviz_cli: %v (output: %s)", err, strings.TrimSpace(string(output)))
			}
			if err = metricsviz.FromFile(ctx, logFilePath, t.Logf); err != nil {
				t.Fatalf("Failed to generate metricsviz from %q: %v", logFilePath, err)
			}
			expectedHTMLPath := path.Join(tempDir, fmt.Sprintf("lossy=%v.html", lossy))
			htmlStat, err := os.Stat(expectedHTMLPath)
			if err != nil {
				t.Fatalf("Failed to stat %q: %v", expectedHTMLPath, err)
			}
			if htmlStat.Size() == 0 {
				t.Fatalf("HTML file %q is empty", expectedHTMLPath)
			}
		})
	}
}
