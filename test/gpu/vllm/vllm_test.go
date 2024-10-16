// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package vllm_test holds benchmarks around the vLLM inference engine.
package vllm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// BenchmarkVLLM runs a vLLM workload.
func BenchmarkVLLM(b *testing.B) {
	doVLLMTest(b)
}

func doVLLMTest(b *testing.B) {
	serverMachine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer serverMachine.CleanUp()

	ctx := context.Background()
	serverCtr := serverMachine.GetContainer(ctx, b)
	defer serverCtr.CleanUp(ctx)
	if err := harness.DropCaches(serverMachine); err != nil {
		b.Skipf("failed to drop caches: %v. You probably need root.", err)
	}

	// Run vllm.
	runOpts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{})
	if err != nil {
		b.Fatalf("failed to get GPU run options: %v", err)
	}
	runOpts.Image = "gpu/vllm"
	runOpts.Env = []string{"PYTHONPATH=$PYTHONPATH:/vllm"}

	if err := serverCtr.Spawn(ctx, runOpts); err != nil {
		b.Errorf("failed to run container: %v", err)
	}
	if out, err := serverCtr.WaitForOutput(ctx, "Uvicorn running on http://0.0.0.0:8000", 10*time.Minute); err != nil {
		b.Fatalf("failed to start vllm model: %v %s", err, out)
	}

	b.Run("opt-125", func(b *testing.B) {
		ctx := context.Background()

		b.ResetTimer()
		b.StopTimer()

		clientMachine, err := harness.GetMachine()
		if err != nil {
			b.Fatalf("failed to get machine: %v", err)
		}
		defer clientMachine.CleanUp()
		clientCtr := clientMachine.GetContainer(ctx, b)
		defer clientCtr.CleanUp(ctx)

		// store vllm logs here
		logsDir := b.TempDir()

		b.StartTimer()
		out, err := clientCtr.Run(ctx, dockerutil.RunOpts{
			Links: []string{serverCtr.MakeLink("vllmctr")},
			Image: "gpu/vllm",
			Env:   []string{"PYTHONPATH=$PYTHONPATH:/vllm"},
			Mounts: []mount.Mount{
				// The logs dir is used because vllm only outputs json to a file.
				{
					Source: logsDir,
					Target: "/tmp",
					Type:   "bind",
				},
			},
		}, "/vllm/benchmarks/benchmark_serving.py", "--num-prompts", fmt.Sprintf("%d", b.N), "--host", "vllmctr", "--model", "/model", "--tokenizer", "/model", "--endpoint", "/v1/completions", "--backend", "openai", "--dataset", "/ShareGPT_V3_unfiltered_cleaned_split.json", "--save-result", "--result-dir", "/tmp")
		if err != nil {
			b.Errorf("failed to run container: %v logs: %s", err, out)
		}

		b.StopTimer()

		metrics, err := parseVLLMJSON(logsDir)
		if err != nil {
			b.Errorf("failed to parse vllm output: %v", err)
		}

		if metrics.Completed == 0 {
			b.Errorf("did not complete at least one request")
		}

		for _, err := range metrics.Errors {
			if err != "" {
				b.Errorf("unexpected errors: %s", metrics.Errors)
			}
		}

		b.ReportMetric(metrics.RequestsPerSec, "requests/sec")
		b.ReportMetric(metrics.InputToksPerSec, "input-tok/sec")
		b.ReportMetric(metrics.OutputToksPerSec, "output-tok/sec")
		b.ReportMetric(metrics.TTFTAvgMS*1000000, "ttft-avg-ns")
		b.ReportMetric(metrics.TTFTP50MS*1000000, "ttft-p50-ns")
		b.ReportMetric(metrics.TTFTP99MS*1000000, "ttft-p99-ns")
		b.ReportMetric(metrics.TPOTAvgMS*1000000, "tpot-avg-ns")
		b.ReportMetric(metrics.TPOTP50MS*1000000, "tpot-p50-ns")
		b.ReportMetric(metrics.TPOTP99MS*1000000, "tpot-p99-ns")
	})
}

// Modeled after the metrics reported here: https://github.com/vllm-project/vllm/blob/main/benchmarks/benchmark_serving.py#L338-L358
type metrics struct {
	Duration          float64 `json:"duration"`
	Completed         int     `json:"completed"`
	TotalInputTokens  int     `json:"total_input_tokens"`
	TotalOutputTokens int     `json:"total_output_tokens"`
	RequestsPerSec    float64 `json:"request_throughput"`
	InputToksPerSec   float64 `json:"input_throughput"`
	OutputToksPerSec  float64 `json:"output_throughput"`
	TTFTAvgMS         float64 `json:"mean_ttft_ms"`
	TTFTP50MS         float64 `json:"median_ttft_ms"`
	TTFTP99MS         float64 `json:"p99_ttft_ms"`
	TPOTAvgMS         float64 `json:"mean_tpot_ms"`
	TPOTP50MS         float64 `json:"median_tpot_ms"`
	TPOTP99MS         float64 `json:"p99_tpot_ms"`
	// metrics that are available but unused so far.
	// InputLens         []int   `json:"input_lens"`
	// OutputLens        []int   `json:"output_lens"`
	// TTFTs             []float64   `json:"ttfts"`
	// ITLS              [][]float64 `json:"itls"`
	// GeneratedTexts    []string `json:"generated_texts"`
	Errors []string `json:"errors"`
}

// parseVLLMJSON expects a path that contains only one json file.
func parseVLLMJSON(path string) (metrics, error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return metrics{}, fmt.Errorf("failed to read directory: %w", err)
	}

	var jsonPath string
	// Take the first json file as logs output.
	// Error if there are multiple.
	for _, name := range files {
		if strings.HasSuffix(name.Name(), ".json") {
			jsonPath = filepath.Join(path, name.Name())
			continue
		}

		if jsonPath != "" && strings.HasSuffix(name.Name(), ".json") {
			return metrics{}, errors.New("found more than one json file, expected 1")
		}
	}
	if jsonPath == "" {
		return metrics{}, errors.New("no json file found")
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return metrics{}, fmt.Errorf("failed to read file: %w", err)
	}

	var vllm metrics
	if err := json.Unmarshal(data, &vllm); err != nil {
		return metrics{}, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	return vllm, nil
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
