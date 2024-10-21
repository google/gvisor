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

package tools

import (
	"testing"
)

const (
	exampleOutput = `*** Measurement Settings ***
          Batch size: 1
          Service Kind: TRITON
          Sending a total of 1 requests
          Using asynchronous calls for inference

        Request concurrency: 1
          Client:
            Request count: 2
            Sequence count: 1 (0.999571 seq/sec)
            Throughput: 1.99914 infer/sec
            Avg latency: 5259 usec (standard deviation 63 usec)
            p50 latency: 5304 usec
            p90 latency: 5304 usec
            p95 latency: 5304 usec
            p99 latency: 5304 usec
            Avg HTTP time: 5207 usec (send/recv 256 usec + response wait 4951 usec)
          Server:
            Inference count: 2
            Execution count: 2
            Successful request count: 2
            Avg request latency: 4675 usec (overhead 27 usec + queue 2352 usec + compute input 24 usec + compute infer 2259 usec + compute output 13 usec)

        Inferences/Second vs. Client Average Batch Latency
        Concurrency: 1, throughput: 1.99914 infer/sec, latency 5259 usec`
)

func TestParseOutput(t *testing.T) {
	throughput, latency, err := parseMetrics(exampleOutput)
	if err != nil {
		t.Errorf("parseMetrics failed: %v", err)
	}
	if throughput != 1.99914 {
		t.Errorf("throughput = %v, want 1.99914", throughput)
	}
	if latency != 5259 {
		t.Errorf("latency = %v, want 5259", latency)
	}
}
