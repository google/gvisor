// Copyright 2020 The gVisor Authors.
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

// TestSysbenchCpu tests parses on sample 'sysbench cpu' output.
func TestSysbenchCpu(t *testing.T) {
	sampleData := `
sysbench 1.0.11 (using system LuaJIT 2.1.0-beta3)

Running the test with following options:
Number of threads: 8
Initializing random number generator from current time


Prime numbers limit: 10000

Initializing worker threads...

Threads started!

CPU speed:
    events per second:  9093.38

General statistics:
    total time:                          10.0007s
    total number of events:              90949

Latency (ms):
         min:                                  0.64
         avg:                                  0.88
         max:                                 24.65
         95th percentile:                      1.55
         sum:                              79936.91

Threads fairness:
    events (avg/stddev):           11368.6250/831.38
    execution time (avg/stddev):   9.9921/0.01
`
	sysbench := SysbenchCPU{}
	want := 9093.38
	if got, err := sysbench.parseEvents(sampleData); err != nil {
		t.Fatalf("parse cpu events failed: %v", err)
	} else if want != got {
		t.Fatalf("got: %f want: %f", got, want)
	}
}

// TestSysbenchMemory tests parsers on sample 'sysbench memory' output.
func TestSysbenchMemory(t *testing.T) {
	sampleData := `
sysbench 1.0.11 (using system LuaJIT 2.1.0-beta3)

Running the test with following options:
Number of threads: 8
Initializing random number generator from current time


Running memory speed test with the following options:
  block size: 1KiB
  total size: 102400MiB
  operation: write
  scope: global

Initializing worker threads...

Threads started!

Total operations: 47999046 (9597428.64 per second)

46874.07 MiB transferred (9372.49 MiB/sec)


General statistics:
    total time:                          5.0001s
    total number of events:              47999046

Latency (ms):
         min:                                  0.00
         avg:                                  0.00
         max:                                  0.21
         95th percentile:                      0.00
         sum:                              33165.91

Threads fairness:
    events (avg/stddev):           5999880.7500/111242.52
    execution time (avg/stddev):   4.1457/0.09
`
	sysbench := SysbenchMemory{}
	want := 9597428.64
	if got, err := sysbench.parseOperations(sampleData); err != nil {
		t.Fatalf("parse memory ops failed: %v", err)
	} else if want != got {
		t.Fatalf("got: %f want: %f", got, want)
	}
}

// TestSysbenchMutex tests parsers on sample 'sysbench mutex' output.
func TestSysbenchMutex(t *testing.T) {
	sampleData := `
sysbench 1.0.11 (using system LuaJIT 2.1.0-beta3)

The 'mutex' test requires a command argument. See 'sysbench mutex help'
root@ec078132e294:/# sysbench mutex --threads=8 run
sysbench 1.0.11 (using system LuaJIT 2.1.0-beta3)

Running the test with following options:
Number of threads: 8
Initializing random number generator from current time


Initializing worker threads...

Threads started!


General statistics:
    total time:                          0.2320s
    total number of events:              8

Latency (ms):
         min:                                152.35
         avg:                                192.48
         max:                                231.41
         95th percentile:                    231.53
         sum:                               1539.83

Threads fairness:
    events (avg/stddev):           1.0000/0.00
    execution time (avg/stddev):   0.1925/0.04
`

	sysbench := SysbenchMutex{}
	want := .1925
	if got, err := sysbench.parseExecutionTime(sampleData); err != nil {
		t.Fatalf("parse mutex time failed: %v", err)
	} else if want != got {
		t.Fatalf("got: %f want: %f", got, want)
	}

	want = 0.04
	if got, err := sysbench.parseDeviation(sampleData); err != nil {
		t.Fatalf("parse mutex deviation failed: %v", err)
	} else if want != got {
		t.Fatalf("got: %f want: %f", got, want)
	}

	want = 192.48
	if got, err := sysbench.parseLatency(sampleData); err != nil {
		t.Fatalf("parse mutex time failed: %v", err)
	} else if want != got {
		t.Fatalf("got: %f want: %f", got, want)
	}
}
