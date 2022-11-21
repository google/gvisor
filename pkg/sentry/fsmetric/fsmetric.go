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

// Package fsmetric defines filesystem metrics.
package fsmetric

import (
	"time"

	"gvisor.dev/gvisor/pkg/metric"
)

// RecordWaitTime enables the ReadWait, GoferReadWait9P, GoferReadWaitHost, and
// TmpfsReadWait metrics. Enabling this comes at a CPU cost due to performing
// three clock reads per read call.
//
// Note that this is only performed in the direct read path, and may not be
// consistently applied for other forms of reads, such as splice.
var RecordWaitTime = false

// Metrics that apply to all filesystems.
var (
	Opens    = metric.MustCreateNewUint64Metric("/fs/opens", false /* sync */, "Number of file opens.")
	Reads    = metric.MustCreateNewUint64Metric("/fs/reads", false /* sync */, "Number of file reads.")
	ReadWait = metric.MustCreateNewUint64NanosecondsMetric("/fs/read_wait", false /* sync */, "Time waiting on file reads, in nanoseconds.")
)

// Metrics that only apply to fs/gofer and fsimpl/gofer.
var (
	GoferOpens9P      = metric.MustCreateNewUint64Metric("/gofer/opens_9p", false /* sync */, "Number of times a file was opened from a gofer and did not have a host file descriptor.")
	GoferOpensHost    = metric.MustCreateNewUint64Metric("/gofer/opens_host", false /* sync */, "Number of times a file was opened from a gofer and did have a host file descriptor.")
	GoferReads9P      = metric.MustCreateNewUint64Metric("/gofer/reads_9p", false /* sync */, "Number of 9P file reads from a gofer.")
	GoferReadWait9P   = metric.MustCreateNewUint64NanosecondsMetric("/gofer/read_wait_9p", false /* sync */, "Time waiting on 9P file reads from a gofer, in nanoseconds.")
	GoferReadsHost    = metric.MustCreateNewUint64Metric("/gofer/reads_host", false /* sync */, "Number of host file reads from a gofer.")
	GoferReadWaitHost = metric.MustCreateNewUint64NanosecondsMetric("/gofer/read_wait_host", false /* sync */, "Time waiting on host file reads from a gofer, in nanoseconds.")
)

// Metrics that only apply to fs/tmpfs and fsimpl/tmpfs.
var (
	TmpfsOpensRO  = metric.MustCreateNewUint64Metric("/in_memory_file/opens_ro", false /* sync */, "Number of times an in-memory file was opened in read-only mode.")
	TmpfsOpensW   = metric.MustCreateNewUint64Metric("/in_memory_file/opens_w", false /* sync */, "Number of times an in-memory file was opened in write mode.")
	TmpfsReads    = metric.MustCreateNewUint64Metric("/in_memory_file/reads", false /* sync */, "Number of in-memory file reads.")
	TmpfsReadWait = metric.MustCreateNewUint64NanosecondsMetric("/in_memory_file/read_wait", false /* sync */, "Time waiting on in-memory file reads, in nanoseconds.")
)

// StartReadWait indicates the beginning of a file read.
func StartReadWait() time.Time {
	if !RecordWaitTime {
		return time.Time{}
	}
	return time.Now()
}

// FinishReadWait indicates the end of a file read whose time is accounted by
// m. start must be the value returned by the corresponding call to
// StartReadWait.
//
// FinishReadWait is marked nosplit for performance since it's often called
// from defer statements, which prevents it from being inlined
// (https://github.com/golang/go/issues/38471).
//
//go:nosplit
func FinishReadWait(m *metric.Uint64Metric, start time.Time) {
	if !RecordWaitTime {
		return
	}
	m.IncrementBy(uint64(time.Since(start).Nanoseconds()))
}
