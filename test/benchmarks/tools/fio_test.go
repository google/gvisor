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

import "testing"

// TestFio checks the Fio parsers on sample output.
func TestFio(t *testing.T) {
	sampleData := `
{
  "fio version" : "fio-3.1",
  "timestamp" : 1554837456,
  "timestamp_ms" : 1554837456621,
  "time" : "Tue Apr  9 19:17:36 2019",
  "jobs" : [
    {
      "jobname" : "test",
      "groupid" : 0,
      "error" : 0,
      "eta" : 2147483647,
      "elapsed" : 1,
      "job options" : {
        "name" : "test",
        "ioengine" : "sync",
        "size" : "1073741824",
        "filename" : "/disk/file.dat",
        "iodepth" : "4",
        "bs" : "4096",
        "rw" : "write"
      },
      "read" : {
        "io_bytes" : 0,
        "io_kbytes" : 0,
        "bw" : 123456,
        "iops" : 1234.5678,
        "runtime" : 0,
        "total_ios" : 0,
        "short_ios" : 0,
        "bw_min" : 0,
        "bw_max" : 0,
        "bw_agg" : 0.000000,
        "bw_mean" : 0.000000,
        "bw_dev" : 0.000000,
        "bw_samples" : 0,
        "iops_min" : 0,
        "iops_max" : 0,
        "iops_mean" : 0.000000,
        "iops_stddev" : 0.000000,
        "iops_samples" : 0
      },
      "write" : {
        "io_bytes" : 1073741824,
        "io_kbytes" : 1048576,
        "bw" : 1753471,
        "iops" : 438367.892977,
        "runtime" : 598,
        "total_ios" : 262144,
        "bw_min" : 1731120,
        "bw_max" : 1731120,
        "bw_agg" : 98.725328,
        "bw_mean" : 1731120.000000,
        "bw_dev" : 0.000000,
        "bw_samples" : 1,
        "iops_min" : 432780,
        "iops_max" : 432780,
        "iops_mean" : 432780.000000,
        "iops_stddev" : 0.000000,
        "iops_samples" : 1
      }
    }
  ]
}
`
	fio := Fio{}
	// WriteBandwidth.
	got, err := fio.parseBandwidth(sampleData, false)
	want := 1753471.0 * 1024
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// ReadBandwidth.
	got, err = fio.parseBandwidth(sampleData, true)
	want = 123456 * 1024
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// WriteIOps.
	got, err = fio.parseIOps(sampleData, false)
	want = 438367.892977
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// ReadIOps.
	got, err = fio.parseIOps(sampleData, true)
	want = 1234.5678
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}
}
