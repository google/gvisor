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
package fs

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

type fioTestCase struct {
	test      string // test to run: read, write, randread, randwrite.
	size      string // total size to be read/written of format N[GMK] (e.g. 5G).
	blocksize string // blocksize to be read/write of format N[GMK] (e.g. 4K).
	iodepth   int    // iodepth for reads/writes.
	time      int    // time to run the test in seconds, usually for rand(read/write).
}

// makeCmdFromTestcase makes a fio command.
func (f *fioTestCase) makeCmdFromTestcase(filename string) []string {
	cmd := []string{"fio", "--output-format=json", "--ioengine=sync"}
	cmd = append(cmd, fmt.Sprintf("--name=%s", f.test))
	cmd = append(cmd, fmt.Sprintf("--size=%s", f.size))
	cmd = append(cmd, fmt.Sprintf("--blocksize=%s", f.blocksize))
	cmd = append(cmd, fmt.Sprintf("--filename=%s", filename))
	cmd = append(cmd, fmt.Sprintf("--iodepth=%d", f.iodepth))
	cmd = append(cmd, fmt.Sprintf("--rw=%s", f.test))
	if f.time != 0 {
		cmd = append(cmd, "--time_based")
		cmd = append(cmd, fmt.Sprintf("--runtime=%d", f.time))
	}
	return cmd
}

// BenchmarkFio runs fio on the runtime under test. There are 4 basic test
// cases each run on a tmpfs mount and a bind mount. Fio requires root so that
// caches can be dropped.
func BenchmarkFio(b *testing.B) {
	testCases := []fioTestCase{
		fioTestCase{
			test:      "write",
			size:      "5G",
			blocksize: "1M",
			iodepth:   4,
		},
		fioTestCase{
			test:      "read",
			size:      "5G",
			blocksize: "1M",
			iodepth:   4,
		},
		fioTestCase{
			test:      "randwrite",
			size:      "5G",
			blocksize: "4K",
			iodepth:   4,
			time:      30,
		},
		fioTestCase{
			test:      "randread",
			size:      "5G",
			blocksize: "4K",
			iodepth:   4,
			time:      30,
		},
	}

	machine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	for _, fsType := range []mount.Type{mount.TypeBind, mount.TypeTmpfs} {
		for _, tc := range testCases {
			testName := strings.Title(tc.test) + strings.Title(string(fsType))
			b.Run(testName, func(b *testing.B) {
				ctx := context.Background()
				container := machine.GetContainer(ctx, b)
				defer container.CleanUp(ctx)

				// Directory and filename inside container where fio will read/write.
				outdir := "/data"
				outfile := filepath.Join(outdir, "test.txt")

				// Make the required mount and grab a cleanup for bind mounts
				// as they are backed by a temp directory (mktemp).
				mnt, mountCleanup, err := makeMount(machine, fsType, outdir)
				if err != nil {
					b.Fatalf("failed to make mount: %v", err)
				}
				defer mountCleanup()
				cmd := tc.makeCmdFromTestcase(outfile)

				// Start the container with the mount.
				if err := container.Spawn(
					ctx,
					dockerutil.RunOpts{
						Image: "benchmarks/fio",
						Mounts: []mount.Mount{
							mnt,
						},
					},
					// Sleep on the order of b.N.
					"sleep", fmt.Sprintf("%d", 1000*b.N),
				); err != nil {
					b.Fatalf("failed to start fio container with: %v", err)
				}

				// For reads, we need a file to read so make one inside the container.
				if strings.Contains(tc.test, "read") {
					fallocateCmd := fmt.Sprintf("fallocate -l %s %s", tc.size, outfile)
					if out, err := container.Exec(ctx, dockerutil.ExecOpts{},
						strings.Split(fallocateCmd, " ")...); err != nil {
						b.Fatalf("failed to create readable file on mount: %v, %s", err, out)
					}
				}

				// Drop caches just before running.
				if err := harness.DropCaches(machine); err != nil {
					b.Skipf("failed to drop caches with %v. You probably need root.", err)
				}
				container.RestartProfiles()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Run fio.
					data, err := container.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
					if err != nil {
						b.Fatalf("failed to run cmd %v: %v", cmd, err)
					}
					b.StopTimer()
					// Parse the output and report the metrics.
					isRead := strings.Contains(tc.test, "read")
					bw, err := parseBandwidth(data, isRead)
					if err != nil {
						b.Fatalf("failed to parse bandwidth from %s with: %v", data, err)
					}
					b.ReportMetric(bw, "bandwidth") // in b/s.

					iops, err := parseIOps(data, isRead)
					if err != nil {
						b.Fatalf("failed to parse iops from %s with: %v", data, err)
					}
					b.ReportMetric(iops, "iops")
					// If b.N is used (i.e. we run for an hour), we should drop caches
					// after each run.
					if err := harness.DropCaches(machine); err != nil {
						b.Fatalf("failed to drop caches: %v", err)
					}
					b.StartTimer()
				}
			})
		}
	}
}

// makeMount makes a mount and cleanup based on the requested type. Bind
// and volume mounts are backed by a temp directory made with mktemp.
// tmpfs mounts require no such backing and are just made.
// It is up to the caller to call the returned cleanup.
func makeMount(machine harness.Machine, mountType mount.Type, target string) (mount.Mount, func(), error) {
	switch mountType {
	case mount.TypeVolume, mount.TypeBind:
		dir, err := machine.RunCommand("mktemp", "-d")
		if err != nil {
			return mount.Mount{}, func() {}, fmt.Errorf("failed to create tempdir: %v", err)
		}
		dir = strings.TrimSuffix(dir, "\n")

		out, err := machine.RunCommand("chmod", "777", dir)
		if err != nil {
			machine.RunCommand("rm", "-rf", dir)
			return mount.Mount{}, func() {}, fmt.Errorf("failed modify directory: %v %s", err, out)
		}
		return mount.Mount{
			Target: target,
			Source: dir,
			Type:   mount.TypeBind,
		}, func() { machine.RunCommand("rm", "-rf", dir) }, nil
	case mount.TypeTmpfs:
		return mount.Mount{
			Target: target,
			Type:   mount.TypeTmpfs,
		}, func() {}, nil
	default:
		return mount.Mount{}, func() {}, fmt.Errorf("illegal mount time not supported: %v", mountType)
	}
}

// parseBandwidth reports the bandwidth in b/s.
func parseBandwidth(data string, isRead bool) (float64, error) {
	if isRead {
		result, err := parseFioJSON(data, "read", "bw")
		if err != nil {
			return 0, err
		}
		return 1024 * result, nil
	}
	result, err := parseFioJSON(data, "write", "bw")
	if err != nil {
		return 0, err
	}
	return 1024 * result, nil
}

// parseIOps reports the write IO per second metric.
func parseIOps(data string, isRead bool) (float64, error) {
	if isRead {
		return parseFioJSON(data, "read", "iops")
	}
	return parseFioJSON(data, "write", "iops")
}

// fioResult is for parsing FioJSON.
type fioResult struct {
	Jobs []fioJob
}

// fioJob is for parsing FioJSON.
type fioJob map[string]json.RawMessage

// fioMetrics is for parsing FioJSON.
type fioMetrics map[string]json.RawMessage

// parseFioJSON parses data and grabs "op" (read or write) and "metric"
// (bw or iops) from the JSON.
func parseFioJSON(data, op, metric string) (float64, error) {
	var result fioResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return 0, fmt.Errorf("could not unmarshal data: %v", err)
	}

	if len(result.Jobs) < 1 {
		return 0, fmt.Errorf("no jobs present to parse")
	}

	var metrics fioMetrics
	if err := json.Unmarshal(result.Jobs[0][op], &metrics); err != nil {
		return 0, fmt.Errorf("could not unmarshal jobs: %v", err)
	}

	if _, ok := metrics[metric]; !ok {
		return 0, fmt.Errorf("no metric found for op: %s", op)
	}
	return strconv.ParseFloat(string(metrics[metric]), 64)
}

// TestParsers tests that the parsers work on sampleData.
func TestParsers(t *testing.T) {
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
	// WriteBandwidth.
	got, err := parseBandwidth(sampleData, false)
	var want float64 = 1753471.0 * 1024
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// ReadBandwidth.
	got, err = parseBandwidth(sampleData, true)
	want = 123456 * 1024
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// WriteIOps.
	got, err = parseIOps(sampleData, false)
	want = 438367.892977
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	// ReadIOps.
	got, err = parseIOps(sampleData, true)
	want = 1234.5678
	if err != nil {
		t.Fatalf("parse failed with err: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}
}
