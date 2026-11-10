// Copyright 2026 The gVisor Authors.
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

package fs_test

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var (
	runsc    = flag.String("runsc", os.Getenv("RUNTIME"), "runsc binary for overlay identity benchmarks")
	directfs = flag.Bool("directfs", true, "enable DirectFS")
)

type measurement struct {
	FirstNS  int64
	SecondNS int64
}

// workload measures filesystem operations inside the sandbox.
func workload() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("expected workload directory, count, operation")
	}
	count, err := strconv.Atoi(os.Args[3])
	if err != nil {
		return err
	}
	var result measurement
	for iteration := 0; iteration < 2; iteration++ {
		start := time.Now()
		switch os.Args[4] {
		case "readdir":
			f, err := os.Open(os.Args[2])
			if err != nil {
				return err
			}
			names, err := f.Readdirnames(-1)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(names) != count {
				return fmt.Errorf("listed %d files, want %d", len(names), count)
			}
		case "stat":
			for i := 0; i < count; i++ {
				if _, err := os.Stat(filepath.Join(os.Args[2], strconv.Itoa(i))); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unknown operation %q", os.Args[4])
		}
		elapsed := time.Since(start).Nanoseconds()
		if iteration == 0 {
			result.FirstNS = elapsed
		} else {
			result.SecondNS = elapsed
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	return nil
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "overlay-identity-workload" {
		if err := workload(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func benchmarkIdentity(b *testing.B, operation string, counts []int) {
	if *runsc == "" {
		b.Fatal("set -runsc to an absolute runtime binary path")
	}
	if os.Geteuid() != 0 {
		b.Fatal("run as root to create the sandbox namespaces")
	}
	// A copy outside bazel-bin can be executed from the sandbox's rootfs.
	base, err := os.MkdirTemp("/tmp", "overlay-identity-benchmark-")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(base)
	self, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		b.Fatal(err)
	}
	app := filepath.Join(base, "workload")
	if err := os.WriteFile(app, binary, 0755); err != nil {
		b.Fatal(err)
	}
	for _, count := range counts {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			dir, err := os.MkdirTemp(base, strconv.Itoa(count)+"-")
			if err != nil {
				b.Fatal(err)
			}
			defer os.RemoveAll(dir)
			for i := 0; i < count; i++ {
				if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)), nil, 0644); err != nil {
					b.Fatal(err)
				}
			}
			var first, second int64
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				cmd := exec.CommandContext(ctx, *runsc, "--root="+filepath.Join(base, "state"),
					"--network=none", "--platform=systrap", "--directfs="+strconv.FormatBool(*directfs),
					"do", "--quiet", "--cwd=/", app, "overlay-identity-workload", dir, strconv.Itoa(count), operation)
				out, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					b.Fatalf("workload failed: %v: %s", err, out)
				}
				var result measurement
				if err := json.Unmarshal(out, &result); err != nil {
					b.Fatalf("invalid workload output: %v: %s", err, out)
				}
				first += result.FirstNS
				second += result.SecondNS
			}
			b.ReportMetric(float64(first)/float64(b.N), "ns/op")
			b.ReportMetric(float64(second)/float64(b.N), "second-ns/op")
		})
	}
}

func BenchmarkOverlayReaddir(b *testing.B) {
	benchmarkIdentity(b, "readdir", []int{1000, 10000, 100000})
}

func BenchmarkOverlayStat(b *testing.B) {
	benchmarkIdentity(b, "stat", []int{20000, 100000, 200000})
}
