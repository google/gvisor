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

package container

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var platforms = flag.String("test_platforms", os.Getenv("TEST_PLATFORMS"), "Platforms to test with.")
var benchIterations = flag.Int("benchmark_iterations", 1000, "Number of benchmark iterations to run.")

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Debug)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

type benchMetrics struct {
	Name           string
	SetupLatencies []time.Duration
	ExecLatencies  []time.Duration
	CleanLatencies []time.Duration
	TotalLatencies []time.Duration
}

type statSummary struct {
	Count  int
	Min    time.Duration
	Max    time.Duration
	Mean   time.Duration
	Median time.Duration
	P90    time.Duration
	P95    time.Duration
	P99    time.Duration
	StdDev time.Duration
}

func computeSummary(durs []time.Duration) statSummary {
	if len(durs) == 0 {
		return statSummary{}
	}
	sorted := make([]time.Duration, len(durs))
	copy(sorted, durs)
	slices.Sort(sorted)

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	mean := time.Duration(int64(sum) / int64(len(sorted)))

	var sumSq float64
	for _, d := range sorted {
		diff := float64(d - mean)
		sumSq += diff * diff
	}
	stdDev := time.Duration(math.Sqrt(sumSq / float64(len(sorted))))

	pct := func(p float64) time.Duration {
		idx := int(float64(len(sorted)-1) * p)
		return sorted[idx]
	}

	return statSummary{
		Count:  len(sorted),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Mean:   mean,
		Median: pct(0.50),
		P90:    pct(0.90),
		P95:    pct(0.95),
		P99:    pct(0.99),
		StdDev: stdDev,
	}
}

func printBenchmarkReport(platformName string, cold, warm benchMetrics) {
	coldTotal := computeSummary(cold.TotalLatencies)
	warmTotal := computeSummary(warm.TotalLatencies)
	coldSetup := computeSummary(cold.SetupLatencies)
	warmSetup := computeSummary(warm.SetupLatencies)
	coldExec := computeSummary(cold.ExecLatencies)
	warmExec := computeSummary(warm.ExecLatencies)

	speedupTotal := float64(coldTotal.Mean) / float64(warmTotal.Mean)
	speedupMedian := float64(coldTotal.Median) / float64(warmTotal.Median)
	reductionTotal := (1.0 - float64(warmTotal.Mean)/float64(coldTotal.Mean)) * 100.0
	setupReduction := (1.0 - float64(warmSetup.Mean)/float64(coldSetup.Mean)) * 100.0

	fmt.Println()
	fmt.Println("==================================================================================")
	fmt.Printf(" BENCHMARK REPORT [%s]: %s vs %s\n", strings.ToUpper(platformName), cold.Name, warm.Name)
	fmt.Println("==================================================================================")
	fmt.Printf("Iterations: %d runs each\n\n", coldTotal.Count)

	fmt.Println("+-----------------------+--------------------+--------------------+--------------------+")
	fmt.Println("| Metric (Latency)      | Cold Start         | Warm Pool + DynMnt | Speedup / Diff     |")
	fmt.Println("+-----------------------+--------------------+--------------------+--------------------+")
	fmt.Printf("| Setup (Mean)          | %18v | %18v | %17.2f%% | (reduction)\n", coldSetup.Mean, warmSetup.Mean, setupReduction)
	fmt.Printf("| Setup (Median / p50)  | %18v | %18v | %17.2fx | (faster)\n", coldSetup.Median, warmSetup.Median, float64(coldSetup.Median)/float64(warmSetup.Median))
	fmt.Printf("| Exec (Mean)           | %18v | %18v | %17.2fx |\n", coldExec.Mean, warmExec.Mean, float64(coldExec.Mean)/float64(warmExec.Mean))
	fmt.Printf("| Total (Mean)          | %18v | %18v | %17.2fx |\n", coldTotal.Mean, warmTotal.Mean, speedupTotal)
	fmt.Printf("| Total (Median / p50)  | %18v | %18v | %17.2fx |\n", coldTotal.Median, warmTotal.Median, speedupMedian)
	fmt.Printf("| Total (p90)           | %18v | %18v | %17.2fx |\n", coldTotal.P90, warmTotal.P90, float64(coldTotal.P90)/float64(warmTotal.P90))
	fmt.Printf("| Total (p95)           | %18v | %18v | %17.2fx |\n", coldTotal.P95, warmTotal.P95, float64(coldTotal.P95)/float64(warmTotal.P95))
	fmt.Printf("| Total (p99)           | %18v | %18v | %17.2fx |\n", coldTotal.P99, warmTotal.P99, float64(coldTotal.P99)/float64(warmTotal.P99))
	fmt.Printf("| Total (Min .. Max)    | %9v..%-7v | %9v..%-7v |                    |\n", coldTotal.Min, coldTotal.Max, warmTotal.Min, warmTotal.Max)
	fmt.Printf("| Total (StdDev)        | %18v | %18v |                    |\n", coldTotal.StdDev, warmTotal.StdDev)
	fmt.Println("+-----------------------+--------------------+--------------------+--------------------+")
	fmt.Printf("OVERALL SPEEDUP [%s]: %.2fx faster (Mean total latency reduced by %.2f%%)\n", platformName, speedupTotal, reductionTotal)
	fmt.Println("==================================================================================")
}

func sleepSpecConfBench(t *testing.T, platformName string) (*specs.Spec, *config.Config) {
	conf := testutil.TestConfig(t)
	conf.Platform = platformName
	return testutil.NewSpecWithArgs("sleep", "1000"), conf
}

func execCombinedOutputBench(conf *config.Config, cont *Container, name string, arg ...string) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	args := &control.ExecArgs{
		Filename: name,
		Argv:     append([]string{name}, arg...),
		FilePayload: control.NewFilePayload(map[int]*os.File{
			0: os.Stdin, 1: w, 2: w,
		}, nil),
	}
	pid, err := cont.Execute(conf, args)
	if err != nil {
		w.Close()
		return nil, err
	}
	ws, err := cont.WaitPID(pid)
	w.Close()
	if err != nil {
		return nil, err
	}
	if !ws.Exited() {
		return nil, fmt.Errorf("process did not exit properly")
	}
	status := ws.ExitStatus()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return out, fmt.Errorf("exec failed, status: %v", status)
	}
	return out, nil
}

func runBenchmarkForPlatform(t *testing.T, platformName string) {
	iterations := *benchIterations
	if iterations <= 0 {
		iterations = 50
	}

	spec, conf := sleepSpecConfBench(t, platformName)
	var coldMetrics benchMetrics
	coldMetrics.Name = "Cold Start (Gofer Host Mount)"

	var warmMetrics benchMetrics
	warmMetrics.Name = "Warm Pool + Dynamic Mount (Gofer Host Mount)"

	// 1. Run Cold Start Benchmark (Creating and starting a new container per request).
	for i := 0; i < iterations; i++ {
		hostDir := filepath.Join(testutil.TmpDir(), fmt.Sprintf("cold-bench-%s-host-%d", platformName, i))
		if err := os.MkdirAll(hostDir, 0755); err != nil {
			t.Fatalf("failed to create host dir: %v", err)
		}
		hostFile := filepath.Join(hostDir, "payload.txt")
		if err := os.WriteFile(hostFile, []byte("benchmark payload data"), 0644); err != nil {
			t.Fatalf("failed to write payload: %v", err)
		}

		targetDir := filepath.Join(testutil.TmpDir(), fmt.Sprintf("cold-%s-target-%d", platformName, i))
		iterSpec := *spec
		iterSpec.Mounts = append(slices.Clone(spec.Mounts), specs.Mount{
			Type:        "bind",
			Source:      hostDir,
			Destination: targetDir,
		})

		tTotalStart := time.Now()

		// Setup phase: bundle + create container + start container.
		tSetupStart := time.Now()
		_, bundleDir, cleanup, err := testutil.SetupContainer(&iterSpec, conf)
		if err != nil {
			t.Fatalf("setup container: %v", err)
		}
		cArgs := Args{
			ID:        testutil.RandomContainerID(),
			Spec:      &iterSpec,
			BundleDir: bundleDir,
		}
		c, err := New(conf, cArgs)
		if err != nil {
			t.Fatalf("new container: %v", err)
		}
		if err := c.Start(conf); err != nil {
			t.Fatalf("start container: %v", err)
		}
		setupDur := time.Since(tSetupStart)

		// Exec phase: execute workload inside container.
		tExecStart := time.Now()
		guestFile := filepath.Join(targetDir, "payload.txt")
		out, err := execCombinedOutputBench(conf, c, "/bin/cat", guestFile)
		if err != nil || string(out) != "benchmark payload data" {
			t.Fatalf("exec workload failed: %v, out: %s", err, out)
		}
		execDur := time.Since(tExecStart)

		// Clean phase: destroy container + bundle.
		tCleanStart := time.Now()
		c.Destroy()
		cleanup()
		cleanDur := time.Since(tCleanStart)
		totalDur := time.Since(tTotalStart)

		coldMetrics.SetupLatencies = append(coldMetrics.SetupLatencies, setupDur)
		coldMetrics.ExecLatencies = append(coldMetrics.ExecLatencies, execDur)
		coldMetrics.CleanLatencies = append(coldMetrics.CleanLatencies, cleanDur)
		coldMetrics.TotalLatencies = append(coldMetrics.TotalLatencies, totalDur)
	}

	// 2. Run Warm Pool + Dynamic Mount Benchmark (Using 1 pre-warmed running sandbox).
	_, warmBundleDir, warmCleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("warm setup container: %v", err)
	}
	defer warmCleanup()

	warmArgs := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: warmBundleDir,
	}
	warmC, err := New(conf, warmArgs)
	if err != nil {
		t.Fatalf("new warm container: %v", err)
	}
	defer warmC.Destroy()
	if err := warmC.Start(conf); err != nil {
		t.Fatalf("start warm container: %v", err)
	}

	for i := 0; i < iterations; i++ {
		hostDir := filepath.Join(testutil.TmpDir(), fmt.Sprintf("warm-bench-%s-host-%d", platformName, i))
		if err := os.MkdirAll(hostDir, 0755); err != nil {
			t.Fatalf("failed to create warm host dir: %v", err)
		}
		hostFile := filepath.Join(hostDir, "payload.txt")
		if err := os.WriteFile(hostFile, []byte("benchmark payload data"), 0644); err != nil {
			t.Fatalf("failed to write warm payload: %v", err)
		}

		targetDir := filepath.Join(testutil.TmpDir(), fmt.Sprintf("warm-%s-target-%d", platformName, i))

		tTotalStart := time.Now()

		// Setup phase: Dynamic Mount of host directory via runsc mount CLI.
		tSetupStart := time.Now()
		mountCmd := exec.Command(specutils.ExePath, "--root", conf.RootDir, "mount", "-t", "gofer", warmC.ID, hostDir, targetDir)
		if out, err := mountCmd.CombinedOutput(); err != nil {
			t.Fatalf("dynamic mount failed: %v, out: %s", err, out)
		}
		setupDur := time.Since(tSetupStart)

		// Exec phase: execute workload inside container.
		tExecStart := time.Now()
		guestFile := filepath.Join(targetDir, "payload.txt")
		out, err := execCombinedOutputBench(conf, warmC, "/bin/cat", guestFile)
		if err != nil || string(out) != "benchmark payload data" {
			t.Fatalf("warm exec workload failed: %v, out: %s", err, out)
		}
		execDur := time.Since(tExecStart)

		// Clean phase: Dynamic Umount via runsc umount CLI.
		tCleanStart := time.Now()
		umountCmd := exec.Command(specutils.ExePath, "--root", conf.RootDir, "umount", warmC.ID, targetDir)
		if out, err := umountCmd.CombinedOutput(); err != nil {
			t.Fatalf("dynamic umount failed: %v, out: %s", err, out)
		}
		cleanDur := time.Since(tCleanStart)
		totalDur := time.Since(tTotalStart)

		warmMetrics.SetupLatencies = append(warmMetrics.SetupLatencies, setupDur)
		warmMetrics.ExecLatencies = append(warmMetrics.ExecLatencies, execDur)
		warmMetrics.CleanLatencies = append(warmMetrics.CleanLatencies, cleanDur)
		warmMetrics.TotalLatencies = append(warmMetrics.TotalLatencies, totalDur)
	}

	printBenchmarkReport(platformName, coldMetrics, warmMetrics)
}

// TestBenchmarkDynamicMountWarmPool runs latency comparisons across requested platforms.
func TestBenchmarkDynamicMountWarmPool(t *testing.T) {
	var ps []string
	if *platforms == "" {
		ps = []string{"systrap"}
	} else {
		ps = strings.Split(*platforms, ",")
	}
	for _, p := range ps {
		p = strings.TrimSpace(p)
		if p == "" || p == "ptrace" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			runBenchmarkForPlatform(t, p)
		})
	}
}
