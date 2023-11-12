// Copyright 2023 The gVisor Authors.
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

// Package secbench provides utilities for benchmarking seccomp-bpf filters.
package secbench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/secbench/secbenchdef"
)

// BenchFromSyscallRules returns a new Bench created from SyscallRules.
func BenchFromSyscallRules(b *testing.B, name string, profile secbenchdef.Profile, rules seccomp.SyscallRules, denyRules seccomp.SyscallRules) secbenchdef.Bench {
	// If there is a rule allowing rt_sigreturn to be called,
	// also add a rule for the stand-in syscall number instead.
	if rules.Has(unix.SYS_RT_SIGRETURN) {
		rules = rules.Copy()
		rules.Set(uintptr(secbenchdef.RTSigreturn.Data(profile.Arch).Nr), rules.Get(unix.SYS_RT_SIGRETURN))
	}
	insns, buildStats, err := seccomp.BuildProgram([]seccomp.RuleSet{
		{
			Rules:  denyRules,
			Action: linux.SECCOMP_RET_ERRNO,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, seccomp.ProgramOptions{
		DefaultAction: linux.SECCOMP_RET_ERRNO,
		BadArchAction: linux.SECCOMP_RET_ERRNO,
	})
	if err != nil {
		b.Fatalf("BuildProgram() failed: %v", err)
	}
	return secbenchdef.Bench{
		Name:         name,
		Profile:      secbenchdef.Profile(profile),
		Instructions: insns,
		BuildStats:   buildStats,
	}
}

func runRequest(runReq secbenchdef.BenchRunRequest) (secbenchdef.BenchRunResponse, error) {
	runReqData, err := json.Marshal(&runReq)
	if err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot serialize benchmark run request: %v", err)
	}
	runnerPath, err := testutil.FindFile("test/secbench/runner")
	if err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot find runner binary: %v", err)
	}
	cmd := exec.Command(runnerPath)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot attach pipe to stdin: %v", err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot attach pipe to stdout: %v", err)
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot start runner: %v", err)
	}
	if _, err := stdin.Write(runReqData); err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot write benchmark instructions to runner: %v", err)
	}
	if err := stdin.Close(); err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot close runner stdin pipe: %v", err)
	}
	stdoutData, err := io.ReadAll(stdout)
	if err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("failed to read from runner stdout: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("runner failed: %v", err)
	}
	var runResp secbenchdef.BenchRunResponse
	if err := json.Unmarshal(stdoutData, &runResp); err != nil {
		return secbenchdef.BenchRunResponse{}, fmt.Errorf("cannot unmarshal response: %v", err)
	}
	return runResp, nil
}

func evalSyscall(program bpf.Program, arch uint32, sc secbenchdef.Syscall, buf []byte) (uint32, error) {
	return bpf.Exec[bpf.NativeEndian](program, seccomp.DataAsBPFInput(&linux.SeccompData{
		Nr:   int32(sc.Sysno),
		Arch: arch,
		Args: [6]uint64{
			uint64(sc.Args[0]),
			uint64(sc.Args[1]),
			uint64(sc.Args[2]),
			uint64(sc.Args[3]),
			uint64(sc.Args[4]),
			uint64(sc.Args[5]),
		},
	}, buf))
}

// Number of times we scale b.N by.
// Without this, a single iteration would be meaningless.
// Since the benchmark always runs with a single iteration first,
// we scale it so that even a single iteration means something.
const iterationScaleFactor = 128

// RunBench runs a single Bench.
func RunBench(b *testing.B, bn secbenchdef.Bench) {
	b.Helper()
	b.Run(bn.Name, func(b *testing.B) {
		randSeed := time.Now().UnixNano()
		b.Logf("Running with %d iterations (scaled by %dx), random seed %d...", b.N, iterationScaleFactor, randSeed)
		iterations := uint64(b.N * iterationScaleFactor)
		buf := make([]byte, (&linux.SeccompData{}).SizeBytes())

		// Check if there are any sequences where the syscall will be approved.
		// If there is any, we will need to run the runner twice: Once with the
		// filter, once without. Then we will compute the difference between the
		// two runs.
		// If there are no syscall sequences that will be approved, then we can
		// skip running the runner the second time altogether.
		program, err := bpf.Compile(bn.Instructions, true /* optimize */)
		if err != nil {
			b.Fatalf("program does not compile: %v", err)
		}
		b.ReportMetric(float64(bn.BuildStats.BuildDuration.Nanoseconds()), "build-ns")
		b.ReportMetric(float64(bn.BuildStats.RuleOptimizeDuration.Nanoseconds()), "ruleopt-ns")
		b.ReportMetric(float64(bn.BuildStats.BPFOptimizeDuration.Nanoseconds()), "bpfopt-ns")
		b.ReportMetric(float64((bn.BuildStats.RuleOptimizeDuration + bn.BuildStats.BPFOptimizeDuration).Nanoseconds()), "opt-ns")
		b.ReportMetric(float64(bn.BuildStats.SizeBeforeOptimizations), "gen-instr")
		b.ReportMetric(float64(bn.BuildStats.SizeAfterOptimizations), "opt-instr")
		b.ReportMetric(float64(bn.BuildStats.SizeBeforeOptimizations)/float64(bn.BuildStats.SizeAfterOptimizations), "compression-ratio")
		activeSequences := make([]bool, len(bn.Profile.Sequences))
		positiveSequenceIndexes := make(map[int]struct{}, len(bn.Profile.Sequences))
		for i, seq := range bn.Profile.Sequences {
			result := int64(-1)
			for _, sc := range seq.Syscalls {
				scResult, err := evalSyscall(program, bn.Profile.Arch, sc, buf)
				if err != nil {
					b.Fatalf("cannot eval program with syscall %v: %v", sc, err)
				}
				if result == -1 {
					result = int64(scResult)
				} else if result != int64(scResult) {
					b.Fatalf("sequence %v has incoherent syscall return results: %v vs %v", seq, result, scResult)
				}
			}
			if result == -1 {
				b.Fatalf("sequence %v is empty", seq)
			}
			if linux.BPFAction(result) == linux.SECCOMP_RET_ALLOW {
				positiveSequenceIndexes[i] = struct{}{}
			} else if !bn.AllowRejected {
				b.Fatalf("sequence %v is disallowed (%v), but AllowRejected is false", seq, result)
			}
			activeSequences[i] = true
		}

		// Run the runner with the seccomp filter.
		runReq := secbenchdef.BenchRunRequest{
			Bench:           bn,
			Iterations:      iterations,
			ActiveSequences: activeSequences,
			RandomSeed:      randSeed,
			InstallFilter:   true,
		}
		runResp, err := runRequest(runReq)
		if err != nil {
			b.Fatalf("cannot run benchmark with the filter: %v", err)
		}

		// Now run the runner without the seccomp filter, if necessary.
		coherent := true
		if len(positiveSequenceIndexes) > 0 {
			onlyPositiveSequences := make([]bool, len(activeSequences))
			copy(onlyPositiveSequences, activeSequences)
			for i := range bn.Profile.Sequences {
				if _, found := positiveSequenceIndexes[i]; !found {
					onlyPositiveSequences[i] = false
				}
			}
			noFilterReq := runReq
			noFilterReq.ActiveSequences = onlyPositiveSequences
			noFilterReq.InstallFilter = false
			b.Logf("Running allowed sequences only (%v), without the filter...", onlyPositiveSequences)
			noFilterResp, err := runRequest(noFilterReq)
			if err != nil {
				b.Fatalf("cannot run benchmark without the filter: %v", err)
			}
			if noFilterResp.TotalNanos >= runResp.TotalNanos {
				// This can happen for low iteration numbers where noise is high, so
				// don't treat this as fatal.
				b.Logf(
					"It took us %v to run with filter, but %v without filter => run is incoherent",
					time.Duration(runResp.TotalNanos)*time.Nanosecond,
					time.Duration(noFilterResp.TotalNanos)*time.Nanosecond,
				)
				coherent = false
			} else {
				b.Logf(
					"Reducing total runtime (%v with filter) by %v without filter => %v for filter evaluation time",
					time.Duration(runResp.TotalNanos)*time.Nanosecond,
					time.Duration(noFilterResp.TotalNanos)*time.Nanosecond,
					time.Duration(runResp.TotalNanos-noFilterResp.TotalNanos)*time.Nanosecond,
				)
				runResp.TotalNanos -= noFilterResp.TotalNanos
				for i := range onlyPositiveSequences {
					// Same.
					if noFilterResp.SequenceMetrics[i].TotalNanos >= runResp.SequenceMetrics[i].TotalNanos {
						b.Logf(
							"Sequence %v took %v to run with filter, but %v without filter => sequence is incoherent",
							bn.Profile.Sequences[i],
							time.Duration(runResp.SequenceMetrics[i].TotalNanos)*time.Nanosecond,
							time.Duration(noFilterResp.SequenceMetrics[i].TotalNanos)*time.Nanosecond,
						)
						// Invalidate the data by setting it to zero.
						runResp.SequenceMetrics[i].TotalNanos = 0
						runResp.SequenceMetrics[i].Iterations = 0
					} else {
						b.Logf(
							"Reducing sequence %v runtime (%v with filter) by %v without filter => %v for filter evaluation time",
							bn.Profile.Sequences[i],
							time.Duration(runResp.SequenceMetrics[i].TotalNanos)*time.Nanosecond,
							time.Duration(noFilterResp.SequenceMetrics[i].TotalNanos)*time.Nanosecond,
							time.Duration(runResp.SequenceMetrics[i].TotalNanos-noFilterResp.SequenceMetrics[i].TotalNanos)*time.Nanosecond,
						)
						runResp.SequenceMetrics[i].TotalNanos -= noFilterResp.SequenceMetrics[i].TotalNanos
					}
				}
			}
		}

		if coherent {
			// Report results.
			if !bn.AllowRejected {
				b.ReportMetric(float64(runResp.TotalNanos)/float64(iterations), "ns/op")
			} else {
				// Suppress default metric.
				b.ReportMetric(0, "ns/op")
			}
			for i, seq := range bn.Profile.Sequences {
				seqData := runResp.SequenceMetrics[i]
				if seqData.Iterations < 100 {
					// Too small number of attempts for this number to be precise, or
					// invalidated earlier due to incoherence. Skip.
					continue
				}
				// We don't use b.ReportMetric here because the number of iterations
				// would be incorrect.
				fmt.Fprintf(os.Stdout, "%s/%s %d %v ns/op\n", b.Name(), seq.Name, seqData.Iterations, float64(seqData.TotalNanos)/float64(seqData.Iterations))
			}
		} else {
			// Suppress default metric, which is useless for us here.
			b.ReportMetric(0, "ns/op")
		}
	})
}

// Run runs a set of Benches.
func Run(b *testing.B, bns ...secbenchdef.Bench) {
	b.Helper()
	for _, bn := range bns {
		RunBench(b, bn)
	}
	b.ReportMetric(0, "ns/op")
}
