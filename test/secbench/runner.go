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

// The runner binary executes a single benchmark run and prints out results.
// Because seccomp-bpf filters cannot be removed from a process, this runs as
// a subprocess of the secbench library.
// This requires the ability to write(2) to stdout even after installing the
// seccomp-bpf filter.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/test/secbench/secbenchdef"
)

// install installs the given program on the runner.
func install(program []bpf.Instruction) error {
	// Rewrite the program so that all return actions are either ALLOW or
	// RET_ERRNO. This allows us to benchmark the program without worrying
	// that we'll crash if we call a bad system call.
	rewritten := make([]bpf.Instruction, len(program))
	copy(rewritten, program)
	for pc, ins := range rewritten {
		switch ins.OpCode {
		case bpf.Ret | bpf.A:
			// Override the return action value to RET_ERRNO.
			ins.K = uint32(linux.SECCOMP_RET_ERRNO)
		case bpf.Ret | bpf.K:
			switch linux.BPFAction(ins.K) {
			case linux.SECCOMP_RET_ALLOW, linux.SECCOMP_RET_ERRNO:
				// Do nothing.
			default:
				// Override the return action value to RET_ERRNO.
				ins.K = uint32(linux.SECCOMP_RET_ERRNO)
			}
		default:
			// Do nothing.
		}
		rewritten[pc] = ins
	}
	return seccomp.SetFilter(rewritten)
}

// run runs a Bench request.
func run(req secbenchdef.BenchRunRequest) (secbenchdef.BenchRunResponse, error) {
	bn := req.Bench
	rng := rand.New(rand.NewSource(req.RandomSeed))

	sequenceMetrics := make([]secbenchdef.SequenceMetrics, len(bn.Profile.Sequences))
	var totalWeight int
	for _, seq := range bn.Profile.Sequences {
		if seq.Weight < 0 {
			return secbenchdef.BenchRunResponse{}, fmt.Errorf("weight of sequence %v cannot be zero or negative: %d", seq, seq.Weight)
		}
		totalWeight += seq.Weight
	}

	// We're ready. Install the BPF program.
	if req.InstallFilter {
		if err := install(bn.Instructions); err != nil {
			panic(fmt.Sprintf("cannot install BPF program: %v", err))
		}
	}

	var (
		before, after            int64
		si, seqIndex, randWeight int
		seq                      secbenchdef.Sequence
		seqSyscalls              []secbenchdef.Syscall
		sc                       secbenchdef.Syscall
		duration, totalNanos     uint64
	)
	for i := uint64(0); i < req.Iterations; i++ {
		randWeight = rng.Intn(totalWeight)
		seqIndex = -1
		for si, seq = range bn.Profile.Sequences {
			if randWeight -= seq.Weight; randWeight < 0 {
				seqIndex = si
				break
			}
		}
		if seqIndex == -1 {
			panic("logic error in weight randomization")
		}
		if !req.ActiveSequences[seqIndex] {
			continue
		}
		seqSyscalls = bn.Profile.Sequences[seqIndex].Syscalls
		if len(seqSyscalls) == 1 {
			// If we have only one syscall to call (common), measure this directly to
			// avoid measuring the loop overhead.
			sc = seqSyscalls[0]
			before = gohacks.Nanotime()
			sc.Call()
			after = gohacks.Nanotime()
		} else {
			before = gohacks.Nanotime()
			for _, sc = range seqSyscalls {
				sc.Call()
			}
			after = gohacks.Nanotime()
		}
		duration = uint64(after - before)
		sequenceMetrics[seqIndex].Iterations++
		sequenceMetrics[seqIndex].TotalNanos += duration
		totalNanos += duration
	}

	return secbenchdef.BenchRunResponse{
		TotalNanos:      totalNanos,
		SequenceMetrics: sequenceMetrics,
	}, nil
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Sprintf("cannot read from stdin: %v", err))
	}
	var runReq secbenchdef.BenchRunRequest
	if err = json.Unmarshal(data, &runReq); err != nil {
		panic(fmt.Sprintf("cannot deserialize bench data: %v", err))
	}
	resp, err := run(runReq)
	if err != nil {
		panic(fmt.Sprintf("cannot run bench: %v", err))
	}
	respData, err := json.Marshal(&resp)
	if err != nil {
		panic(fmt.Sprintf("cannot serialize bench response: %v", err))
	}
	if _, err := os.Stdout.Write(respData); err != nil {
		panic(fmt.Sprintf("cannot write response to stdout: %v", err))
	}
	os.Stdout.Close()
}
