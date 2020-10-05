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

// Package coverage provides an interface through which Go coverage data can
// be collected, converted to kcov format, and exposed to userspace.
//
// Coverage can be enabled by calling bazel {build,test} with
// --collect_coverage_data and --instrumentation_filter with the desired
// coverage surface. This causes bazel to use the Go cover tool manually to
// generate instrumented files. It injects a hook that registers all coverage
// data with the coverdata package.
package coverage

import (
	"fmt"
	"io"
	"sort"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"

	"github.com/bazelbuild/rules_go/go/tools/coverdata"
)

// KcovAvailable returns whether the kcov coverage interface is available. It is
// available as long as coverage is enabled for some files.
func KcovAvailable() bool {
	return len(coverdata.Cover.Blocks) > 0
}

// coverageMu must be held while accessing coverdata.Cover. This prevents
// concurrent reads/writes from multiple threads collecting coverage data.
var coverageMu sync.RWMutex

// once ensures that globalData is only initialized once.
var once sync.Once

var globalData struct {
	// files is the set of covered files sorted by filename. It is calculated at
	// startup.
	files []string

	// syntheticPCs are a set of PCs calculated at startup, where the PC
	// at syntheticPCs[i][j] corresponds to file i, block j.
	syntheticPCs [][]uint64
}

// ClearCoverageData clears existing coverage data.
func ClearCoverageData() {
	coverageMu.Lock()
	defer coverageMu.Unlock()
	for _, counters := range coverdata.Cover.Counters {
		for index := 0; index < len(counters); index++ {
			atomic.StoreUint32(&counters[index], 0)
		}
	}
}

var coveragePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0)
	},
}

// ConsumeCoverageData builds and writes the collection of covered PCs. It
// returns the number of bytes written.
//
// In Linux, a kernel configuration is set that compiles the kernel with a
// custom function that is called at the beginning of every basic block, which
// updates the memory-mapped coverage information. The Go coverage tool does not
// allow us to inject arbitrary instructions into basic blocks, but it does
// provide data that we can convert to a kcov-like format and transfer them to
// userspace through a memory mapping.
//
// Note that this is not a strict implementation of kcov, which is especially
// tricky to do because we do not have the same coverage tools available in Go
// that that are available for the actual Linux kernel. In Linux, a kernel
// configuration is set that compiles the kernel with a custom function that is
// called at the beginning of every basic block to write program counters to the
// kcov memory mapping. In Go, however, coverage tools only give us a count of
// basic blocks as they are executed. Every time we return to userspace, we
// collect the coverage information and write out PCs for each block that was
// executed, providing userspace with the illusion that the kcov data is always
// up to date. For convenience, we also generate a unique synthetic PC for each
// block instead of using actual PCs. Finally, we do not provide thread-specific
// coverage data (each kcov instance only contains PCs executed by the thread
// owning it); instead, we will supply data for any file specified by --
// instrumentation_filter.
//
// Note that we "consume", i.e. clear, coverdata when this function is run, to
// ensure that each event is only reported once. Due to the limitations of Go
// coverage tools, we reset the global coverage data every time this function is
// run.
func ConsumeCoverageData(w io.Writer) int {
	once.Do(initCoverageData)

	coverageMu.Lock()
	defer coverageMu.Unlock()

	total := 0
	var pcBuffer [8]byte
	for fileIndex, file := range globalData.files {
		counters := coverdata.Cover.Counters[file]
		for index := 0; index < len(counters); index++ {
			if atomic.LoadUint32(&counters[index]) == 0 {
				continue
			}
			// Non-zero coverage data found; consume it and report as a PC.
			atomic.StoreUint32(&counters[index], 0)
			pc := globalData.syntheticPCs[fileIndex][index]
			usermem.ByteOrder.PutUint64(pcBuffer[:], pc)
			n, err := w.Write(pcBuffer[:])
			if err != nil {
				if err == io.EOF {
					// Simply stop writing if we encounter EOF; it's ok if we attempted to
					// write more than we can hold.
					return total + n
				}
				panic(fmt.Sprintf("Internal error writing PCs to kcov area: %v", err))
			}
			total += n
		}
	}

	if total == 0 {
		// An empty profile indicates that coverage is not enabled, in which case
		// there shouldn't be any task work registered.
		panic("kcov task work is registered, but no coverage data was found")
	}
	return total
}

// initCoverageData initializes globalData. It should only be called once,
// before any kcov data is written.
func initCoverageData() {
	// First, order all files. Then calculate synthetic PCs for every block
	// (using the well-defined ordering for files as well).
	for file := range coverdata.Cover.Blocks {
		globalData.files = append(globalData.files, file)
	}
	sort.Strings(globalData.files)

	// nextSyntheticPC is the first PC that we generate for a block.
	//
	// This uses a standard-looking kernel range for simplicity.
	//
	// FIXME(b/160639712): This is only necessary because syzkaller requires
	// addresses in the kernel range. If we can remove this constraint, then we
	// should be able to use the actual addresses.
	var nextSyntheticPC uint64 = 0xffffffff80000000
	for _, file := range globalData.files {
		blocks := coverdata.Cover.Blocks[file]
		thisFile := make([]uint64, 0, len(blocks))
		for range blocks {
			thisFile = append(thisFile, nextSyntheticPC)
			nextSyntheticPC++ // Advance.
		}
		globalData.syntheticPCs = append(globalData.syntheticPCs, thisFile)
	}
}
