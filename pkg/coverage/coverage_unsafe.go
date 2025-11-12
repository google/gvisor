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

//go:build kcov && opensource
// +build kcov,opensource

// Package coverage provides an interface through which Go coverage data can
// be collected, converted to kcov format, and exposed to userspace.
//
// Coverage can be enabled by calling bazel {build,test} with
// --collect_coverage_data and --instrumentation_filter with the desired
// coverage surface. This causes bazel to use the Go cover tool manually to
// generate instrumented files. It injects a hook that registers all coverage
// data with the coverdata package.
//
// Using coverdata.Counters requires sync/atomic integers.
// +checkalignedignore
package coverage

import (
	"bytes"
	"fmt"
	icov "internal/coverage"
	"internal/coverage/cfile"
	"internal/coverage/decodecounter"
	"internal/coverage/decodemeta"
	"internal/coverage/rtcov"
	"io"
	"runtime/coverage"
	"unsafe"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// coverageMu must be held while accessing coverdata.*. This prevents
	// concurrent reads/writes from multiple threads collecting coverage data.
	coverageMu sync.RWMutex

	// reportOutput is the place to write out a coverage report. It should be
	// closed after the report is written. It is protected by reportOutputMu.
	reportOutput   io.WriteCloser
	reportOutputMu sync.Mutex
)

// blockBitLength is the number of bits used to represent coverage block index
// in a synthetic PC (the rest are used to represent the file index). Even
// though a PC has 64 bits, we only use the lower 32 bits because some users
// (e.g., syzkaller) may truncate that address to a 32-bit value.
//
// As of this writing, there are ~1200 files that can be instrumented and at
// most ~1200 blocks per file, so 16 bits is more than enough to represent every
// file and every block.
const blockBitLength = 16

// Available returns whether any coverage data is available.
func Available() bool {
	InitCoverageData()
	return len(globalData.pkgs) > 0
}

// EnableReport sets up coverage reporting.
func EnableReport(w io.WriteCloser) {
	reportOutputMu.Lock()
	defer reportOutputMu.Unlock()
	reportOutput = w
}

// KcovSupported returns whether the kcov interface should be made available.
//
// If coverage reporting is on, do not turn on kcov, which will consume
// coverage data.
func KcovSupported() bool {
	return (reportOutput == nil) && Available()
}

var globalData struct {
	pkgs map[uint32]*pkg

	// once ensures that globalData is only initialized once.
	once sync.Once
}

// ClearCoverageData clears existing coverage data.
//
//go:norace
func ClearCoverageData() {
	coverageMu.Lock()
	defer coverageMu.Unlock()

	coverage.ClearCounters()
}

var coveragePool = sync.Pool{
	New: func() any {
		return make([]byte, 0)
	},
}

// fileBuffer implements io.ReadWriteSeeker.
type fileBuffer struct {
	buffer []byte
	offset int64
}

// Bytes implements io.ReadWriteSeeker.Bytes.
func (fb *fileBuffer) Bytes() []byte {
	return fb.buffer
}

// Len implements io.ReadWriteSeeker.Len.
func (fb *fileBuffer) Len() int {
	return len(fb.buffer)
}

// Write implements io.ReadWriteSeeker.Write.
func (fb *fileBuffer) Read(b []byte) (int, error) {
	available := len(fb.buffer) - int(fb.offset)
	if available == 0 {
		return 0, io.EOF
	}
	size := len(b)
	if size > available {
		size = available
	}
	copy(b, fb.buffer[fb.offset:fb.offset+int64(size)])
	fb.offset += int64(size)
	return size, nil
}

// Write implements io.ReadWriteSeeker.Write.
func (fb *fileBuffer) Write(b []byte) (int, error) {
	copied := copy(fb.buffer[fb.offset:], b)
	if copied < len(b) {
		fb.buffer = append(fb.buffer, b[copied:]...)
	}
	fb.offset += int64(len(b))
	return len(b), nil
}

// Seek implements io.ReadWriteSeeker.Seek.
func (fb *fileBuffer) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = fb.offset + offset
	case io.SeekEnd:
		newOffset = int64(len(fb.buffer)) + offset
	default:
		return 0, fmt.Errorf("unknown seek method: %v", whence)
	}
	if newOffset > int64(len(fb.buffer)) || newOffset < 0 {
		return 0, fmt.Errorf("invalid offset %d", offset)
	}
	fb.offset = newOffset
	return newOffset, nil
}

//go:linkname getCovCounterList
func getCovCounterList() []rtcov.CovCounterBlob

type pkg struct {
	funcs map[uint32]icov.FuncDesc
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
//
//go:norace
func ConsumeCoverageData(w io.Writer) int {
	total := 0
	var pcBuffer [8]byte

	consumeCoverageData(func(pc uint64) bool {
		hostarch.ByteOrder.PutUint64(pcBuffer[:], pc)
		n, err := w.Write(pcBuffer[:])
		if err != nil {
			if err == io.EOF {
				// Simply stop writing if we encounter EOF; it's ok if we attempted to
				// write more than we can hold.
				total += n
				return false
			}
			panic(fmt.Sprintf("Internal error writing PCs to kcov area: %v", err))
		}
		total += n
		return true
	})

	return total
}

func consumeCoverageData(handler func(pc uint64) bool) {
	InitCoverageData()

	coverageMu.Lock()
	defer coverageMu.Unlock()

	var buf bytes.Buffer
	var writer io.Writer = &buf
	err := coverage.WriteCounters(writer)
	if err != nil {
		log.Warningf("coverage.WriteCounters failed: %s", err)
		return
	}
	coverage.ClearCounters()

	fb := fileBuffer{buffer: buf.Bytes()}
	cdr, err := decodecounter.NewCounterDataReader("cover", &fb)
	if err != nil {
		log.Warningf("decodecounter.NewCounterDataReader failed: %s", err)
		return
	}

	var data decodecounter.FuncPayload
	for {
		ok, err := cdr.NextFunc(&data)
		if err != nil {
			panic(fmt.Sprintf("CounterDataReader.NextFunc failed: %s", err))
		}
		if !ok {
			break
		}
		for i := 0; i < len(data.Counters); i++ {
			if data.Counters[i] == 0 {
				continue
			}
			pc := calculateSyntheticPC(data.PkgIdx, data.FuncIdx, i)
			if !handler(pc) {
				return
			}
		}
	}
	return
}

// InitCoverageData initializes globalData. It should be called before any kcov
// data is written.
func InitCoverageData() {
	globalData.once.Do(func() {
		cfile.InitHook(false)
		globalData.pkgs = make(map[uint32]*pkg)
		ml := rtcov.Meta.List
		for k, b := range ml {
			byteSlice := unsafe.Slice(b.P, b.Len)
			p := pkg{}
			globalData.pkgs[uint32(k)] = &p
			p.funcs = make(map[uint32]icov.FuncDesc)
			pd, err := decodemeta.NewCoverageMetaDataDecoder(byteSlice, true)
			if err != nil {
				panic(fmt.Sprintf("decodemeta.NewCoverageMetaDataDecoder failed: %s", err))
			}
			var fd icov.FuncDesc
			nf := pd.NumFuncs()
			for fidx := uint32(0); fidx < nf; fidx++ {
				if err := pd.ReadFunc(fidx, &fd); err != nil {
					panic(fmt.Sprintf("reading meta-data file: %s", err))
				}
				p.funcs[fidx] = fd
			}

		}
	})
}

// reportOnce ensures that a coverage report is written at most once. For a
// complete coverage report, Report should be called during the sandbox teardown
// process. Report is called from multiple places (which may overlap) so that a
// coverage report is written in different sandbox exit scenarios.
var reportOnce sync.Once

// Report writes out a coverage report with all blocks that have been covered.
//
// TODO(b/144576401): Decide whether this should actually be in LCOV format
func Report() error {
	if reportOutput == nil {
		return nil
	}

	var err error
	reportOnce.Do(func() {
		consumeCoverageData(func(pc uint64) bool {
			err = symbolize(reportOutput, pc)
			return err == nil
		})
		reportOutput.Close()
	})
	return err
}

// Symbolize prints information about the block corresponding to pc.
func Symbolize(out io.Writer, pc uint64) error {
	if _, err := io.WriteString(out, fmt.Sprintf("%#x\n", pc)); err != nil {
		return err
	}
	return symbolize(out, pc)
}

func symbolize(out io.Writer, pc uint64) error {
	pkgIdx, funcIdx, idx := syntheticPCToIndexes(pc)
	p := globalData.pkgs[uint32(pkgIdx)]
	fd := p.funcs[uint32(funcIdx)]
	u := fd.Units[idx]
	_, err := io.WriteString(out, fmt.Sprintf("%s:%d.%d,%d.%d\n", fd.Srcfile, u.StLine, u.StCol, u.EnLine, u.EnCol))
	return err
}

// WriteAllBlocks prints all information about all blocks along with their
// corresponding synthetic PCs.
func WriteAllBlocks(out io.Writer) error {
	for pkgIdx, p := range globalData.pkgs {
		for funcIdx, fd := range p.funcs {
			for idx := range fd.Units {
				pc := calculateSyntheticPC(pkgIdx, funcIdx, idx)
				err := Symbolize(out, pc)
				if err != nil {
					return err
				}

			}
		}
	}
	return nil
}

const (
	blockIdxBits = 8
	funcIdxBits  = 12
	pkgIdxShift  = funcIdxBits + blockIdxBits
	funcIdxShift = blockIdxBits
	blockIdxMask = (1 << blockIdxBits) - 1
	funcIdxMask  = (1 << funcIdxBits) - 1
)

func calculateSyntheticPC(pkgIdx uint32, funcIdx uint32, blockIdx int) uint64 {
	pc := uint64(blockIdx) | (uint64(funcIdx) << funcIdxShift) | (uint64(pkgIdx) << pkgIdxShift)
	return ^pc
}

func syntheticPCToIndexes(pc uint64) (pkgIdx uint32, funcIdx uint32, blockIdx int) {
	pc = ^pc
	blockIdx = int(pc & blockIdxMask)
	funcIdx = uint32((pc >> funcIdxShift) & funcIdxMask)
	pkgIdx = uint32(pc >> pkgIdxShift)
	return
}
