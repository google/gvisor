// Copyright 2021 The gVisor Authors.
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

// Package worker provides an implementation of the bazel worker protocol.
//
// Tools may be written as a normal command line utility, except the passed
// run function may be invoked multiple times.
package worker

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "net/http/pprof" // For profiling.

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	wpb "gvisor.dev/bazel/worker_protocol_go_proto"
)

var (
	persistentWorker  = flag.Bool("persistent_worker", false, "enable persistent worker.")
	workerDebug       = flag.Bool("worker_debug", false, "debug persistent workers.")
	maximumCacheUsage = flag.Int64("maximum_cache_usage", 1024*1024*1024, "maximum cache size.")
)

var (
	// inputFiles is the last set of input files.
	//
	// This is used for cache invalidation. The key is the *absolute* path
	// name, and the value is the digest in the current run.
	inputFiles = make(map[string]string)

	// activeCaches is the set of active caches.
	activeCaches = make(map[*Cache]struct{})

	// totalCacheUsage is the total usage of all caches.
	totalCacheUsage int64
)

// mustAbs returns the absolute path of a filename or dies.
func mustAbs(filename string) string {
	abs, err := filepath.Abs(filename)
	if err != nil {
		log.Fatalf("error getting absolute path: %v", err)
	}
	return abs
}

// updateInputFiles creates an entry in inputFiles.
func updateInputFile(filename, digest string) {
	inputFiles[mustAbs(filename)] = digest
}

// Sizer returns a size.
type Sizer interface {
	Size() int64
}

// CacheBytes is an example of a Sizer.
type CacheBytes []byte

// Size implements Sizer.Size.
func (cb CacheBytes) Size() int64 {
	return int64(len(cb))
}

// Cache is a worker cache.
//
// They can be created via NewCache.
type Cache struct {
	name    string
	entries map[string]Sizer
	size    int64
	hits    int64
	misses  int64
}

// NewCache returns a new cache.
func NewCache(name string) *Cache {
	return &Cache{
		name: name,
	}
}

// Lookup looks up an entry in the cache.
//
// It is a function of the given files.
func (c *Cache) Lookup(filenames []string, generate func() Sizer) Sizer {
	digests := make([]string, 0, len(filenames))
	for _, filename := range filenames {
		digest, ok := inputFiles[mustAbs(filename)]
		if !ok {
			// This is not a valid input. We may not be running as
			// persistent worker in this cache. If that's the case,
			// then the file's contents will not change across the
			// run, and we just use the filename itself.
			digest = filename
		}
		digests = append(digests, digest)
	}

	// Attempt the lookup.
	sort.Slice(digests, func(i, j int) bool {
		return digests[i] < digests[j]
	})
	cacheKey := strings.Join(digests, "+")
	if c.entries == nil {
		c.entries = make(map[string]Sizer)
		activeCaches[c] = struct{}{}
	}
	entry, ok := c.entries[cacheKey]
	if ok {
		c.hits++
		return entry
	}

	// Generate a new entry.
	entry = generate()
	c.misses++
	c.entries[cacheKey] = entry
	if entry != nil {
		sz := entry.Size()
		c.size += sz
		totalCacheUsage += sz
	}

	// Check the capacity of all caches. If it greater than the maximum, we
	// flush everything but still return this entry.
	if totalCacheUsage > *maximumCacheUsage {
		for entry, _ := range activeCaches {
			// Drop all entries.
			entry.size = 0
			entry.entries = nil
		}
		totalCacheUsage = 0 // Reset.
	}

	return entry
}

// allCacheStats returns stats for all caches.
func allCacheStats() string {
	var sb strings.Builder
	for entry, _ := range activeCaches {
		ratio := float64(entry.hits) / float64(entry.hits+entry.misses)
		fmt.Fprintf(&sb,
			"% 10s: count: % 5d  size: % 10d  hits: % 7d  misses: % 7d  ratio: %2.2f\n",
			entry.name, len(entry.entries), entry.size, entry.hits, entry.misses, ratio)
	}
	if len(activeCaches) > 0 {
		fmt.Fprintf(&sb, "total: % 10d\n", totalCacheUsage)
	}
	return sb.String()
}

// LookupDigest returns a digest for the given file.
func LookupDigest(filename string) (string, bool) {
	digest, ok := inputFiles[filename]
	return digest, ok
}

// Work invokes the main function.
func Work(run func([]string) int) {
	flag.CommandLine.Parse(os.Args[1:])
	if !*persistentWorker {
		// Handle the argument file.
		args := flag.CommandLine.Args()
		if len(args) == 1 && len(args[0]) > 1 && args[0][0] == '@' {
			content, err := ioutil.ReadFile(args[0][1:])
			if err != nil {
				log.Fatalf("unable to parse args file: %v", err)
			}
			// Pull arguments from the file.
			args = strings.Split(string(content), "\n")
			flag.CommandLine.Parse(args)
			args = flag.CommandLine.Args()
		}
		os.Exit(run(args))
	}

	var listenHeader string // Emitted always.
	if *workerDebug {
		// Bind a server for profiling.
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			log.Fatalf("unable to bind a server: %v", err)
		}
		// Construct the header for stats output, below.
		listenHeader = fmt.Sprintf("Listening @ http://localhost:%d\n", listener.Addr().(*net.TCPAddr).Port)
		go http.Serve(listener, nil)
	}

	// Move stdout. This is done to prevent anything else from accidentally
	// printing to stdout, which must contain only the valid WorkerResponse
	// serialized protos.
	newOutput, err := unix.Dup(1)
	if err != nil {
		log.Fatalf("unable to move stdout: %v", err)
	}
	// Stderr may be closed or may be a copy of stdout. We make sure that
	// we have an output that is in a completely separate range.
	for newOutput <= 2 {
		newOutput, err = unix.Dup(newOutput)
		if err != nil {
			log.Fatalf("unable to move stdout: %v", err)
		}
	}

	// Best-effort: collect logs.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		log.Fatalf("unable to create pipe: %v", err)
	}
	if err := unix.Dup2(int(wPipe.Fd()), 1); err != nil {
		log.Fatalf("error duping over stdout: %v", err)
	}
	if err := unix.Dup2(int(wPipe.Fd()), 2); err != nil {
		log.Fatalf("error duping over stderr: %v", err)
	}
	wPipe.Close()
	defer rPipe.Close()

	// Read requests from stdin.
	input := bufio.NewReader(os.NewFile(0, "input"))
	output := bufio.NewWriter(os.NewFile(uintptr(newOutput), "output"))
	for {
		szBuf, err := input.Peek(4)
		if err != nil {
			log.Fatalf("unabel to read header: %v", err)
		}

		// Parse the size, and discard bits.
		sz, szBytes := protowire.ConsumeVarint(szBuf)
		if szBytes < 0 {
			szBytes = 0
		}
		if _, err := input.Discard(szBytes); err != nil {
			log.Fatalf("error discarding size: %v", err)
		}

		// Read a full message.
		msg := make([]byte, int(sz))
		if _, err := io.ReadFull(input, msg); err != nil {
			log.Fatalf("error reading worker request: %v", err)
		}
		var wreq wpb.WorkRequest
		if err := proto.Unmarshal(msg, &wreq); err != nil {
			log.Fatalf("error unmarshaling worker request: %v", err)
		}

		// Flush relevant caches.
		inputFiles = make(map[string]string)
		for _, input := range wreq.GetInputs() {
			updateInputFile(input.GetPath(), string(input.GetDigest()))
		}

		// Prepare logging.
		outputBuffer := bytes.NewBuffer(nil)
		outputBuffer.WriteString(listenHeader)
		log.SetOutput(outputBuffer)

		// Parse all arguments.
		flag.CommandLine.Parse(wreq.GetArguments())
		var exitCode int
		exitChan := make(chan int)
		go func() { exitChan <- run(flag.CommandLine.Args()) }()
		for running := true; running; {
			select {
			case exitCode = <-exitChan:
				running = false
			default:
			}
			// N.B. rPipe is given a read deadline of 1ms. We expect
			// this to turn a copy error after 1ms, and we just keep
			// flushing this buffer while the task is running.
			rPipe.SetReadDeadline(time.Now().Add(time.Millisecond))
			outputBuffer.ReadFrom(rPipe)
		}

		if *workerDebug {
			// Attach all cache stats.
			outputBuffer.WriteString(allCacheStats())
		}

		// Send the response.
		var wresp wpb.WorkResponse
		wresp.ExitCode = int32(exitCode)
		wresp.Output = string(outputBuffer.Bytes())
		rmsg, err := proto.Marshal(&wresp)
		if err != nil {
			log.Fatalf("error marshaling response: %v", err)
		}
		if _, err := output.Write(append(protowire.AppendVarint(nil, uint64(len(rmsg))), rmsg...)); err != nil {
			log.Fatalf("error sending worker response: %v", err)
		}
		if err := output.Flush(); err != nil {
			log.Fatalf("error flushing output: %v", err)
		}
	}
}
