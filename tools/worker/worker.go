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
	"sync"

	_ "net/http/pprof" // For profiling.

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	wpb "gvisor.dev/bazel/worker_protocol_go_proto"
	"gvisor.dev/gvisor/runsc/flag"
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
)

// LookupDigest returns a digest for the given file.
func LookupDigest(filename string) (string, bool) {
	digest, ok := inputFiles[filename]
	return digest, ok
}

var (
	// allCaches is a global list of caches.
	allCaches cachesList

	// globalMu is a globalMutex for globalLRU.
	//
	// Note that this has a strict lock ordering requirement. No cache locks
	// may be held when acquiring this lock.
	globalMu sync.Mutex

	// globalLRU is a globalLRU for all entries.
	//
	// Protected by globalMu.
	globalLRU lruList

	// totalCacheUsage is the total usage of all caches.
	//
	// Protected by globalMu.
	totalCacheUsage int64
)

// Sizer returns a size.
type Sizer interface {
	Size() int64
}

// cacheEntry is a cache entry.
//
// The cacheEntry object is immutable, with the exception of the ready
// WaitGroup, which may be signalled.
type cacheEntry struct {
	cache    *Cache
	key      string
	sizer    Sizer
	err      error
	ready    sync.WaitGroup
	lruEntry // in globalLRU.
}

// Cache is a worker cache.
//
// They can be created via NewCache.
type Cache struct {
	name        string
	mu          sync.Mutex
	entries     map[string]*cacheEntry
	size        int64
	hits        int64
	misses      int64
	cachesEntry // in allCaches.
}

// NewCache returns a new cache.
//
// Precondition: this must be called at init.
func NewCache(name string) *Cache {
	c := &Cache{
		name:    name,
		entries: make(map[string]*cacheEntry),
	}
	allCaches.PushBack(c)
	return c
}

// mustAbs returns the absolute path of a filename or dies.
func mustAbs(filename string) string {
	abs, err := filepath.Abs(filename)
	if err != nil {
		log.Fatalf("error getting absolute path: %v", err)
	}
	return abs
}

// Lookup looks up an entry in the cache.
func (c *Cache) Lookup(filenames []string, generate func() (Sizer, error)) (Sizer, error) {
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

	c.mu.Lock()
	entry, ok := c.entries[cacheKey]
	if ok {
		c.hits++
		c.mu.Unlock() // See ordering requirement.
		if entry.sizer != nil {
			globalMu.Lock()
			globalLRU.Remove(entry)
			globalLRU.PushBack(entry)
			globalMu.Unlock()
		}
		entry.ready.Wait()
		return entry.sizer, entry.err
	}

	// Generate a new entry.
	c.misses++
	entry = &cacheEntry{
		cache: c,
		key:   cacheKey,
	}
	entry.ready.Add(1)
	c.entries[cacheKey] = entry
	c.mu.Unlock() // Unlock for generate.
	entry.sizer, entry.err = generate()
	entry.ready.Done()

	// Does this need to be accounted? We consider negative cache entries
	// to be free, in order to avoid extra work.
	if entry.sizer == nil {
		return entry.sizer, entry.err
	}

	// Account for the size of this item. This is complex, but we may clear
	// out other caches based on the globalLRU. Only items with non-zero
	// size are added here. This routine is the reason for the locking
	// order requirement on globalMu and must be respected.
	globalMu.Lock()
	globalLRU.PushBack(entry)
	totalCacheUsage += entry.sizer.Size()
	if totalCacheUsage > *maximumCacheUsage {
		for entry := globalLRU.Front(); entry != nil && totalCacheUsage > *maximumCacheUsage; entry = globalLRU.Front() {
			sz := entry.sizer.Size()

			// Remove from its cache.
			entry.cache.mu.Lock()
			delete(entry.cache.entries, entry.key)
			entry.cache.size -= sz
			entry.cache.mu.Unlock()

			// Remove from the global list.
			globalLRU.Remove(entry)
			totalCacheUsage -= sz
		}
	}
	globalMu.Unlock()

	// Return the value.
	return entry.sizer, entry.err
}

// allCacheStats returns stats for all caches.
func allCacheStats() string {
	var (
		sb    strings.Builder
		count int
	)
	for c := allCaches.Front(); c != nil; c = c.Next() {
		c.mu.Lock()
		if len(c.entries) == 0 {
			c.mu.Unlock()
			continue // Not active.
		}
		count++ // At least one active cache.
		ratio := float64(c.hits) / float64(c.hits+c.misses)
		fmt.Fprintf(&sb,
			"% 10s: count: % 5d  size: % 10d  hits: % 7d  misses: % 7d  ratio: %2.2f\n",
			c.name, len(c.entries), c.size, c.hits, c.misses, ratio)
		c.mu.Unlock()
	}
	if count > 0 {
		fmt.Fprintf(&sb, "total: % 10d\n", totalCacheUsage)
	}
	return sb.String()
}

// safeBuffer is a trivial wrapper around bytes.Buffer.
type safeBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

// Write implements io.Writer.Write.
func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Buffer.Write(p)
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
			for i := 0; i < len(args); {
				if args[i] == "" {
					// Remove empty arguments.
					copy(args[i:], args[i+1:])
					args = args[:len(args)-1]
					continue
				}
				i++ // Visit next.
			}
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
	wPipe.Close() // Still open at stdout, stderr.
	rPipe.Close() // Read end of pipe is now closed.

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
			inputFiles[mustAbs(input.GetPath())] = string(input.GetDigest())
		}

		// Prepare logging.
		var outputBuffer safeBuffer
		outputBuffer.WriteString(listenHeader)
		log.SetOutput(&outputBuffer)

		// Parse all arguments.
		flag.CommandLine.Parse(wreq.GetArguments())
		exitCode := run(flag.CommandLine.Args())

		// Attach all cache stats.
		if *workerDebug {
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
