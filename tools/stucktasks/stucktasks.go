// Copyright 2022 The gVisor Authors.
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

// Package main implements a tool to help troubleshoot watchdog dumps.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/runsc/flag"
)

var (
	flagStacks = flag.String("stacks", "", "path to log file containing stuck task stacks.")
	flagOut    = flag.String("out", "", "path to output file (default: STDERR).")
)

func main() {
	flag.Parse()

	// Mandatory fields missing, print usage.
	if len(*flagStacks) == 0 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintf(os.Stderr, "\t%s --stacks=<path> [--out=<path>]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	in, err := os.Open(*flagStacks)
	if err != nil {
		fatal(err)
	}
	defer in.Close()

	var out io.Writer = os.Stdout
	if len(*flagOut) > 0 {
		f, err := os.Create(*flagOut)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		out = f
	}

	if err := analyze(in, out); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fatalf("%v", err)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func analyze(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "stuck task(s)") {
			return analyzeStuckTasks(scanner, out)
		}
		if strings.Contains(line, "Watchdog goroutine is stuck") {
			return analyzeStackDump(scanner, out, nil)
		}
		// Skip all lines before the watchdog dump.
	}
	return fmt.Errorf("watchdog header not found")
}

func analyzeStuckTasks(scanner *bufio.Scanner, out io.Writer) error {
	// Look for stuck tasks goroutine. The output has the folowing format:
	//	Task tid: 123 (goroutine 45), entered RunSys state 3m28.77s ago.
	ids := make(map[uint]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		id, err := parseGoroutineID(line)
		if err != nil {
			// All stuck tasks were collected, the log is followed by the stack dump.
			return analyzeStackDump(scanner, out, ids)
		}
		ids[id] = struct{}{}
	}
	return fmt.Errorf("not able to find stuck task IDs")
}

func analyzeStackDump(scanner *bufio.Scanner, out io.Writer, stuckIds map[uint]struct{}) error {
	stacks, err := collectStacks(scanner)
	if err != nil {
		return nil
	}

	// Create histogram with all unique stacks.
	type counter struct {
		count int
		ids   []uint
		*stack
	}
	uniq := make(map[string]*counter)
	for _, stack := range stacks {
		c := uniq[stack.signature]
		if c == nil {
			c = &counter{stack: stack}
			uniq[stack.signature] = c
		}
		c.count++
		c.ids = append(c.ids, stack.id)
	}

	// Sort them in reverse order, to print most occurring at the top.
	var sorted []*counter
	for _, c := range uniq {
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool {
		// Reverse sort
		return sorted[i].count > sorted[j].count
	})

	fmt.Fprintf(out, "Stacks: %d, unique: %d\n\n", len(stacks), len(sorted))
	for _, c := range sorted {
		fmt.Fprintf(out, "=== Stack (count: %d) ===\ngoroutine IDs: %v\n", c.count, c.ids)
		var stucks []uint
		for _, id := range c.ids {
			if _, ok := stuckIds[id]; ok {
				stucks = append(stucks, id)
			}
		}
		if len(stucks) > 0 {
			fmt.Fprintf(out, "*** Stuck goroutines: %v ***\n", stucks)
		}
		fmt.Fprintln(out)
		for _, line := range c.lines {
			fmt.Fprintln(out, line)
		}
		fmt.Fprintln(out)
	}

	return nil
}

// collectStacks parses the input to find stack dump. Expected format is:
//
//	goroutine ID [reason, time]:
//	package.function(args)
//		GOROOT/path/file.go:line +offset
//	<blank line between stacks>
func collectStacks(scanner *bufio.Scanner) ([]*stack, error) {
	var stacks []*stack
	var block []string
	for scanner.Scan() {
		line := scanner.Text()

		// Expect the first line of a block to be the goroutine header:
		//   goroutine 43 [select, 19 minutes]:
		if len(block) == 0 {
			if _, err := parseGoroutineID(line); err != nil {
				// If not the header and no stacks have been found yet, skip the line
				// until the start of stack dump is found.
				if len(stacks) == 0 {
					continue
				}
				// if stacks has been found, it means we reached the end of the dump and
				// more logging lines exist in the file.
				break
			}
		}

		// A blank line means that we reached the end of the block
		if len(strings.TrimSpace(line)) > 0 {
			block = append(block, line)
			continue
		}
		stack, err := parseBlock(block)
		if err != nil {
			return nil, err
		}
		stacks = append(stacks, stack)
		block = nil
	}
	return stacks, nil
}

func parseBlock(block []string) (*stack, error) {
	id, err := parseGoroutineID(block[0])
	if err != nil {
		return nil, err
	}

	var signature string
	for i, line := range block[1:] {
		if i%2 == 1 {
			signature += line + "\n"
		}
	}

	return &stack{
		id:        uint(id),
		signature: signature,
		lines:     block[1:],
	}, nil
}

func parseGoroutineID(line string) (uint, error) {
	r := regexp.MustCompile(`goroutine (\d+)`)
	matches := r.FindStringSubmatch(line)
	if len(matches) != 2 {
		return 0, fmt.Errorf("invalid goroutine ID line: %q", line)
	}
	id, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("parsing goroutine ID, line: %q: %w", line, err)
	}
	return uint(id), nil
}

type stack struct {
	id        uint
	signature string
	lines     []string
}
