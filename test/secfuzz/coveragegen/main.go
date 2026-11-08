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

// Binary coveragegen generates separate Go fuzz coverage branches for each BPF
// instruction in the two programs under test.
package main

import (
	"bytes"
	"log"
	"os"
	"text/template"

	"gvisor.dev/gvisor/pkg/bpf"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s TEMPLATE OUTPUT", os.Args[0])
	}
	tmpl, err := template.ParseFiles(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Bound the compiler's control-flow graph for each generated function.
	const blockSize = 64
	type instruction struct {
		Length, Index int
		Fallthrough   bool
	}
	data := struct {
		BlockSize int
		Blocks    [][]instruction
	}{BlockSize: blockSize}
	for first := 0; first < bpf.MaxInstructions; first += blockSize {
		end := min(first+blockSize, bpf.MaxInstructions)
		block := make([]instruction, 0, end-first)
		for length := end; length > first; length-- {
			block = append(block, instruction{
				Length: length, Index: length - 1, Fallthrough: length > first+1,
			})
		}
		data.Blocks = append(data.Blocks, block)
	}
	var source bytes.Buffer
	if err := tmpl.Execute(&source, data); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(os.Args[2], source.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}
