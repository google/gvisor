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

// flatecompress compresses data from stdin and writes it to stdout with flate.
package main

import (
	"compress/flate"
	"fmt"
	"io"
	"os"
)

func main() {
	writer, err := flate.NewWriter(os.Stdout, flate.BestCompression)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create flate writer: %v\n", err)
		os.Exit(1)
	}
	if _, err := io.Copy(writer, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compress binary: %v\n", err)
		os.Exit(1)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot flush: %v\n", err)
		os.Exit(1)
	}
	if err := writer.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot close writer: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
