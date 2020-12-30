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

// Package harness holds utility code for running benchmarks on Docker.
package harness

import (
	"flag"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

var (
	help  = flag.Bool("help", false, "print this usage message")
	debug = flag.Bool("debug", false, "turns on debug messages for individual benchmarks")
)

// Init performs any harness initilialization before runs.
func Init() error {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -- --test.bench=<regex>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	dockerutil.EnsureSupportedDockerVersion()
	return nil
}

// SetFixedBenchmarks causes all benchmarks to run once.
//
// This must be set if they cannot scale with N. Note that this uses 1ns
// instead of 1x due to https://github.com/golang/go/issues/32051.
func SetFixedBenchmarks() {
	flag.Set("test.benchtime", "1ns")
}

// GetMachine returns this run's implementation of machine.
func GetMachine() (Machine, error) {
	return &localMachine{}, nil
}
