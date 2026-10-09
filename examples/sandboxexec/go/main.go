// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary doc_processor runs the docprocessor example from the command line.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"gvisor.dev/gvisor/examples/sandboxexec/go/docprocessor"
)

func main() {
	var cfg docprocessor.ProcessConfig
	flag.StringVar(&cfg.InputDir, "input", "", "Host directory to mount read-only at /input (e.g. ./docs)")
	flag.StringVar(&cfg.OutputDir, "output", "", "Host directory to mount read-write at /output (e.g. ./results)")
	flag.StringVar(&cfg.Command, "cmd", "", "Shell command to run in sandbox (default: batch uppercase conversion)")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Execution timeout (e.g. 5s, 30s)")
	flag.StringVar(&cfg.Network, "network", "none", "Network mode: 'none' (isolated), 'host', or 'sandbox'")
	flag.StringVar(&cfg.WorkingDir, "working-dir", "/", "Working directory inside the sandbox")
	flag.StringVar(&cfg.SnapshotDir, "snapshot-dir", "", "Directory with exactly one pre-warmed snapshot to restore (-warm-snapshot writes it)")
	warmSnapshot := flag.Bool("warm-snapshot", false, "Pre-warm and save a base template snapshot to -snapshot-dir and exit")
	flag.Parse()
	log.SetFlags(0)

	ctx := context.Background()
	var err error
	switch {
	case *warmSnapshot && cfg.SnapshotDir == "":
		log.Fatal("Error: -snapshot-dir is required when using -warm-snapshot")
	case *warmSnapshot:
		err = docprocessor.WarmSnapshot(ctx, cfg.SnapshotDir)
	default:
		err = docprocessor.ProcessDocuments(ctx, cfg)
	}
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
