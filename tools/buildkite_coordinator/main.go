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

// Package main implements the Buildkite coordinator.
//
// Currently WIP.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	cfg := loadConfig()

	// Fetch the Buildkite agent token
	token, err := accessSecret(context.Background(), cfg.bkTokenProject, cfg.bkTokenSecret)
	if err != nil {
		log.Fatalf("Failed to read Buildkite agent token: %v", err)
	}
	log.Printf("Read Buildkite agent token (%d bytes)", len(token))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "PONG")
	})
	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	log.Printf("Listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
