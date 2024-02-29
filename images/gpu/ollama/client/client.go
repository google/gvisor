// Copyright 2024 The gVisor Authors.
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

// A simple `curl`-like HTTP client that prints metrics after the request.
// All of its output is structured to be unambiguous even if stdout/stderr
// is combined, as is the case for Kubernetes logs.
// Useful for communicating with ollama.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

// Flags.
var (
	url            = flag.String("url", "", "HTTP request URL.")
	method         = flag.String("method", "GET", "HTTP request method (GET or POST).")
	postDataBase64 = flag.String("post_base64", "", "HTTP request POST data in base64 format; ignored for GET requests.")
	timeout        = flag.Duration("timeout", 0, "HTTP request timeout; 0 for no timeout.")
)

// bufSize is the size of buffers used for HTTP requests and responses.
const bufSize = 1024 * 1024 // 1MiB

// fatalf crashes the program with a given error message.
func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", values...)
	os.Exit(1)
}

// Metrics contains the request metrics to export to JSON.
// This is parsed by the ollama library at `test/gpu/ollama/ollama.go`.
type Metrics struct {
	// ProgramStarted is the time when the program started.
	ProgramStarted time.Time `json:"program_started"`
	// RequestSent is the time when the HTTP request was sent.
	RequestSent time.Time `json:"request_sent"`
	// ResponseReceived is the time when the HTTP response headers were received.
	ResponseReceived time.Time `json:"response_received"`
	// FirstByteRead is the time when the first HTTP response body byte was read.
	FirstByteRead time.Time `json:"first_byte_read"`
	// LastByteRead is the time when the last HTTP response body byte was read.
	LastByteRead time.Time `json:"last_byte_read"`
}

func main() {
	var metrics Metrics
	metrics.ProgramStarted = time.Now()
	flag.Parse()
	if *url == "" {
		fatalf("--url is required")
	}
	client := http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    1,
			IdleConnTimeout: *timeout,
			ReadBufferSize:  bufSize,
			WriteBufferSize: bufSize,
		},
		Timeout: *timeout,
	}
	var request *http.Request
	var err error
	switch *method {
	case "GET":
		request, err = http.NewRequest("GET", *url, nil)
	case "POST":
		postData, postDataErr := base64.StdEncoding.DecodeString(*postDataBase64)
		if postDataErr != nil {
			fatalf("cannot decode POST data: %v", postDataErr)
		}
		request, err = http.NewRequest("POST", *url, bytes.NewBuffer(postData))
	default:
		err = fmt.Errorf("unknown method %q", *method)
	}
	if err != nil {
		fatalf("cannot create request: %v", err)
	}
	readBuf := make([]byte, bufSize)
	orderedReqHeaders := make([]string, 0, len(request.Header))
	for k := range request.Header {
		orderedReqHeaders = append(orderedReqHeaders, k)
	}
	sort.Strings(orderedReqHeaders)
	for _, k := range orderedReqHeaders {
		for _, v := range request.Header[k] {
			fmt.Fprintf(os.Stderr, "REQHEADER: %s: %s\n", k, v)
		}
	}
	metrics.RequestSent = time.Now()
	resp, err := client.Do(request)
	metrics.ResponseReceived = time.Now()
	if err != nil {
		fatalf("cannot make request: %v", err)
	}
	gotFirstByte := false
	for {
		n, err := resp.Body.Read(readBuf)
		if n > 0 {
			if !gotFirstByte {
				metrics.FirstByteRead = time.Now()
				gotFirstByte = true
			}
			fmt.Printf("BODY: %q\n", string(readBuf[:n]))
		}
		if err == io.EOF {
			metrics.LastByteRead = time.Now()
			break
		}
		if err != nil {
			fatalf("cannot read response body: %v", err)
		}
	}
	if err := resp.Body.Close(); err != nil {
		fatalf("cannot close response body: %v", err)
	}
	orderedRespHeaders := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		orderedRespHeaders = append(orderedRespHeaders, k)
	}
	sort.Strings(orderedRespHeaders)
	for _, k := range orderedRespHeaders {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(os.Stderr, "RESPHEADER: %s: %s\n", k, v)
		}
	}
	metricsBytes, err := json.Marshal(&metrics)
	if err != nil {
		fatalf("cannot marshal metrics: %v", err)
	}
	fmt.Fprintf(os.Stderr, "STATS: %s\n", string(metricsBytes))
}
