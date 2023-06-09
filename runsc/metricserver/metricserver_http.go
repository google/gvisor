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

package metricserver

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/log"
)

// httpTimeout is the timeout used for all connect/read/write operations of the HTTP server.
const httpTimeout = 1 * time.Minute

// httpResult is returned by HTTP handlers.
type httpResult struct {
	code int
	err  error
}

// httpOK is the "everything went fine" HTTP result.
var httpOK = httpResult{code: http.StatusOK}

// serveIndex serves the index page.
func (m *metricServer) serveIndex(w http.ResponseWriter, req *http.Request) httpResult {
	if req.URL.Path != "/" {
		if strings.HasPrefix(req.URL.Path, "/metrics?") {
			// Prometheus's scrape_config.metrics_path takes in a query path and automatically encodes
			// all special characters in it to %-form, including the "?" character.
			// This can prevent use of query parameters, and we end up here instead.
			// To address this, rewrite the URL to undo this transformation.
			// This means requesting "/metrics%3Ffoo=bar" is rewritten to "/metrics?foo=bar".
			req.URL.RawQuery = strings.TrimPrefix(req.URL.Path, "/metrics?")
			req.URL.Path = "/metrics"
			return m.serveMetrics(w, req)
		}
		return httpResult{http.StatusNotFound, errors.New("path not found")}
	}
	fmt.Fprintf(w, "<html><head><title>runsc metrics</title></head><body>")
	fmt.Fprintf(w, "<p>You have reached the runsc metrics server page!</p>")
	fmt.Fprintf(w, `<p>To see actual metric data, head over to <a href="/metrics">/metrics</a>.</p>`)
	fmt.Fprintf(w, "</body></html>")
	return httpOK
}

// logRequest wraps an HTTP handler and adds logging to it.
func logRequest(f func(w http.ResponseWriter, req *http.Request) httpResult) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Infof("Request: %s %s", req.Method, req.URL.Path)
		defer func() {
			if r := recover(); r != nil {
				log.Warningf("Request: %s %s: Panic:\n%v", req.Method, req.URL.Path, r)
			}
		}()
		result := f(w, req)
		if result.err != nil {
			http.Error(w, result.err.Error(), result.code)
			log.Warningf("Request: %s %s: Failed with HTTP code %d: %v", req.Method, req.URL.Path, result.code, result.err)
		}
		// Run GC after every request to keep memory usage as predictable and as flat as possible.
		runtime.GC()
	}
}
