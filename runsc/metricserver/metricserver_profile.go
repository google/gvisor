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
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/log"
)

// profileCPU returns a CPU profile over HTTP.
func (m *metricServer) profileCPU(w http.ResponseWriter, req *http.Request) httpResult {
	// Time to finish up profiling and flush out the results to the client.
	const finishProfilingBuffer = 250 * time.Millisecond

	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down already")}
	}
	m.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	if err := pprof.StartCPUProfile(w); err != nil {
		// We cannot return this as an error, because we've already sent the HTTP 200 OK status.
		log.Warningf("Failed to start recording CPU profile: %v", err)
		return httpOK
	}
	deadline := time.Now().Add(httpTimeout - finishProfilingBuffer)
	if seconds, err := strconv.Atoi(req.URL.Query().Get("seconds")); err == nil && time.Duration(seconds)*time.Second < httpTimeout {
		deadline = time.Now().Add(time.Duration(seconds) * time.Second)
	} else if ctxDeadline, hasDeadline := req.Context().Deadline(); hasDeadline {
		deadline = ctxDeadline.Add(-finishProfilingBuffer)
	}
	log.Infof("Profiling CPU until %v...", deadline)
	var wasInterrupted bool
	select {
	case <-time.After(time.Until(deadline)):
		wasInterrupted = false
	case <-req.Context().Done():
		wasInterrupted = true
	}
	pprof.StopCPUProfile()
	if wasInterrupted {
		log.Warningf("Profiling CPU interrupted.")
	} else {
		log.Infof("Profiling CPU done.")
	}
	return httpOK
}

// profileHeap returns a heap profile over HTTP.
func (m *metricServer) profileHeap(w http.ResponseWriter, req *http.Request) httpResult {
	m.mu.Lock()
	if m.shuttingDown {
		m.mu.Unlock()
		return httpResult{http.StatusServiceUnavailable, errors.New("server is shutting down already")}
	}
	m.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	runtime.GC() // Run GC just before looking at the heap to get a clean view.
	if err := pprof.Lookup("heap").WriteTo(w, 0); err != nil {
		// We cannot return this as an error, because we've already sent the HTTP 200 OK status.
		log.Warningf("Failed to record heap profile: %v", err)
	}
	return httpOK
}
