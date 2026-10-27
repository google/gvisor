// Copyright The Isola Authors
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

package installer

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func healthHandler(installer *Installer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if stalled, silent := installer.Stalled(); stalled {
			http.Error(w, fmt.Sprintf("no reconcile iteration completed in %s, the reconcile loop is wedged",
				silent.Round(time.Second)), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if installer.Ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "last reconcile did not converge, see pod logs and node events", http.StatusServiceUnavailable)
	})
	return mux
}

func ServeHealth(ctx context.Context, addr string, installer *Installer, log Logger) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           healthHandler(installer),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("health server failed", "error", err)
	}
}
