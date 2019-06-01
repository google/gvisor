// Copyright 2019 Google LLC
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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	// For triggering manual rebuilds.
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudbuild/v1"
)

var redirects = map[string]string{
	"/change":    "https://gvisor.googlesource.com/gvisor/",
	"/cl":        "https://gvisor-review.googlesource.com/",
	"/issue":     "https://github.com/google/gvisor/issues",
	"/issue/new": "https://github.com/google/gvisor/issues/new",

	// Redirects to compatibility docs.
	"/c":             "/docs/user_guide/compatibility",
	"/c/linux/amd64": "/docs/user_guide/compatibility/amd64",
}

var prefixHelpers = map[string]string{
	"cl":     "https://gvisor-review.googlesource.com/c/gvisor/+/%s",
	"change": "https://gvisor.googlesource.com/gvisor/+/%s",
	"issue":  "https://github.com/google/gvisor/issues/%s",

	// Redirects to compatibility docs.
	"c/linux/amd64": "/docs/user_guide/compatibility/amd64/#%s",
}

var (
	validId     = regexp.MustCompile(`^[A-Za-z0-9-]*/?$`)
	goGetHeader = `<meta name="go-import" content="gvisor.dev git https://github.com/google/gvisor">`
	goGetHTML5  = `<!doctype html><html><head><meta charset=utf-8>` + goGetHeader + `<title>Go-get</title></head><body></html>`
)

// wrappedHandler wraps an http.Handler.
//
// If the query parameters include go-get=1, then we redirect to a single
// static page that allows us to serve arbitrary Go packages.
func wrappedHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gg, ok := r.URL.Query()["go-get"]
		if ok && len(gg) == 1 && gg[0] == "1" {
			// Serve a trivial html page.
			w.Write([]byte(goGetHTML5))
			return
		}
		// Fallthrough.
		h.ServeHTTP(w, r)
	})
}

// redirectWithQuery redirects to the given target url preserving query parameters.
func redirectWithQuery(w http.ResponseWriter, r *http.Request, target string) {
	url := target
	if qs := r.URL.RawQuery; qs != "" {
		url += "?" + qs
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// hostRedirectHandler redirects the www. domain to the naked domain.
func hostRedirectHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "www.") {
			// Redirect to the naked domain.
			r.URL.Scheme = "https"  // Assume https.
			r.URL.Host = r.Host[4:] // Remove the 'www.'
			http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// prefixRedirectHandler returns a handler that redirects to the given formated url.
func prefixRedirectHandler(prefix, baseURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == prefix {
			// Redirect /prefix/ to /prefix.
			http.Redirect(w, r, p[:len(p)-1], http.StatusFound)
			return
		}
		id := r.URL.Path[len(prefix):]
		if !validId.MatchString(id) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		target := fmt.Sprintf(baseURL, id)
		redirectWithQuery(w, r, target)
	})
}

// redirectHandler returns a handler that redirects to the given url.
func redirectHandler(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectWithQuery(w, r, target)
	})
}

// redirectRedirects registers redirect http handlers.
func registerRedirects(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}

	for prefix, baseURL := range prefixHelpers {
		p := "/" + prefix + "/"
		mux.Handle(p, hostRedirectHandler(wrappedHandler(prefixRedirectHandler(p, baseURL))))
	}

	for path, redirect := range redirects {
		mux.Handle(path, hostRedirectHandler(wrappedHandler(redirectHandler(redirect))))
	}
}

// registerStatic registers static file handlers
func registerStatic(mux *http.ServeMux, staticDir string) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.Handle("/", hostRedirectHandler(wrappedHandler(http.FileServer(http.Dir(staticDir)))))
}

// registerRebuild registers the rebuild handler.
func registerRebuild(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}

	mux.Handle("/rebuild", wrappedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		credentials, err := google.FindDefaultCredentials(ctx, cloudbuild.CloudPlatformScope)
		if err != nil {
			http.Error(w, "credentials error: "+err.Error(), 500)
			return
		}
		cloudbuildService, err := cloudbuild.NewService(ctx)
		if err != nil {
			http.Error(w, "cloudbuild service error: "+err.Error(), 500)
			return
		}
		projectID := credentials.ProjectID
		if projectID == "" {
			// If running locally, then this project will not be
			// available. Use the default project here.
			projectID = "gvisor-website"
		}
		triggers, err := cloudbuildService.Projects.Triggers.List(projectID).Do()
		if err != nil {
			http.Error(w, "trigger list error: "+err.Error(), 500)
			return
		}
		if len(triggers.Triggers) < 1 {
			http.Error(w, "trigger list error: no triggers", 500)
			return
		}
		if _, err := cloudbuildService.Projects.Triggers.Run(
			projectID,
			triggers.Triggers[0].Id,
			&cloudbuild.RepoSource{
				// In the current project, require that a
				// github cloud source repository exists with
				// the given name, and build from master.
				BranchName: "master",
				RepoName:   "github_google_gvisor-website",
				ProjectId:  projectID,
			}).Do(); err != nil {
			http.Error(w, "run error: "+err.Error(), 500)
			return
		}
	})))
}

func envFlagString(name, def string) string {
	if val := os.Getenv(name); val != "" {
		return val
	}
	return def
}

var (
	addr      = flag.String("http", envFlagString("HTTP", ":8080"), "HTTP service address")
	staticDir = flag.String("static-dir", envFlagString("STATIC_DIR", "static"), "static files directory")
)

func main() {
	flag.Parse()

	registerRedirects(nil)
	registerRebuild(nil)
	registerStatic(nil, *staticDir)

	log.Fatal(http.ListenAndServe(*addr, nil))
}
