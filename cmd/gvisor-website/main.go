/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
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

var validId = regexp.MustCompile(`^[A-Za-z0-9-]*/?$`)

// redirectWithQuery redirects to the given target url preserving query parameters.
func redirectWithQuery(w http.ResponseWriter, r *http.Request, target string) {
	url := target
	if qs := r.URL.RawQuery; qs != "" {
		url += "?" + qs
	}
	http.Redirect(w, r, url, http.StatusFound)
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
		mux.Handle(p, prefixRedirectHandler(p, baseURL))
	}

	for path, redirect := range redirects {
		mux.Handle(path, redirectHandler(redirect))
	}
}

// registerStatic registers static file handlers
func registerStatic(mux *http.ServeMux, staticDir string) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))
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
	registerStatic(nil, *staticDir)

	log.Fatal(http.ListenAndServe(*addr, nil))
}
