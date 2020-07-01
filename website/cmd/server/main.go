// Copyright 2019 The gVisor Authors
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

// Server is the main gvisor.dev binary.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var redirects = map[string]string{
	// GitHub redirects.
	"/change":    "https://github.com/google/gvisor",
	"/issue":     "https://github.com/google/gvisor/issues",
	"/issue/new": "https://github.com/google/gvisor/issues/new",
	"/pr":        "https://github.com/google/gvisor/pulls",

	// For links.
	"/faq": "/docs/user_guide/faq/",

	// From 2020-05-12 to 2020-06-30, the FAQ URL was uppercase. Redirect that
	// back to maintain any links.
	"/docs/user_guide/FAQ/": "/docs/user_guide/faq/",

	// Redirects to compatibility docs.
	"/c":             "/docs/user_guide/compatibility/",
	"/c/linux/amd64": "/docs/user_guide/compatibility/linux/amd64/",

	// Redirect for old URLs.
	"/docs/user_guide/compatibility/amd64/": "/docs/user_guide/compatibility/linux/amd64/",
	"/docs/user_guide/compatibility/amd64":  "/docs/user_guide/compatibility/linux/amd64/",
	"/docs/user_guide/kubernetes/":          "/docs/user_guide/quick_start/kubernetes/",
	"/docs/user_guide/kubernetes":           "/docs/user_guide/quick_start/kubernetes/",
	"/docs/user_guide/oci/":                 "/docs/user_guide/quick_start/oci/",
	"/docs/user_guide/oci":                  "/docs/user_guide/quick_start/oci/",
	"/docs/user_guide/docker/":              "/docs/user_guide/quick_start/docker/",
	"/docs/user_guide/docker":               "/docs/user_guide/quick_start/docker/",

	// Deprecated, but links continue to work.
	"/cl": "https://gvisor-review.googlesource.com",
}

var prefixHelpers = map[string]string{
	"change": "https://github.com/google/gvisor/commit/%s",
	"issue":  "https://github.com/google/gvisor/issues/%s",
	"pr":     "https://github.com/google/gvisor/pull/%s",

	// Redirects to compatibility docs.
	"c/linux/amd64": "/docs/user_guide/compatibility/linux/amd64/#%s",

	// Deprecated, but links continue to work.
	"cl": "https://gvisor-review.googlesource.com/c/gvisor/+/%s",
}

var (
	validID    = regexp.MustCompile(`^[A-Za-z0-9-]*/?$`)
	goGetHTML5 = `<!doctype html><html><head><meta charset=utf-8>
<meta name="go-import" content="gvisor.dev/gvisor git https://github.com/google/gvisor">
<meta name="go-import" content="gvisor.dev/website git https://github.com/google/gvisor-website">
<title>Go-get</title></head><body></html>`
)

// cronHandler wraps an http.Handler to check that the request is from the App
// Engine Cron service.
// See: https://cloud.google.com/appengine/docs/standard/go112/scheduling-jobs-with-cron-yaml#validating_cron_requests
func cronHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Appengine-Cron") != "true" {
			http.NotFound(w, r)
			return
		}
		// Fallthrough.
		h.ServeHTTP(w, r)
	})
}

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

		if *projectID != "" && r.Host == *projectID+".appspot.com" && *customHost != "" {
			// Redirect to the custom domain.
			r.URL.Scheme = "https" // Assume https.
			r.URL.Host = *customHost
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
		if !validID.MatchString(id) {
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

func envFlagString(name, def string) string {
	if val := os.Getenv(name); val != "" {
		return val
	}
	return def
}

var (
	addr      = flag.String("http", envFlagString("HTTP", ":"+envFlagString("PORT", "8080")), "HTTP service address")
	staticDir = flag.String("static-dir", envFlagString("STATIC_DIR", "_site"), "static files directory")

	// Uses the standard GOOGLE_CLOUD_PROJECT environment variable set by App Engine.
	projectID  = flag.String("project-id", envFlagString("GOOGLE_CLOUD_PROJECT", ""), "The App Engine project ID.")
	customHost = flag.String("custom-domain", envFlagString("CUSTOM_DOMAIN", "gvisor.dev"), "The application's custom domain.")
)

func main() {
	flag.Parse()

	registerRedirects(nil)
	registerStatic(nil, *staticDir)

	log.Printf("Listening on %s...", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
