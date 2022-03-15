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
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/google/pprof/driver"
)

var redirects = map[string]string{
	// GitHub redirects.
	"/change":    "https://github.com/google/gvisor",
	"/issue":     "https://github.com/google/gvisor/issues",
	"/issues":    "https://github.com/google/gvisor/issues",
	"/issue/new": "https://github.com/google/gvisor/issues/new/choose",
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
	"/docs/user_guide/compatibility/amd64/":  "/docs/user_guide/compatibility/linux/amd64/",
	"/docs/user_guide/compatibility/amd64":   "/docs/user_guide/compatibility/linux/amd64/",
	"/docs/user_guide/kubernetes/":           "/docs/user_guide/quick_start/kubernetes/",
	"/docs/user_guide/kubernetes":            "/docs/user_guide/quick_start/kubernetes/",
	"/docs/user_guide/oci/":                  "/docs/user_guide/quick_start/oci/",
	"/docs/user_guide/oci":                   "/docs/user_guide/quick_start/oci/",
	"/docs/user_guide/docker/":               "/docs/user_guide/quick_start/docker/",
	"/docs/user_guide/docker":                "/docs/user_guide/quick_start/docker/",
	"/blog/2020/09/22/platform-portability":  "/blog/2020/10/22/platform-portability/",
	"/blog/2020/09/22/platform-portability/": "/blog/2020/10/22/platform-portability/",

	// Deprecated, but links continue to work.
	"/cl": "https://gvisor-review.googlesource.com",

	// Access package documentation.
	"/gvisor": "https://pkg.go.dev/gvisor.dev/gvisor",

	// Code search root.
	"/cs": "https://cs.opensource.google/gvisor/gvisor",
}

type prefixInfo struct {
	baseURL      string
	checkValidID bool
	queryEscape  bool
}

var prefixHelpers = map[string]prefixInfo{
	"change": {baseURL: "https://github.com/google/gvisor/commit/%s", checkValidID: true},
	"issue":  {baseURL: "https://github.com/google/gvisor/issues/%s", checkValidID: true},
	"issues": {baseURL: "https://github.com/google/gvisor/issues/%s", checkValidID: true},
	"pr":     {baseURL: "https://github.com/google/gvisor/pull/%s", checkValidID: true},

	// Redirects to compatibility docs.
	"c/linux/amd64": {baseURL: "/docs/user_guide/compatibility/linux/amd64/#%s", checkValidID: true},

	// Deprecated, but links continue to work.
	"cl": {baseURL: "https://gvisor-review.googlesource.com/c/gvisor/+/%s", checkValidID: true},

	// Redirect to source documentation.
	"gvisor": {baseURL: "https://pkg.go.dev/gvisor.dev/gvisor/%s"},

	// Redirect to code search, with the path as the query.
	"cs": {baseURL: "https://cs.opensource.google/search?q=%s&ss=gvisor", queryEscape: true},
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
func prefixRedirectHandler(prefix string, info prefixInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == prefix {
			// Redirect /prefix/ to /prefix.
			http.Redirect(w, r, p[:len(p)-1], http.StatusFound)
			return
		}
		id := r.URL.Path[len(prefix):]
		if info.checkValidID && !validID.MatchString(id) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if info.queryEscape {
			id = url.QueryEscape(id)
		}
		target := fmt.Sprintf(info.baseURL, id)
		redirectWithQuery(w, r, target)
	})
}

// redirectHandler returns a handler that redirects to the given url.
func redirectHandler(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectWithQuery(w, r, target)
	})
}

// registerRedirects registers redirect http handlers.
func registerRedirects(mux *http.ServeMux) {
	for prefix, info := range prefixHelpers {
		p := "/" + prefix + "/"
		mux.Handle(p, hostRedirectHandler(wrappedHandler(prefixRedirectHandler(p, info))))
	}
	for path, redirect := range redirects {
		mux.Handle(path, hostRedirectHandler(wrappedHandler(redirectHandler(redirect))))
	}
}

// registerStatic registers static file handlers.
func registerStatic(mux *http.ServeMux, staticDir string) {
	mux.Handle("/", hostRedirectHandler(wrappedHandler(http.FileServer(http.Dir(staticDir)))))
}

// profileMeta implements synthetic flags for pprof.
type profileMeta struct {
	// Mux is the mux to register on.
	Mux *http.ServeMux

	// SourceURL is the source of the profile.
	SourceURL string
}

func (*profileMeta) ExtraUsage() string                                   { return "" }
func (*profileMeta) AddExtraUsage(string)                                 {}
func (*profileMeta) Bool(_ string, def bool, _ string) *bool              { return &def }
func (*profileMeta) Int(_ string, def int, _ string) *int                 { return &def }
func (*profileMeta) Float64(_ string, def float64, _ string) *float64     { return &def }
func (*profileMeta) StringList(_ string, def string, _ string) *[]*string { return new([]*string) }
func (*profileMeta) String(option string, def string, _ string) *string {
	switch option {
	case "http":
		// Only http is specified. Other options may be accessible via
		// the web interface, so we just need to spoof a valid option
		// here. The server is actually bound by HTTPServer, below.
		value := "localhost:80"
		return &value
	case "symbolize":
		// Don't attempt symbolization. Most profiles should come with
		// mappings built-in to the profile itself.
		value := "none"
		return &value
	default:
		return &def // Default.
	}
}

// Parse implements plugin.FlagSet.Parse.
func (p *profileMeta) Parse(usage func()) []string {
	// Just return the SourceURL. This is interpreted as the profile to
	// download. We validate that the URL corresponds to a Google Cloud
	// Storage URL below.
	return []string{p.SourceURL}
}

// pprofFixedPrefix is used to limit the exposure to SSRF.
//
// See registerProfile below.
const pprofFixedPrefix = "https://storage.googleapis.com/"

// allowedBuckets enforces constraints on the pprof target.
//
// If the continuous integration system is changed in the future to use
// additional buckets, they may be allowed here. See registerProfile.
var allowedBuckets = map[string]bool{
	"gvisor-buildkite": true,
}

// Target returns the URL target.
func (p *profileMeta) Target() string {
	return fmt.Sprintf("/profile/%s/", p.SourceURL[len(pprofFixedPrefix):])
}

// HTTPServer is a function passed to driver.PProf.
func (p *profileMeta) HTTPServer(args *driver.HTTPServerArgs) error {
	target := p.Target()
	for subpath, handler := range args.Handlers {
		handlerPath := path.Join(target, subpath)
		if len(handlerPath) < len(target) {
			// Don't clean the target, match only as the literal
			// directory path in order to keep relative links
			// working in the profile. E.g. /profile/foo/ is the
			// base URL for the profile at https://.../foo.
			//
			// The base target typically shows the dot-based graph,
			// which will not work in the image (due to the lack of
			// a dot binary to execute). Therefore, we redirect to
			// the flamegraph handler. Everything should otherwise
			// work the exact same way, except the "Graph" link.
			handlerPath = target
			handler = redirectHandler(path.Join(handlerPath, "flamegraph"))
		}
		p.Mux.Handle(handlerPath, handler)
	}
	return nil
}

// registerProfile registers the profile handler.
//
// Note that this has a security surface worth considering.
//
// We are passed effectively a URL, which we fetch and parse,
// then display the profile output. We limit the possibility of
// SSRF by interpreting the URL strictly as a part to an object
// in Google Cloud Storage, and further limit the buckets that
// may be used. This contains the vast majority of concerns,
// since objects must at least be uploaded by our CI system.
//
// However, we additionally consider the possibility that users
// craft malicious profile objects (somehow) and pass those URLs
// here as well. It seems feasible that we could parse a profile
// that causes a crash (DOS), but this would be automatically
// handled without a blip. It seems unlikely that we could parse a
// profile that gives full code execution, but even so there is
// nothing in this image except this code and CA certs. At worst,
// code execution would enable someone to serve up content under the
// web domain. This would be ephemeral with the specific instance,
// and persisting such an attack would require constantly crashing
// instances in whatever way gives remote code execution. Even if
// this were possible, it's unlikely that exploiting such a crash
// could be done so constantly and consistently.
//
// The user can also fill the "disk" of this container instance,
// causing an OOM and a crash. This has similar semantics to the
// DOS scenario above, and would just be handled by Cloud Run.
//
// Note that all of the above scenarios would require uploading
// malicious profiles to controller buckets, and a clear audit
// trail would exist in those cases.
func registerProfile(mux *http.ServeMux) {
	const urlPrefix = "/profile/"
	mux.Handle(urlPrefix, hostRedirectHandler(wrappedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the URL; this is everything except the final /.
		parts := strings.Split(r.URL.Path[len(urlPrefix):], "/")
		if len(parts) == 0 {
			http.Error(w, "Invalid URL: no bucket provided.", http.StatusNotFound)
			return
		}
		if !allowedBuckets[parts[0]] {
			http.Error(w, fmt.Sprintf("Invalid URL: not an allowed bucket (%s).", parts[0]), http.StatusNotFound)
			return
		}
		url := pprofFixedPrefix + strings.Join(parts[:len(parts)-1], "/")
		if url == pprofFixedPrefix {
			http.Error(w, "Invalid URL: no path provided.", http.StatusNotFound)
			return
		}

		// Set up the meta handler. This will modify the original mux
		// accordingly, and we ultimately return a redirect that
		// includes all the original arguments. This means that if we
		// ever hit a server that does not have this profile loaded, it
		// will load and redirect again.
		meta := &profileMeta{
			Mux:       mux,
			SourceURL: url,
		}
		if err := driver.PProf(&driver.Options{
			Flagset:    meta,
			HTTPServer: meta.HTTPServer,
		}); err != nil {
			http.Error(w, fmt.Sprintf("Invalid profile: %v", err), http.StatusNotImplemented)
			return
		}

		// Serve the path directly.
		mux.ServeHTTP(w, r)
	}))))
}

func envFlagString(name, def string) string {
	if val, ok := os.LookupEnv(name); ok {
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

	registerRedirects(http.DefaultServeMux)
	registerStatic(http.DefaultServeMux, *staticDir)
	registerProfile(http.DefaultServeMux)

	log.Printf("Listening on %s...", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
