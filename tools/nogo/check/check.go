// Copyright 2019 The gVisor Authors.
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

// Package check implements binary analysis similar to bazel's nogo, or the
// unitchecker package. It exists in order to provide additional facilities for
// analysis, namely plumbing through the output from dumping the generated
// binary (to analyze actual produced code).
package check

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/gcexportdata"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/nogo/facts"
	"gvisor.dev/gvisor/tools/nogo/flags"
	"gvisor.dev/gvisor/tools/worker"
)

var (
	// ErrSkip indicates the package should be skipped.
	ErrSkip = errors.New("skipped2")

	// cachedFacts caches by file (just byte data).
	cachedFacts = worker.NewCache("facts")

	// bundleCachedFacts caches the standard library (bundleFacts).
	bundleCachedFacts = worker.NewCache("stdlib")

	// showTimes indicates we should show analyzer times.
	showTimes = flag.Bool("show_times", false, "show all analyzer times")
)

var (
	tagsOnce       sync.Once
	buildTags      []string
	releaseTagsVal []string
	releaseTagsErr error
)

// versionTags generates all version tags.
//
// This function will panic if passed an invalid version.
func versionTags(v string) (tags []string) {
	if len(v) < 2 || string(v[:2]) != "go" {
		panic(fmt.Errorf("version %q is not valid", v))
	}
	v = v[2:] // Strip go prefix.
	v = strings.Split(v, " ")[0]
	v = strings.Split(v, "-")[0]
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		panic(fmt.Errorf("version %q lacks major and minor number", v))
	}
	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		panic(fmt.Errorf("version %q contains invalid major: %w", v, err))
	}
	minor, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		panic(fmt.Errorf("version %q contains invalid minor: %w", v, err))
	}
	// Generate all compliant tags.
	for i := int64(0); i <= minor; i++ {
		tags = append(tags, fmt.Sprintf("go%d.%d", major, i))
	}
	return tags
}

// shouldInclude indicates whether the file should be included.
func shouldInclude(path string) (bool, error) {
	tagsOnce.Do(func() {
		if len(flags.BuildTags) > 0 {
			buildTags = strings.Split(flags.BuildTags, ",")
		}
		if v, err := flags.Env("GOVERSION"); err == nil {
			buildTags = append(buildTags, versionTags(v)...)
		} else {
			buildTags = append(buildTags, versionTags(runtime.Version())...)
		}
		releaseTagsVal, releaseTagsErr = releaseTags()
	})
	if releaseTagsErr != nil {
		return false, releaseTagsErr
	}
	ctx := build.Default
	ctx.GOOS = flags.GOOS
	ctx.GOARCH = flags.GOARCH
	ctx.BuildTags = buildTags
	ctx.ReleaseTags = releaseTagsVal
	return ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
}

// sortSrcs sorts a set of src files into Go files and non-Go files.
func sortSrcs(srcs []string) (goFiles []string, nonGoFiles []string) {
	for _, filename := range srcs {
		if strings.HasSuffix(filename, ".go") {
			goFiles = append(goFiles, filename)
		} else {
			nonGoFiles = append(nonGoFiles, filename)
		}
	}
	return
}

// importerEntry is a single entry in the importer.
type importerEntry struct {
	ready    sync.WaitGroup
	pkg      *types.Package
	findings FindingSet
	facts    *facts.Package
	err      error
}

// importer is an almost-implementation of go/types.Importer.
//
// This wraps a configuration, which provides the map of package names to
// files, and the facts. Note that this importer implementation will always
// pass when a given package is not available.
type importer struct {
	fset    *token.FileSet
	sources map[string][]string

	// mu protects cache.
	mu    sync.Mutex
	cache map[string]*importerEntry

	// importsMu protects imports.
	importsMu sync.Mutex
	imports   map[string]*types.Package
}

// allFacts returns all package facts for the given name.
//
// This attempts to load via the FactMap (global flags) or the Bundles (global
// flags), but falls back to attempting a direct import.
func (i *importer) allFacts(pkg *types.Package) (*facts.Package, error) {
	// Attempt to load from the fact map.
	filename, ok := flags.FactMap[pkg.Path()]
	if ok {
		cb, err := cachedFacts.Lookup([]string{filename}, func() (worker.Sizer, error) {
			r, openErr := os.Open(filename)
			if openErr != nil {
				return nil, fmt.Errorf("error loading facts from %q: %w", filename, openErr)
			}
			defer r.Close()
			loadedFacts := facts.NewPackage(pkg)
			if _, readErr := loadedFacts.ReadFrom(r); readErr != nil {
				return nil, fmt.Errorf("error loading facts: %w", readErr)
			}
			return loadedFacts, nil
		})
		if err != nil {
			return nil, err
		}
		return cb.(*facts.Package), nil
	}

	// Attempt to load any bundles.
	for _, filename := range flags.Bundles {
		cb, err := bundleCachedFacts.Lookup([]string{filename}, func() (worker.Sizer, error) {
			r, openErr := os.Open(filename)
			if openErr != nil {
				return nil, fmt.Errorf("error loading bundled facts from %q: %w", filename, openErr)
			}
			defer r.Close()
			loadedFacts := facts.NewBundle(i)
			if _, readErr := loadedFacts.ReadFrom(r); readErr != nil {
				// If the file is length zero, we skip it. This
				// is because stray fact files may been left
				// behind that are attempting to recreate now.
				fi, err := r.Stat()
				if err == nil && fi.Size() == 0 {
					return nil, ErrSkip
				}
				return nil, fmt.Errorf("error loading bundled facts: %w", readErr)
			}
			return loadedFacts, nil
		})
		if err == ErrSkip {
			continue // See above.
		}
		if err != nil {
			return nil, err
		}
		if loadedFacts, ok := cb.(*facts.Bundle).Packages[pkg.Path()]; ok {
			return loadedFacts, nil
		}
	}

	// Attempt to resolve the package via import.
	_, parsedFacts, err := i.importPackage(pkg.Path())
	return parsedFacts, err
}

// fastFact returns facts for the given package.
func (i *importer) fastFact(pkg *types.Package, obj types.Object, ptr analysis.Fact) bool {
	foundFacts, err := i.allFacts(pkg)
	if err != nil || foundFacts == nil {
		return false
	}
	return foundFacts.ImportFact(obj, ptr)
}

// findBinary finds the binary for the given package.
func (i *importer) findBinary(path string) (rc io.ReadCloser, err error) {
	realPath, ok := flags.ImportMap[path]
	if !ok {
		// Not found in the import path. Attempt to find the package
		// via the standard library.
		rc, err = findStdPkg(path)
	} else {
		// Open the file.
		rc, err = os.Open(realPath)
	}
	return rc, err
}

// importPackage almost-implements types.Importer.Import.
//
// This must be called by other methods directly.
func (i *importer) importPackage(path string) (*types.Package, *facts.Package, error) {
	if path == "unsafe" {
		// Special case: go/types has pre-defined type information for
		// unsafe. We ensure that this package is correct, in case any
		// analyzers are specifically looking for this.
		return types.Unsafe, nil, nil
	}

	// Pull the internal entry.
	i.mu.Lock()
	entry, ok := i.cache[path]
	if ok {
		i.mu.Unlock()
		entry.ready.Wait()
		return entry.pkg, entry.facts, entry.err
	}

	// Start preparing this entry.
	entry = new(importerEntry)
	entry.ready.Add(1)
	defer entry.ready.Done()
	i.cache[path] = entry
	i.mu.Unlock()

	// If we have the srcs for this package, then we can actually do an
	// analysis from first principles to validate the package and derive
	// the types. We strictly prefer this to the gcexportdata.
	if srcs, ok := i.sources[path]; ok && len(srcs) > 0 {
		start := time.Now()
		entry.pkg, entry.findings, entry.facts, entry.err = i.checkPackage(path, srcs)
		if entry.err != nil {
			return nil, nil, entry.err
		}
		// Why does the news already need to be bad? Note that this is
		// printed here because this will only happen when multiple
		// packages are being analyzed.
		log.Printf("SUCCESS: all analyzers successfully completed %q (%v).", path, time.Since(start))
		i.importsMu.Lock()
		defer i.importsMu.Unlock()
		i.imports[path] = entry.pkg
		return entry.pkg, entry.facts, entry.err
	}

	// Load all exported data. Unfortunately, we will have to hold the lock
	// during this time. The imported may access imports directly.
	rc, err := i.findBinary(path)
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()
	r, err := gcexportdata.NewReader(rc)
	if err != nil {
		return nil, nil, err
	}
	i.importsMu.Lock()
	defer i.importsMu.Unlock()
	entry.pkg, entry.err = gcexportdata.Read(r, i.fset, i.imports, path)
	return entry.pkg, entry.facts, entry.err
}

// Import implements types.Importer.Import.
func (i *importer) Import(path string) (*types.Package, error) {
	pkg, _, err := i.importPackage(path)
	return pkg, err
}

// errorImporter tracks the last error.
type errorImporter struct {
	*importer
	lastErr atomic.Value
}

// Import implements types.Importer.Import.
func (i *errorImporter) Import(path string) (*types.Package, error) {
	pkg, _, err := i.importer.importPackage(path)
	if err != nil {
		i.lastErr.Store(err)
	}
	return pkg, err
}

// checkPackage is the backing implementation for CheckPackage and others.
//
// The implementation was adapted from [1], which was in turn adpated from [2].
// This returns a list of matching analysis issues, or an error if the analysis
// could not be completed.
//
// Note that a partial result may be returned if an error occurred on at least
// one analyzer. This may be expected if e.g. a binary is not provided but a
// binaryAnalyzer is used.
//
// [1] bazelbuid/rules_go/tools/builders/nogo_main.go
// [2] golang.org/x/tools/go/checker/internal/checker
func (i *importer) checkPackage(path string, srcs []string) (*types.Package, FindingSet, *facts.Package, error) {
	// Load all source files.
	goFiles, _ := sortSrcs(srcs)
	syntax := make([]*ast.File, 0, len(goFiles))
	for _, file := range goFiles {
		include, err := shouldInclude(file)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error evaluating file %q: %w", file, err)
		}
		if !include {
			continue
		}
		s, err := parser.ParseFile(i.fset, file, nil, parser.ParseComments)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error parsing file %q: %w", file, err)
		}
		syntax = append(syntax, s)
	}

	// Check type information.
	ei := &errorImporter{
		importer: i,
	}
	typesSizes := types.SizesFor("gc", flags.GOARCH)
	typeConfig := types.Config{
		Importer: ei,
	}
	typesInfo := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
		Defs:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	astPackage, err := typeConfig.Check(path, i.fset, syntax, typesInfo)
	if err != nil && ei.lastErr.Load() != ErrSkip {
		return nil, nil, nil, fmt.Errorf("error checking types: %w", err)
	}

	// We start with completely empty facts. All of our facts are sourced
	// via the fastFact function that hits the local caches.
	//
	// Note that facts should be reconcilable between types as of go/tools
	// commit ee04797aa0b6be5ce3d5f7ac0f91e34716b3acdf. We previously used
	// to do a sanity check to ensure that binary import data was
	// compatible with ast-derived data, but this is no longer necessary.
	// If packages are available locally, we can refer to those directly.
	astFacts := facts.NewPackage(astPackage)

	// Recursively visit all analyzers.
	var (
		resultsMu sync.RWMutex // protects results & errs, findings.
		factsMu   sync.RWMutex // protects facts.
		ready     = make(map[*analysis.Analyzer]*sync.WaitGroup)
		results   = make(map[*analysis.Analyzer]interface{})
		errs      = make(map[*analysis.Analyzer]error)
		findings  = make(FindingSet, 0)
	)
	for a := range allAnalyzers {
		wg := new(sync.WaitGroup)
		wg.Add(1) // For analysis.
		ready[a] = wg
	}
	limit := make(chan struct{}, 1)
	for a, wg := range ready {
		go func(a *analysis.Analyzer, wg *sync.WaitGroup) {
			defer wg.Done()

			// Wait for all requirements.
			for _, orig := range a.Requires {
				ready[orig].Wait()

				// Should we bail early?
				resultsMu.RLock()
				if err := errs[orig]; err != nil {
					resultsMu.RUnlock()
					resultsMu.Lock()
					defer resultsMu.Unlock()
					errs[a] = err
					return
				}
				resultsMu.RUnlock()
			}

			limit <- struct{}{}
			defer func() { <-limit }()

			// Collect local fact types.
			localFactTypes := make(map[reflect.Type]bool)
			for _, ft := range a.FactTypes {
				localFactTypes[reflect.TypeOf(ft)] = true
			}

			// Run the analysis.
			var localFindings FindingSet
			p := &analysis.Pass{
				Analyzer:  a,
				Fset:      i.fset,
				Files:     syntax,
				Pkg:       astPackage,
				TypesInfo: typesInfo,
				ResultOf:  results, // All results.
				Report: func(d analysis.Diagnostic) {
					localFindings = append(localFindings, Finding{
						Category: a.Name,
						Position: i.fset.Position(d.Pos),
						Message:  d.Message,
					})
				},
				ImportPackageFact: func(pkg *types.Package, ptr analysis.Fact) bool {
					if pkg != astPackage {
						return i.fastFact(pkg, nil, ptr)
					}
					factsMu.RLock()
					defer factsMu.RUnlock()
					return astFacts.ImportFact(nil, ptr)
				},
				ExportPackageFact: func(fact analysis.Fact) {
					factsMu.Lock()
					defer factsMu.Unlock()
					astFacts.ExportFact(nil, fact)
				},
				ImportObjectFact: func(obj types.Object, ptr analysis.Fact) bool {
					if pkg := obj.Pkg(); pkg != nil && pkg != astPackage {
						return i.fastFact(pkg, obj, ptr)
					}
					factsMu.RLock()
					defer factsMu.RUnlock()
					return astFacts.ImportFact(obj, ptr)
				},
				ExportObjectFact: func(obj types.Object, fact analysis.Fact) {
					if obj == nil {
						// Tried to export nil object?
						log.Printf("WARNING: attempted to export fact for nil object")
						return
					}
					if obj.Pkg() != astPackage {
						// This is not allowed: the
						// built-in facts library will
						// also panic in this case.
						log.Printf("WARNING: attempted to export fact for package %s", obj.Pkg().Name())
						return
					}
					factsMu.Lock()
					defer factsMu.Unlock()
					astFacts.ExportFact(obj, fact)
				},
				AllPackageFacts: func() (rv []analysis.PackageFact) {
					factsMu.RLock()
					defer factsMu.RUnlock()
					// Pull all dependencies.
					for _, importedPkg := range astPackage.Imports() {
						otherFacts, err := i.allFacts(importedPkg)
						if err != nil || otherFacts == nil {
							continue
						}
						for typ := range localFactTypes {
							v := reflect.New(typ.Elem())
							if otherFacts.ImportFact(nil, v.Interface().(analysis.Fact)) {
								rv = append(rv, analysis.PackageFact{
									Package: importedPkg,
									Fact:    v.Interface().(analysis.Fact),
								})
							}
						}
					}
					// Pull all local facts.
					for typ := range localFactTypes {
						v := reflect.New(typ.Elem())
						if astFacts.ImportFact(nil, v.Interface().(analysis.Fact)) {
							rv = append(rv, analysis.PackageFact{
								Package: astPackage,
								Fact:    v.Interface().(analysis.Fact),
							})
						}
					}
					return
				},
				AllObjectFacts: func() (rv []analysis.ObjectFact) {
					factsMu.RLock()
					defer factsMu.RUnlock()
					// Pull all local facts.
					for obj, _ := range astFacts.Objects {
						for typ := range localFactTypes {
							v := reflect.New(typ.Elem())
							if astFacts.ImportFact(obj, v.Interface().(analysis.Fact)) {
								rv = append(rv, analysis.ObjectFact{
									Object: obj,
									Fact:   v.Interface().(analysis.Fact),
								})
							}
						}
					}
					return
				},
				TypesSizes: typesSizes,
			}

			// Ensure any analyzer panics are captured. This may
			// happen for packages that are not supported by
			// specific analyzers. The only panic that can happen
			// is while resultsMu is held as a read-only lock.
			var (
				result interface{}
				err    error
			)
			defer func() {
				if r := recover(); r != nil {
					// In order to make the multiple
					// analyzers running concurrently
					// debuggable, capture panic exceptions
					// and propagate as an analyzer error.
					err = fmt.Errorf("panic recovered: %s", r)
					resultsMu.RUnlock() // +checklocksignore
					resultsMu.Lock()
					errs[a] = err
					resultsMu.Unlock()
				}
			}()
			found := findAnalyzer(a)
			resultsMu.RLock()
			if ba, ok := found.(binaryAnalyzer); ok {
				// Load the binary and analyze.
				rc, loadErr := i.findBinary(path)
				if loadErr != nil {
					err = loadErr
				} else {
					result, err = ba.Run(p, rc)
					rc.Close()
				}
			} else {
				result, err = a.Run(p)
			}
			resultsMu.RUnlock()
			resultsMu.Lock()
			findings = append(findings, localFindings...)
			results[a] = result
			errs[a] = err
			resultsMu.Unlock()
		}(a, wg)
	}
	for _, wg := range ready {
		// Wait for completion.
		wg.Wait()
	}
	for a := range ready {
		// Check the error. If we generate an error here, we report
		// this as a finding that can be suppressed. Some analyzers
		// will fail on some packages.
		if errs[a] != nil {
			findings = append(findings, Finding{
				Category: a.Name,
				Position: token.Position{Filename: path},
				Message:  errs[a].Error(),
			})
			continue
		}

		// Check the result. Per above, we check that the type is what
		// we expected and that an error did not occur during analysis.
		if got, want := reflect.TypeOf(results[a]), a.ResultType; got != want {
			return astPackage, findings, astFacts, fmt.Errorf("error: analyzer %s returned %v (expected type %v)", a.Name, results[a], want)
		}
	}

	// Return all findings.
	return astPackage, findings, astFacts, nil
}

// allFindingsAndFacts returns the complete set.
func (i *importer) allFindingsAndFacts() (FindingSet, *facts.Bundle, error) {
	var (
		findings = make(FindingSet, 0)
		allFacts = facts.NewBundle(i)
	)
	for path, entry := range i.cache {
		findings = append(findings, entry.findings...)
		if entry.facts != nil {
			allFacts.Packages[path] = entry.facts
		} else if entry.pkg != nil {
			pkgFacts, err := i.allFacts(entry.pkg)
			if err != nil {
				// This should not happen, we should load facts for all packages.
				return nil, nil, fmt.Errorf("no facts available for %s: %v", entry.pkg.Path(), err)
			}
			allFacts.Packages[path] = pkgFacts
		}
	}

	// Return the results.
	return findings, allFacts, nil
}

// Package runs all analyzer on a single package.
func Package(path string, srcs []string) (FindingSet, facts.Writer, error) {
	i := &importer{
		fset:    token.NewFileSet(),
		cache:   make(map[string]*importerEntry),
		imports: make(map[string]*types.Package),
	}
	_, findings, facts, err := i.checkPackage(path, srcs)
	if err != nil {
		return nil, nil, err
	}
	return findings, facts, nil
}

// Facts runs all analyzers, and returns human-readable facts.
//
// These facts are essentially a dictionary tree (split across all '.'
// characters in the canonical human representation) that can be used for
// rendering via a template.
func Facts(path string, srcs []string) (facts.Resolved, error) {
	i := &importer{
		fset:    token.NewFileSet(),
		cache:   make(map[string]*importerEntry),
		imports: make(map[string]*types.Package),
	}
	pkg, _, localFacts, err := i.checkPackage(path, srcs)
	if localFacts == nil && err != nil {
		// Allow failure here, since we may not care about some
		// analyzers for these packages.
		return nil, err
	}
	_, allFacts, err := i.allFindingsAndFacts()
	if err != nil {
		return nil, err
	}
	return facts.Resolve(pkg, localFacts, allFacts, allFactNames), nil
}

// FindRoot finds a package root.
func FindRoot(srcs []string, srcRootRegex string) (string, error) {
	if srcRootRegex == "" {
		return "", nil
	}

	// Calculate the root source directory. This is always a directory
	// named 'src', of which we simply take the first we find. This is a
	// bit fragile, but works for all currently known Go source
	// configurations.
	//
	// Note that there may be extra files outside of the root source
	// directory; we simply ignore those.
	re, err := regexp.Compile(srcRootRegex)
	if err != nil {
		return "", fmt.Errorf("srcRootRegex is not valid: %w", err)
	}
	srcRootPrefix := ""
	for _, filename := range srcs {
		if s := re.FindString(filename); len(s) > len(srcRootPrefix) {
			srcRootPrefix = s
		}
	}
	if srcRootPrefix == "" {
		// For whatever reason, we didn't identify a good common prefix to use here.
		return "", fmt.Errorf("unable to identify src prefix for %v with regex %s", srcs, srcRootRegex)
	}
	return srcRootPrefix, nil
}

// SplitPackages splits a typical package structure into packages.
func SplitPackages(srcs []string, srcRootPrefix string) map[string][]string {
	sources := make(map[string][]string)
	for _, filename := range srcs {
		if !strings.HasPrefix(filename, srcRootPrefix) {
			continue // Superflouous file.
		}
		d := path.Dir(filename)
		if len(srcRootPrefix) >= len(d) {
			continue // Not a file.
		}
		pkg := d[len(srcRootPrefix):]
		for len(pkg) > 0 && pkg[0] == '/' {
			pkg = pkg[1:]
		}
		if len(pkg) == 0 {
			continue // Also not a file.
		}

		// Skip commands where possible. These also have package names
		// that do not match the tree structure and will never be
		// dependencies.
		if strings.HasPrefix(filename, "cmd/") {
			continue
		}

		// Skip obvious test files; they have bizarre package semantics
		// and are never direct dependencies of anything else.
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}

		// Skip unsupported packages explicitly.
		if _, ok := usesTypeParams[pkg]; ok {
			log.Printf("WARNING: Skipping package %q: type param analysis not yet supported.", pkg)
			continue
		}

		// Add to the package.
		sources[pkg] = append(sources[pkg], filename)
	}

	return sources
}

// Go standard library packages using Go 1.18 type parameter features.
//
// As of writing, analysis tooling is not updated to support type parameters
// and will choke on these packages. We skip these packages entirely for now.
//
// TODO(b/201686256): remove once tooling can handle type parameters.
var usesTypeParams = map[string]struct{}{
	"constraints": struct{}{}, // golang.org/issue/45458
	"maps":        struct{}{}, // golang.org/issue/47649
	"slices":      struct{}{}, // golang.org/issue/45955
}

// Bundle checks a bundle of files (typically the standard library).
func Bundle(sources map[string][]string) (FindingSet, facts.Writer, error) {
	// Process all packages.
	i := &importer{
		fset:    token.NewFileSet(),
		sources: sources,
		cache:   make(map[string]*importerEntry),
		imports: make(map[string]*types.Package),
	}
	for pkg, _ := range sources {
		// Was there an error processing this package? Just print a warning.
		if _, _, err := i.importPackage(pkg); err != nil && err != ErrSkip {
			log.Printf("WARNING: %v.", err)
		}
	}

	// Build our findings and facts.
	return i.allFindingsAndFacts()
}
