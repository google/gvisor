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
	"runtime/debug"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/gcexportdata"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/nogo/facts"
	"gvisor.dev/gvisor/tools/nogo/flags"
)

var (
	// ErrSkip indicates the package should be skipped.
	ErrSkip = errors.New("skipped")

	// showTimes indicates we should show analyzer times.
	showTimes = flag.Bool("show_times", false, "show all analyzer times")
)

var (
	tagsOnce       sync.Once
	buildTags      []string
	releaseTagsVal []string
	releaseTagsErr error
)

// shouldInclude indicates whether the file should be included.
func shouldInclude(path string) (bool, error) {
	tagsOnce.Do(func() {
		if len(flags.BuildTags) > 0 {
			buildTags = strings.Split(flags.BuildTags, ",")
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
	err      error
	factsMu  sync.Mutex
	facts    *facts.Package
}

// importer is an almost-implementation of go/types.Importer.
//
// This wraps a configuration, which provides the map of package names to
// files, and the facts. Note that this importer implementation will always
// pass when a given package is not available.
type importer struct {
	fset    *token.FileSet
	sources map[string][]string

	// mu protects cache & bundles (see below).
	mu    sync.Mutex
	cache map[string]*importerEntry

	// bundles is protected by mu, but once set is immutable.
	bundles []*facts.Bundle

	// importsMu protects imports.
	importsMu sync.Mutex
	imports   map[string]*types.Package
}

// loadBundles loads all bundle files.
//
// This should only be called from loadFacts, below. After calling this
// function, i.bundles may be read freely without holding a lock.
func (i *importer) loadBundles() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Are bundles already available?
	if i.bundles != nil {
		return nil
	}

	// Scan all bundle files.
	for _, filename := range flags.Bundles {
		// Open the given filename as a bundle.
		loadedFacts, err := facts.BundleFrom(filename)
		if err != nil {
			return fmt.Errorf("error loading bundled facts: %w", err)
		}

		// Add to the set of available bundles.
		i.bundles = append(i.bundles, loadedFacts)
	}

	return nil
}

// loadFacts returns all package facts for the given name.
//
// This should be called only from importPackage, as this may deserialize a
// facts file (which is an expensive operation). Callers should generally rely
// on fastFacts to access facts for packages that have already been imported.
func (i *importer) loadFacts(pkg *types.Package) (*facts.Package, error) {
	// Attempt to load from the fact map.
	filename, ok := flags.FactMap[pkg.Path()]
	if ok {
		r, openErr := os.Open(filename)
		if openErr != nil {
			return nil, fmt.Errorf("error loading facts from %q: %w", filename, openErr)
		}
		defer r.Close()
		loadedFacts := facts.NewPackage()
		if readErr := loadedFacts.ReadFrom(pkg, r); readErr != nil {
			return nil, fmt.Errorf("error loading facts: %w", readErr)
		}
		return loadedFacts, nil
	}

	// Attempt to load any bundles.
	if err := i.loadBundles(); err != nil {
		return nil, fmt.Errorf("error loading bundles: %w", err)
	}

	// Try to import from the bundle.
	for _, bundleFacts := range i.bundles {
		localFacts, err := bundleFacts.Package(pkg)
		if err != nil {
			return nil, fmt.Errorf("error loading from a bundle: %w", err)
		}
		if localFacts != nil {
			return localFacts, nil
		}
	}

	// Nothing available for this package?
	return nil, nil
}

// fastFacts returns facts for the given package.
//
// This relies exclusively on loaded packages, as the parameter is
// *types.Package and therefore the package data must already be available.
func (i *importer) fastFacts(pkg *types.Package) *facts.Package {
	i.mu.Lock()
	e, ok := i.cache[pkg.Path()]
	i.mu.Unlock()
	if !ok {
		return nil
	}

	e.factsMu.Lock()
	defer e.factsMu.Unlock()

	// Do we have them already?
	if e.facts != nil {
		return e.facts
	}

	// Load the facts.
	facts, err := i.loadFacts(pkg)
	if err != nil {
		// We have no available to propagate an error when attempting
		// to import a fact, so we must simply issue a warning.
		log.Printf("WARNING: error loading facts for %s: %v", pkg.Path(), err)
		return nil
	}
	e.facts = facts // Cache the result.
	return facts
}

// findArchive finds the archive for the given package.
func (i *importer) findArchive(path string) (rc io.ReadCloser, err error) {
	realPath, ok := flags.ArchiveMap[path]
	if !ok {
		return i.findBinary(path)
	}
	return os.Open(realPath)
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
func (i *importer) importPackage(path string) (*types.Package, error) {
	if path == "unsafe" {
		// Special case: go/types has pre-defined type information for
		// unsafe. We ensure that this package is correct, in case any
		// analyzers are specifically looking for this.
		return types.Unsafe, nil
	}

	// Pull the internal entry.
	i.mu.Lock()
	entry, ok := i.cache[path]
	if ok && entry.pkg != nil {
		i.mu.Unlock()
		entry.ready.Wait()
		return entry.pkg, entry.err
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
		entry.pkg, entry.findings, entry.facts, entry.err = i.checkPackage(path, srcs)
		if entry.err != nil {
			return nil, entry.err
		}
		i.importsMu.Lock()
		defer i.importsMu.Unlock()
		i.imports[path] = entry.pkg
		return entry.pkg, entry.err
	}

	// Load all exported data. Unfortunately, we will have to hold the lock
	// during this time. The imported may access imports directly.
	rc, err := i.findBinary(path)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	r, err := gcexportdata.NewReader(rc)
	if err != nil {
		return nil, err
	}
	i.importsMu.Lock()
	defer i.importsMu.Unlock()
	entry.pkg, entry.err = gcexportdata.Read(r, i.fset, i.imports, path)
	return entry.pkg, entry.err
}

// Import implements types.Importer.Import.
func (i *importer) Import(path string) (*types.Package, error) {
	return i.importPackage(path)
}

// errorImporter tracks the last error.
type errorImporter struct {
	*importer
	lastErr error
}

// Import implements types.Importer.Import.
func (i *errorImporter) Import(path string) (*types.Package, error) {
	pkg, err := i.importer.importPackage(path)
	if err != nil {
		i.lastErr = err
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
		Error:    func(error) {},
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
	if err != nil && ei.lastErr != ErrSkip {
		return nil, nil, nil, fmt.Errorf("error checking types: %w", err)
	}

	// Note that facts should be reconcilable between types as of go/tools
	// commit ee04797aa0b6be5ce3d5f7ac0f91e34716b3acdf. We previously used
	// to do a sanity check to ensure that binary import data was
	// compatible with ast-derived data, but this is no longer necessary.
	// If packages are available locally, we can refer to those directly.
	astFacts := facts.NewPackage()

	// Recursively visit all analyzers.
	var (
		resultsMu sync.RWMutex // protects results & errs, findings.
		factsMu   sync.RWMutex // protects facts.
		ready     = make(map[*analysis.Analyzer]*sync.WaitGroup)
		results   = make(map[*analysis.Analyzer]any)
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
						if f := i.fastFacts(pkg); f != nil {
							return f.ImportFact(nil, ptr)
						}
						return false
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
						if f := i.fastFacts(pkg); f != nil {
							return f.ImportFact(obj, ptr)
						}
						return false
					}
					factsMu.RLock()
					defer factsMu.RUnlock()
					return astFacts.ImportFact(obj, ptr)
				},
				ExportObjectFact: func(obj types.Object, fact analysis.Fact) {
					if obj == nil {
						// Tried to export nil object?
						return
					}
					if obj.Pkg() != astPackage {
						// This is not allowed: the
						// built-in facts library will
						// also panic in this case.
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
						otherFacts := i.fastFacts(importedPkg)
						if otherFacts == nil {
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
					for obj := range astFacts.Objects {
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
				result any
				err    error
			)
			defer func() {
				if r := recover(); r != nil {
					// In order to make the multiple
					// analyzers running concurrently
					// debuggable, capture panic exceptions
					// and propagate as an analyzer error.
					err = fmt.Errorf("panic recovered: %s (%s)", r, debug.Stack())
					resultsMu.RUnlock() // +checklocksignore
				}
				resultsMu.Lock()
				findings = append(findings, localFindings...)
				results[a] = result
				errs[a] = err
				resultsMu.Unlock()
			}()
			found := findAnalyzer(a)
			resultsMu.RLock()
			if ba, ok := found.(binaryAnalyzer); ok {
				// Load the binary and analyze.
				rc, loadErr := i.findArchive(path)
				if loadErr != nil {
					if loadErr != ErrSkip {
						err = loadErr
					} else {
						err = nil // Ignore.
					}
				} else {
					result, err = ba.Run(p, rc)
					rc.Close()
				}
			} else {
				result, err = a.Run(p)
			}
			resultsMu.RUnlock()
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
			filename := ""
			if len(srcs) > 0 {
				filename = srcs[0]
			}
			findings = append(findings, Finding{
				Category: a.Name,
				Position: token.Position{Filename: filename},
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

// Package runs all analyzer on a single package.
func Package(path string, srcs []string) (FindingSet, facts.Serializer, error) {
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

// allFactsAndFindings returns all factsAndFindings from an importer.
func (i *importer) allFactsAndFindings() (FindingSet, *facts.Bundle) {
	var (
		findings = make(FindingSet, 0)
		allFacts = facts.NewBundle()
	)
	for path, entry := range i.cache {
		findings = append(findings, entry.findings...)
		allFacts.Add(path, entry.facts)
	}
	return findings, allFacts
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
	_, allFacts := i.allFactsAndFindings()
	return facts.Resolve(pkg, localFacts, allFacts, allFactNames)
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

		// Ignore any files with /testdata/ in the path.
		if strings.Contains(filename, "/testdata/") {
			continue
		}

		// Ignore all test files since they *may* be in a different
		// package than the rest of the sources.
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}

		// Skip the "builtin" package, which is only for docs and not a
		// real package. Attempting type checking goes crazy.
		if pkg == "builtin" {
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
	"sync/atomic": {}, // https://go.dev/issue/50860
}

// Bundle checks a bundle of files (typically the standard library).
func Bundle(sources map[string][]string) (FindingSet, facts.Serializer, error) {
	// Process all packages.
	i := &importer{
		fset:    token.NewFileSet(),
		sources: sources,
		cache:   make(map[string]*importerEntry),
		imports: make(map[string]*types.Package),
	}
	for pkg := range sources {
		// Was there an error processing this package?
		if _, err := i.importPackage(pkg); err != nil && err != ErrSkip {
			return nil, nil, err
		}
	}

	findings, facts := i.allFactsAndFindings()
	return findings, facts, nil
}
