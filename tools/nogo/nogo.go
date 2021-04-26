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

// Package nogo implements binary analysis similar to bazel's nogo,
// or the unitchecker package. It exists in order to provide additional
// facilities for analysis, namely plumbing through the output from
// dumping the generated binary (to analyze actual produced code).
package nogo

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/facts"
	"golang.org/x/tools/go/gcexportdata"

	// Special case: flags live here and change overall behavior.
	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/worker"
)

// StdlibConfig is serialized as the configuration.
//
// This contains everything required for stdlib analysis.
type StdlibConfig struct {
	Srcs   []string
	GOOS   string
	GOARCH string
	Tags   []string
}

// PackageConfig is serialized as the configuration.
//
// This contains everything required for single package analysis.
type PackageConfig struct {
	ImportPath  string
	GoFiles     []string
	NonGoFiles  []string
	Tags        []string
	GOOS        string
	GOARCH      string
	ImportMap   map[string]string
	FactMap     map[string]string
	StdlibFacts string
}

// loader is a fact-loader function.
type loader func(string) ([]byte, error)

// saver is a fact-saver function.
type saver func([]byte) error

// stdlibFact is used for serialiation.
type stdlibFact struct {
	Package string
	Facts   []byte
}

// stdlibFacts is a set of standard library facts.
type stdlibFacts map[string][]byte

// Size implements worker.Sizer.Size.
func (sf stdlibFacts) Size() int64 {
	size := int64(0)
	for filename, data := range sf {
		size += int64(len(filename))
		size += int64(len(data))
	}
	return size
}

// EncodeTo serializes stdlibFacts.
func (sf stdlibFacts) EncodeTo(w io.Writer) error {
	stdlibFactsSorted := make([]stdlibFact, 0, len(sf))
	for pkg, facts := range sf {
		stdlibFactsSorted = append(stdlibFactsSorted, stdlibFact{
			Package: pkg,
			Facts:   facts,
		})
	}
	sort.Slice(stdlibFactsSorted, func(i, j int) bool {
		return stdlibFactsSorted[i].Package < stdlibFactsSorted[j].Package
	})
	enc := gob.NewEncoder(w)
	if err := enc.Encode(stdlibFactsSorted); err != nil {
		return err
	}
	return nil
}

// DecodeFrom deserializes stdlibFacts.
func (sf stdlibFacts) DecodeFrom(r io.Reader) error {
	var stdlibFactsSorted []stdlibFact
	dec := gob.NewDecoder(r)
	if err := dec.Decode(&stdlibFactsSorted); err != nil {
		return err
	}
	for _, stdlibFact := range stdlibFactsSorted {
		sf[stdlibFact.Package] = stdlibFact.Facts
	}
	return nil
}

var (
	// cachedFacts caches by file (just byte data).
	cachedFacts = worker.NewCache("facts")

	// stdlibCachedFacts caches the standard library (stdlibFacts).
	stdlibCachedFacts = worker.NewCache("stdlib")
)

// factLoader loads facts.
func (c *PackageConfig) factLoader(path string) (data []byte, err error) {
	filename, ok := c.FactMap[path]
	if ok {
		cb := cachedFacts.Lookup([]string{filename}, func() worker.Sizer {
			data, readErr := ioutil.ReadFile(filename)
			if readErr != nil {
				err = fmt.Errorf("error loading %q: %w", filename, readErr)
				return nil
			}
			return worker.CacheBytes(data)
		})
		if cb != nil {
			return []byte(cb.(worker.CacheBytes)), err
		}
		return nil, err
	}
	cb := stdlibCachedFacts.Lookup([]string{c.StdlibFacts}, func() worker.Sizer {
		r, openErr := os.Open(c.StdlibFacts)
		if openErr != nil {
			err = fmt.Errorf("error loading stdlib facts from %q: %w", c.StdlibFacts, openErr)
			return nil
		}
		defer r.Close()
		sf := make(stdlibFacts)
		if readErr := sf.DecodeFrom(r); readErr != nil {
			err = fmt.Errorf("error loading stdlib facts: %w", readErr)
			return nil
		}
		return sf
	})
	if cb != nil {
		return (cb.(stdlibFacts))[path], err
	}
	return nil, err
}

// shouldInclude indicates whether the file should be included.
//
// NOTE: This does only basic parsing of tags.
func (c *PackageConfig) shouldInclude(path string) (bool, error) {
	ctx := build.Default
	ctx.GOOS = c.GOOS
	ctx.GOARCH = c.GOARCH
	ctx.BuildTags = c.Tags
	return ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
}

// importer is an implementation of go/types.Importer.
//
// This wraps a configuration, which provides the map of package names to
// files, and the facts. Note that this importer implementation will always
// pass when a given package is not available.
type importer struct {
	*PackageConfig
	fset     *token.FileSet
	cache    map[string]*types.Package
	lastErr  error
	callback func(string) error
}

// Import implements types.Importer.Import.
func (i *importer) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		// Special case: go/types has pre-defined type information for
		// unsafe. We ensure that this package is correct, in case any
		// analyzers are specifically looking for this.
		return types.Unsafe, nil
	}

	// Call the internal callback. This is used to resolve loading order
	// for the standard library. See checkStdlib.
	if i.callback != nil {
		if err := i.callback(path); err != nil {
			i.lastErr = err
			return nil, err
		}
	}

	// Actually load the data.
	realPath, ok := i.ImportMap[path]
	var (
		rc  io.ReadCloser
		err error
	)
	if !ok {
		// Not found in the import path. Attempt to find the package
		// via the standard library.
		rc, err = findStdPkg(i.GOOS, i.GOARCH, path)
	} else {
		// Open the file.
		rc, err = os.Open(realPath)
	}
	if err != nil {
		i.lastErr = err
		return nil, err
	}
	defer rc.Close()

	// Load all exported data.
	r, err := gcexportdata.NewReader(rc)
	if err != nil {
		return nil, err
	}

	return gcexportdata.Read(r, i.fset, i.cache, path)
}

// ErrSkip indicates the package should be skipped.
var ErrSkip = errors.New("skipped")

// CheckStdlib checks the standard library.
//
// This constructs a synthetic package configuration for each library in the
// standard library sources, and call CheckPackage repeatedly.
//
// Note that not all parts of the source are expected to build. We skip obvious
// test files, and cmd files, which should not be dependencies.
func CheckStdlib(config *StdlibConfig, analyzers []*analysis.Analyzer) (allFindings FindingSet, facts []byte, err error) {
	if len(config.Srcs) == 0 {
		return nil, nil, nil
	}

	// Ensure all paths are normalized.
	for i := 0; i < len(config.Srcs); i++ {
		config.Srcs[i] = path.Clean(config.Srcs[i])
	}

	// Calculate the root source directory. This is always a directory
	// named 'src', of which we simply take the first we find. This is a
	// bit fragile, but works for all currently known Go source
	// configurations.
	//
	// Note that there may be extra files outside of the root source
	// directory; we simply ignore those.
	rootSrcPrefix := ""
	for _, file := range config.Srcs {
		const src = "/src/"
		i := strings.Index(file, src)
		if i == -1 {
			// Superfluous file.
			continue
		}

		// Index of first character after /src/.
		i += len(src)
		rootSrcPrefix = file[:i]
		break
	}

	// Aggregate all files by directory.
	packages := make(map[string]*PackageConfig)
	for _, file := range config.Srcs {
		if !strings.HasPrefix(file, rootSrcPrefix) {
			// Superflouous file.
			continue
		}

		d := path.Dir(file)
		if len(rootSrcPrefix) >= len(d) {
			continue // Not a file.
		}
		pkg := d[len(rootSrcPrefix):]
		// Skip cmd packages and obvious test files: see above.
		if strings.HasPrefix(pkg, "cmd/") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		c, ok := packages[pkg]
		if !ok {
			c = &PackageConfig{
				ImportPath: pkg,
				GOOS:       config.GOOS,
				GOARCH:     config.GOARCH,
				Tags:       config.Tags,
			}
			packages[pkg] = c
		}
		// Add the files appropriately. Note that they will be further
		// filtered by architecture and build tags below, so this need
		// not be done immediately.
		if strings.HasSuffix(file, ".go") {
			c.GoFiles = append(c.GoFiles, file)
		} else {
			c.NonGoFiles = append(c.NonGoFiles, file)
		}
	}

	// Closure to check a single package.
	localStdlibFacts := make(stdlibFacts)
	localStdlibErrs := make(map[string]error)
	var checkOne func(pkg string) error // Recursive.
	checkOne = func(pkg string) error {
		// Is this already done?
		if _, ok := localStdlibFacts[pkg]; ok {
			return nil
		}
		// Did this fail previously?
		if _, ok := localStdlibErrs[pkg]; ok {
			return nil
		}

		// Lookup the configuration.
		config, ok := packages[pkg]
		if !ok {
			return nil // Not known.
		}

		// Find the binary package, and provide to objdump.
		rc, err := findStdPkg(config.GOOS, config.GOARCH, pkg)
		if err != nil {
			// If there's no binary for this package, it is likely
			// not built with the distribution. That's fine, we can
			// just skip analysis.
			localStdlibErrs[pkg] = err
			return nil
		}

		// Provide the input.
		oldReader := checkescape.Reader
		checkescape.Reader = rc // For analysis.
		defer func() {
			rc.Close()
			checkescape.Reader = oldReader // Restore.
		}()

		// Run the analysis.
		findings, factData, err := CheckPackage(config, analyzers, checkOne)
		if err != nil {
			// If we can't analyze a package from the standard library,
			// then we skip it. It will simply not have any findings.
			localStdlibErrs[pkg] = err
			return nil
		}
		localStdlibFacts[pkg] = factData
		allFindings = append(allFindings, findings...)
		return nil
	}

	// Check all packages.
	//
	// Note that this may call checkOne recursively, so it's not guaranteed
	// to evaluate in the order provided here. We do ensure however, that
	// all packages are evaluated.
	for pkg := range packages {
		if err := checkOne(pkg); err != nil {
			return nil, nil, err
		}
	}

	// Sanity check.
	if len(localStdlibFacts) == 0 {
		return nil, nil, fmt.Errorf("no stdlib facts found: misconfiguration?")
	}

	// Write out all findings.
	buf := bytes.NewBuffer(nil)
	if err := localStdlibFacts.EncodeTo(buf); err != nil {
		return nil, nil, fmt.Errorf("error serialized stdlib facts: %v", err)
	}

	// Write out all errors.
	for pkg, err := range localStdlibErrs {
		log.Printf("WARNING: error while processing %v: %v", pkg, err)
	}

	// Return all findings.
	return allFindings, buf.Bytes(), nil
}

// CheckPackage runs all given analyzers.
//
// The implementation was adapted from [1], which was in turn adpated from [2].
// This returns a list of matching analysis issues, or an error if the analysis
// could not be completed.
//
// [1] bazelbuid/rules_go/tools/builders/nogo_main.go
// [2] golang.org/x/tools/go/checker/internal/checker
func CheckPackage(config *PackageConfig, analyzers []*analysis.Analyzer, importCallback func(string) error) (findings []Finding, factData []byte, err error) {
	imp := &importer{
		PackageConfig: config,
		fset:          token.NewFileSet(),
		cache:         make(map[string]*types.Package),
		callback:      importCallback,
	}

	// Load all source files.
	var syntax []*ast.File
	for _, file := range config.GoFiles {
		include, err := config.shouldInclude(file)
		if err != nil {
			return nil, nil, fmt.Errorf("error evaluating file %q: %v", file, err)
		}
		if !include {
			continue
		}
		s, err := parser.ParseFile(imp.fset, file, nil, parser.ParseComments)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing file %q: %v", file, err)
		}
		syntax = append(syntax, s)
	}

	// Check type information.
	typesSizes := types.SizesFor("gc", config.GOARCH)
	typeConfig := types.Config{Importer: imp}
	typesInfo := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
		Defs:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	types, err := typeConfig.Check(config.ImportPath, imp.fset, syntax, typesInfo)
	if err != nil && imp.lastErr != ErrSkip {
		return nil, nil, fmt.Errorf("error checking types: %w", err)
	}

	// Load all package facts.
	facts, err := facts.Decode(types, config.factLoader)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding facts: %w", err)
	}

	// Register fact types and establish dependencies between analyzers.
	// The visit closure will execute recursively, and populate results
	// will all required analysis results.
	results := make(map[*analysis.Analyzer]interface{})
	var visit func(*analysis.Analyzer) error // For recursion.
	visit = func(a *analysis.Analyzer) error {
		if _, ok := results[a]; ok {
			return nil
		}

		// Run recursively for all dependencies.
		for _, req := range a.Requires {
			if err := visit(req); err != nil {
				return err
			}
		}

		// Run the analysis.
		factFilter := make(map[reflect.Type]bool)
		for _, f := range a.FactTypes {
			factFilter[reflect.TypeOf(f)] = true
		}
		p := &analysis.Pass{
			Analyzer:  a,
			Fset:      imp.fset,
			Files:     syntax,
			Pkg:       types,
			TypesInfo: typesInfo,
			ResultOf:  results, // All results.
			Report: func(d analysis.Diagnostic) {
				findings = append(findings, Finding{
					Category: AnalyzerName(a.Name),
					Position: imp.fset.Position(d.Pos),
					Message:  d.Message,
				})
			},
			ImportPackageFact: facts.ImportPackageFact,
			ExportPackageFact: facts.ExportPackageFact,
			ImportObjectFact:  facts.ImportObjectFact,
			ExportObjectFact:  facts.ExportObjectFact,
			AllPackageFacts:   func() []analysis.PackageFact { return facts.AllPackageFacts(factFilter) },
			AllObjectFacts:    func() []analysis.ObjectFact { return facts.AllObjectFacts(factFilter) },
			TypesSizes:        typesSizes,
		}
		result, err := a.Run(p)
		if err != nil {
			return fmt.Errorf("error running analysis %s: %v", a, err)
		}

		// Sanity check & save the result.
		if got, want := reflect.TypeOf(result), a.ResultType; got != want {
			return fmt.Errorf("error: analyzer %s returned a result of type %v, but declared ResultType %v", a, got, want)
		}
		results[a] = result
		return nil // Success.
	}

	// Visit all analyzers recursively.
	for _, a := range analyzers {
		if imp.lastErr == ErrSkip {
			continue // No local analysis.
		}
		if err := visit(a); err != nil {
			return nil, nil, err // Already has context.
		}
	}

	// Return all findings.
	return findings, facts.Encode(), nil
}

func init() {
	gob.Register((*stdlibFact)(nil))
}
