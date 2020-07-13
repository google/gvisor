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
	"encoding/json"
	"errors"
	"flag"
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
	"path/filepath"
	"reflect"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/facts"
	"golang.org/x/tools/go/gcexportdata"
	"gvisor.dev/gvisor/tools/nogo/data"
)

// pkgConfig is serialized as the configuration.
//
// This contains everything required for the analysis.
type pkgConfig struct {
	ImportPath string
	GoFiles    []string
	NonGoFiles []string
	Tags       []string
	GOOS       string
	GOARCH     string
	ImportMap  map[string]string
	FactMap    map[string]string
	FactOutput string
	Objdump    string
}

// loadFacts finds and loads facts per FactMap.
func (c *pkgConfig) loadFacts(path string) ([]byte, error) {
	realPath, ok := c.FactMap[path]
	if !ok {
		return nil, nil // No facts available.
	}

	// Read the files file.
	data, err := ioutil.ReadFile(realPath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// shouldInclude indicates whether the file should be included.
//
// NOTE: This does only basic parsing of tags.
func (c *pkgConfig) shouldInclude(path string) (bool, error) {
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
	pkgConfig
	fset    *token.FileSet
	cache   map[string]*types.Package
	lastErr error
}

// Import implements types.Importer.Import.
func (i *importer) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		// Special case: go/types has pre-defined type information for
		// unsafe. We ensure that this package is correct, in case any
		// analyzers are specifically looking for this.
		return types.Unsafe, nil
	}
	realPath, ok := i.ImportMap[path]
	var (
		rc  io.ReadCloser
		err error
	)
	if !ok {
		// Not found in the import path. Attempt to find the package
		// via the standard library.
		rc, err = findStdPkg(path, i.GOOS, i.GOARCH)
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

// checkPackage runs all analyzers.
//
// The implementation was adapted from [1], which was in turn adpated from [2].
// This returns a list of matching analysis issues, or an error if the analysis
// could not be completed.
//
// [1] bazelbuid/rules_go/tools/builders/nogo_main.go
// [2] golang.org/x/tools/go/checker/internal/checker
func checkPackage(config pkgConfig) ([]string, error) {
	imp := &importer{
		pkgConfig: config,
		fset:      token.NewFileSet(),
		cache:     make(map[string]*types.Package),
	}

	// Load all source files.
	var syntax []*ast.File
	for _, file := range config.GoFiles {
		include, err := config.shouldInclude(file)
		if err != nil {
			return nil, fmt.Errorf("error evaluating file %q: %v", file, err)
		}
		if !include {
			continue
		}
		s, err := parser.ParseFile(imp.fset, file, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("error parsing file %q: %v", file, err)
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
		return nil, fmt.Errorf("error checking types: %w", err)
	}

	// Load all package facts.
	facts, err := facts.Decode(types, config.loadFacts)
	if err != nil {
		return nil, fmt.Errorf("error decoding facts: %w", err)
	}

	// Set the binary global for use.
	data.Objdump = config.Objdump

	// Register fact types and establish dependencies between analyzers.
	// The visit closure will execute recursively, and populate results
	// will all required analysis results.
	diagnostics := make(map[*analysis.Analyzer][]analysis.Diagnostic)
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

		// Prepare the matcher.
		m := analyzerConfig[a]
		report := func(d analysis.Diagnostic) {
			if m.ShouldReport(d, imp.fset) {
				diagnostics[a] = append(diagnostics[a], d)
			}
		}

		// Run the analysis.
		factFilter := make(map[reflect.Type]bool)
		for _, f := range a.FactTypes {
			factFilter[reflect.TypeOf(f)] = true
		}
		p := &analysis.Pass{
			Analyzer:          a,
			Fset:              imp.fset,
			Files:             syntax,
			Pkg:               types,
			TypesInfo:         typesInfo,
			ResultOf:          results, // All results.
			Report:            report,
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

	// Visit all analysis recursively.
	for a, _ := range analyzerConfig {
		if imp.lastErr == ErrSkip {
			continue // No local analysis.
		}
		if err := visit(a); err != nil {
			return nil, err // Already has context.
		}
	}

	// Write the output file.
	if config.FactOutput != "" {
		factData := facts.Encode()
		if err := ioutil.WriteFile(config.FactOutput, factData, 0644); err != nil {
			return nil, fmt.Errorf("error: unable to open facts output %q: %v", config.FactOutput, err)
		}
	}

	// Convert all diagnostics to strings.
	findings := make([]string, 0, len(diagnostics))
	for a, ds := range diagnostics {
		for _, d := range ds {
			// Include the anlyzer name for debugability and configuration.
			findings = append(findings, fmt.Sprintf("%s: %s: %s", a.Name, imp.fset.Position(d.Pos), d.Message))
		}
	}

	// Return all findings.
	return findings, nil
}

var (
	configFile = flag.String("config", "", "configuration file (in JSON format)")
)

// Main is the entrypoint; it should be called directly from main.
//
// N.B. This package registers it's own flags.
func Main() {
	// Parse all flags.
	flag.Parse()

	// Load the configuration.
	f, err := os.Open(*configFile)
	if err != nil {
		log.Fatalf("unable to open configuration %q: %v", *configFile, err)
	}
	defer f.Close()
	config := new(pkgConfig)
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(config); err != nil {
		log.Fatalf("unable to decode configuration: %v", err)
	}

	// Process the package.
	findings, err := checkPackage(*config)
	if err != nil {
		log.Fatalf("error checking package: %v", err)
	}

	// No findings?
	if len(findings) == 0 {
		os.Exit(0)
	}

	// Print findings and exit with non-zero code.
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s\n", finding)
	}
	os.Exit(1)
}
