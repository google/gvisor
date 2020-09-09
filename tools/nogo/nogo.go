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
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/facts"
	"golang.org/x/tools/go/gcexportdata"
	"gvisor.dev/gvisor/tools/nogo/dump"
)

// stdlibConfig is serialized as the configuration.
//
// This contains everything required for stdlib analysis.
type stdlibConfig struct {
	Srcs       []string
	GOOS       string
	GOARCH     string
	Tags       []string
	FactOutput string
}

// packageConfig is serialized as the configuration.
//
// This contains everything required for single package analysis.
type packageConfig struct {
	ImportPath  string
	GoFiles     []string
	NonGoFiles  []string
	Tags        []string
	GOOS        string
	GOARCH      string
	ImportMap   map[string]string
	FactMap     map[string]string
	FactOutput  string
	StdlibFacts string
}

// loader is a fact-loader function.
type loader func(string) ([]byte, error)

// saver is a fact-saver function.
type saver func([]byte) error

// factLoader returns a function that loads facts.
//
// This resolves all standard library facts and imported package facts up
// front. The returned loader function will never return an error, only
// empty facts.
//
// This is done because all stdlib data is stored together, and we don't want
// to load this data many times over.
func (c *packageConfig) factLoader() (loader, error) {
	allFacts := make(map[string][]byte)
	if c.StdlibFacts != "" {
		data, err := ioutil.ReadFile(c.StdlibFacts)
		if err != nil {
			return nil, fmt.Errorf("error loading stdlib facts from %q: %w", c.StdlibFacts, err)
		}
		var stdlibFacts map[string][]byte
		if err := json.Unmarshal(data, &stdlibFacts); err != nil {
			return nil, fmt.Errorf("error loading stdlib facts: %w", err)
		}
		for pkg, data := range stdlibFacts {
			allFacts[pkg] = data
		}
	}
	for pkg, file := range c.FactMap {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %w", file, err)
		}
		allFacts[pkg] = data
	}
	return func(path string) ([]byte, error) {
		return allFacts[path], nil
	}, nil
}

// factSaver may be used directly as a saver.
func (c *packageConfig) factSaver(factData []byte) error {
	if c.FactOutput == "" {
		return nil // Nothing to save.
	}
	return ioutil.WriteFile(c.FactOutput, factData, 0644)
}

// shouldInclude indicates whether the file should be included.
//
// NOTE: This does only basic parsing of tags.
func (c *packageConfig) shouldInclude(path string) (bool, error) {
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
	*packageConfig
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

// checkStdlib checks the standard library.
//
// This constructs a synthetic package configuration for each library in the
// standard library sources, and call checkPackage repeatedly.
//
// Note that not all parts of the source are expected to build. We skip obvious
// test files, and cmd files, which should not be dependencies.
func checkStdlib(config *stdlibConfig) ([]string, error) {
	if len(config.Srcs) == 0 {
		return nil, nil
	}

	// Ensure all paths are normalized.
	for i := 0; i < len(config.Srcs); i++ {
		config.Srcs[i] = path.Clean(config.Srcs[i])
	}

	// Calculate the root directory.
	longestPrefix := path.Dir(config.Srcs[0])
	for _, file := range config.Srcs[1:] {
		for i := 0; i < len(file) && i < len(longestPrefix); i++ {
			if file[i] != longestPrefix[i] {
				// Truncate here; will stop the loop.
				longestPrefix = longestPrefix[:i]
				break
			}
		}
	}
	if len(longestPrefix) > 0 && longestPrefix[len(longestPrefix)-1] != '/' {
		longestPrefix += "/"
	}

	// Aggregate all files by directory.
	packages := make(map[string]*packageConfig)
	for _, file := range config.Srcs {
		d := path.Dir(file)
		if len(longestPrefix) >= len(d) {
			continue // Not a file.
		}
		pkg := path.Dir(file)[len(longestPrefix):]
		// Skip cmd packages and obvious test files: see above.
		if strings.HasPrefix(pkg, "cmd/") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		c, ok := packages[pkg]
		if !ok {
			c = &packageConfig{
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
	allFindings := make([]string, 0)
	stdlibFacts := make(map[string][]byte)
	var checkOne func(pkg string) error // Recursive.
	checkOne = func(pkg string) error {
		// Is this already done?
		if _, ok := stdlibFacts[pkg]; ok {
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
			return nil
		}

		// Provide the input.
		oldReader := dump.Reader
		dump.Reader = rc // For analysis.
		defer func() {
			rc.Close()
			dump.Reader = oldReader // Restore.
		}()

		// Run the analysis.
		findings, err := checkPackage(config, func(factData []byte) error {
			stdlibFacts[pkg] = factData
			return nil
		}, checkOne)
		if err != nil {
			// If we can't analyze a package from the standard library,
			// then we skip it. It will simply not have any findings.
			return nil
		}
		allFindings = append(allFindings, findings...)
		return nil
	}

	// Check all packages.
	//
	// Note that this may call checkOne recursively, so it's not guaranteed
	// to evaluate in the order provided here. We do ensure however, that
	// all packages are evaluated.
	for pkg := range packages {
		checkOne(pkg)
	}

	// Write out all findings.
	factData, err := json.Marshal(stdlibFacts)
	if err != nil {
		return nil, fmt.Errorf("error saving stdlib facts: %w", err)
	}
	if err := ioutil.WriteFile(config.FactOutput, factData, 0644); err != nil {
		return nil, fmt.Errorf("error saving findings to %q: %v", config.FactOutput, err)
	}

	// Return all findings.
	return allFindings, nil
}

// checkPackage runs all analyzers.
//
// The implementation was adapted from [1], which was in turn adpated from [2].
// This returns a list of matching analysis issues, or an error if the analysis
// could not be completed.
//
// [1] bazelbuid/rules_go/tools/builders/nogo_main.go
// [2] golang.org/x/tools/go/checker/internal/checker
func checkPackage(config *packageConfig, factSaver saver, importCallback func(string) error) ([]string, error) {
	imp := &importer{
		packageConfig: config,
		fset:          token.NewFileSet(),
		cache:         make(map[string]*types.Package),
		callback:      importCallback,
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
	loader, err := config.factLoader()
	if err != nil {
		return nil, fmt.Errorf("error loading facts: %w", err)
	}
	facts, err := facts.Decode(types, loader)
	if err != nil {
		return nil, fmt.Errorf("error decoding facts: %w", err)
	}

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
	factData := facts.Encode()
	if err := factSaver(factData); err != nil {
		return nil, fmt.Errorf("error: unable to save facts: %v", err)
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
	packageFile = flag.String("package", "", "package configuration file (in JSON format)")
	stdlibFile  = flag.String("stdlib", "", "stdlib configuration file (in JSON format)")
)

func loadConfig(file string, config interface{}) interface{} {
	// Load the configuration.
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("unable to open configuration %q: %v", file, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(config); err != nil {
		log.Fatalf("unable to decode configuration: %v", err)
	}
	return config
}

// Main is the entrypoint; it should be called directly from main.
//
// N.B. This package registers it's own flags.
func Main() {
	// Parse all flags.
	flag.Parse()

	var (
		findings []string
		err      error
	)

	// Check the configuration.
	if *packageFile != "" && *stdlibFile != "" {
		log.Fatalf("unable to perform stdlib and package analysis; provide only one!")
	} else if *stdlibFile != "" {
		c := loadConfig(*stdlibFile, new(stdlibConfig)).(*stdlibConfig)
		findings, err = checkStdlib(c)
	} else if *packageFile != "" {
		c := loadConfig(*packageFile, new(packageConfig)).(*packageConfig)
		findings, err = checkPackage(c, c.factSaver, nil)
	} else {
		log.Fatalf("please provide at least one of package or stdlib!")
	}

	// Handle findings & errors.
	if err != nil {
		log.Fatalf("error checking package: %v", err)
	}
	if len(findings) == 0 {
		return
	}

	// Print findings and exit with non-zero code.
	for _, finding := range findings {
		fmt.Fprintf(os.Stdout, "%s\n", finding)
	}
	os.Exit(1)
}
