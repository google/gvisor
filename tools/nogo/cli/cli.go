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

// Package cli implements a basic command line interface.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"text/template"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	yaml "gopkg.in/yaml.v2"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/nogo/check"
	"gvisor.dev/gvisor/tools/nogo/config"
	"gvisor.dev/gvisor/tools/nogo/facts"
	"gvisor.dev/gvisor/tools/nogo/flags"
)

// openOutput opens an output file.
func openOutput(filename string, def *os.File) (*os.File, error) {
	if filename == "" {
		if def != nil {
			return def, nil
		}
		filename = "/dev/null" // Sink.
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		// See above.
		return nil, err
	}
	return f, nil
}

// closeOutput closes an output if necessary.
//
// If an error occurs during close, this function will panic.
func closeOutput(w io.Writer) {
	if c, ok := w.(io.Closer); ok {
		if err := c.Close(); err != nil {
			panic(err)
		}
	}
}

// failure exits with the given failure message.
func failure(fmtStr string, v ...any) subcommands.ExitStatus {
	fmt.Fprintf(os.Stderr, fmtStr+"\n", v...)
	return subcommands.ExitFailure
}

// isTerminal return true if the file is a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// collectAllFiles collects all files from a directory tree.
func collectAllFiles(dir string) (files []string, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return
}

// checkCommon is a common set of flags for check-like commands.
type checkCommon struct {
	Facts    string
	Findings string
	Text     bool
}

// setFlags may be called by embedding types.
//
// Note that the default file names here depend on the command name. See init
// at the bottom, where this files will be registered if they exist already.
func (c *checkCommon) setFlags(fs *flag.FlagSet, commandType string) {
	fs.StringVar(&c.Facts, "facts", fmt.Sprintf(".nogo.%s.facts", commandType), "facts output file (optional)")
	fs.StringVar(&c.Findings, "findings", "", "findings output file (optional)")
	fs.BoolVar(&c.Text, "text", false, "force text output (by default, only if output is a terminal)")
}

// execute runs the common bits for a check command.
func (c *checkCommon) execute(fn func() (check.FindingSet, facts.Serializer, error)) error {
	// Open outputs.
	factsOutput, err := openOutput(c.Facts, nil)
	if err != nil {
		return fmt.Errorf("opening facts: %w", err)
	}
	defer closeOutput(factsOutput)
	findingsOutput, err := openOutput(c.Findings, os.Stdout)
	if err != nil {
		return fmt.Errorf("opening findings: %w", err)
	}
	defer closeOutput(findingsOutput)

	// Perform the analysis.
	findings, factData, err := fn()
	if err != nil {
		return err
	}

	// Save the data.
	if err := factData.Serialize(factsOutput); err != nil {
		return fmt.Errorf("writing facts: %w", err)
	}
	if !c.Text && !isTerminal(findingsOutput) {
		// Write in the default internal format (GOB encoded).
		if err := check.WriteFindingsTo(findingsOutput, findings, false /* json */); err != nil {
			return fmt.Errorf("writing findings: %w", err)
		}
	} else {
		// Use a human readable text.
		for _, finding := range findings {
			fmt.Fprintf(findingsOutput, "%s\n", finding.String())
		}
	}

	return nil
}

// Check implements subcommands.Command for the "check" command.
type Check struct {
	checkCommon
	Package string
	Binary  string
}

// Name implements subcommands.Command.Name.
func (*Check) Name() string {
	return "check"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Check) Synopsis() string {
	return "Generate facts and findings for a specific named package and sources."
}

// Usage implements subcommands.Command.Usage.
func (*Check) Usage() string {
	return `check <srcs...>

	Generates facts and findings for a specific named package and sources.
	This command should generally be considered a "low-level" command, and
	it is recommend that you use bundle or mod instead.

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Check) SetFlags(fs *flag.FlagSet) {
	c.setFlags(fs, "check")
	fs.StringVar(&c.Package, "package", "", "package for analysis (required)")
}

// Execute implements subcommands.Command.Execute.
func (c *Check) Execute(ctx context.Context, fs *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if c.Package == "" {
		c.Package = "main" // Default, no imports.
	}

	// Perform the analysis.
	if err := c.execute(func() (check.FindingSet, facts.Serializer, error) {
		return check.Package(c.Package /* path */, fs.Args() /* srcs */)
	}); err != nil {
		return failure("%v", err)
	}

	return subcommands.ExitSuccess
}

// Bundle implements subcommands.Command for the "bundle" command.
type Bundle struct {
	checkCommon
	Root   string
	Prefix string
}

// Name implements subcommands.Command.Name.
func (*Bundle) Name() string {
	return "bundle"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Bundle) Synopsis() string {
	return "Generate facts and findings for a set of sources."
}

// Usage implements subcommands.Command.Usage.
func (*Bundle) Usage() string {
	return `bundle <srcs...>

	Generates facts and findings for a collection of source files. Each
	package name is inferred from the path, assuming a standard package
	structure. The stripped prefix is determined by regular expression.

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (b *Bundle) SetFlags(fs *flag.FlagSet) {
	b.setFlags(fs, "bundle")
	fs.StringVar(&b.Root, "root", "", "root regular expression (for package discovery)")
	fs.StringVar(&b.Prefix, "prefix", "", "package prefix to apply (for complete names)")
}

// Execute implements subcommands.Command.Execute.
func (b *Bundle) Execute(ctx context.Context, fs *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Perform the analysis.
	if err := b.execute(func() (check.FindingSet, facts.Serializer, error) {
		// Discover the correct common root.
		srcRootPrefix, err := check.FindRoot(fs.Args(), b.Root)
		if err != nil {
			return nil, nil, err
		}
		// Split into packages.
		sources := make(map[string][]string)
		for pkg, srcs := range check.SplitPackages(fs.Args(), srcRootPrefix) {
			path := pkg
			if b.Prefix != "" {
				path = b.Prefix + "/" + path // Subpackage.
			}
			sources[path] = append(sources[path], srcs...)
		}
		return check.Bundle(sources)
	}); err != nil {
		return failure("%v", err)
	}

	return subcommands.ExitSuccess
}

// Stdlib implements subcommands.Command for the "stdlib" command.
type Stdlib struct {
	checkCommon
}

// Name implements subcommands.Command.Name.
func (*Stdlib) Name() string {
	return "stdlib"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Stdlib) Synopsis() string {
	return "Generate facts and findings for the standard library."
}

// Usage implements subcommands.Command.Usage.
func (*Stdlib) Usage() string {
	return `stdlib

	Generates facts and findings for the standard library. This wraps
	bundle with a mechansim that discovers the standard library source.

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Stdlib) SetFlags(fs *flag.FlagSet) {
	s.setFlags(fs, "stdlib")
}

// Execute implements subcommands.Command.Execute.
func (s *Stdlib) Execute(ctx context.Context, fs *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if fs.NArg() != 0 {
		return subcommands.ExitUsageError // Need no arguments.
	}

	if err := s.execute(func() (check.FindingSet, facts.Serializer, error) {
		root, err := flags.Env("GOROOT")
		if err != nil {
			return nil, nil, err
		}
		root = path.Join(root, "src")
		srcs, err := collectAllFiles(root)
		if err != nil {
			return nil, nil, err
		}
		return check.Bundle(check.SplitPackages(srcs, root))
	}); err != nil {
		return failure("%v", err)
	}

	return subcommands.ExitSuccess
}

// Filter implements subcommands.Command for the "filter" command.
type Filter struct {
	Configs flags.StringList
	Output  string
	Text    bool
	Test    bool
}

// Name implements subcommands.Command.Name.
func (*Filter) Name() string {
	return "filter"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Filter) Synopsis() string {
	return "Filters findings based on merged configurations."
}

// Usage implements subcommands.Command.Usage.
func (*Filter) Usage() string {
	return `filter [findings...]

	Merges the set of provided configurations and applies to all findings.
	The filtered findings are merged and written to the output.

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (f *Filter) SetFlags(fs *flag.FlagSet) {
	fs.Var(&f.Configs, "config", "filter configuration files (in JSON format)")
	fs.StringVar(&f.Output, "output", "", "findings output (in JSON format by default, unless attached to a terminal)")
	fs.BoolVar(&f.Text, "text", false, "force text format in all cases (even not attached to a terminal)")
	fs.BoolVar(&f.Test, "test", false, "exit with non-zero status if findings are not empty")
}

func loadFindings(filename string) (check.FindingSet, error) {
	r, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open input: %w", err)
	}
	inputFindings, err := check.ExtractFindingsFrom(r, false /* json */)
	if err != nil {
		// Seek to reread the file.
		if _, err := r.Seek(0, os.SEEK_SET); err != nil {
			return nil, fmt.Errorf("unable to reseek in findings %q: %w", filename, err)
		}
		// Attempt to interpret as a json input.
		inputFindings, err = check.ExtractFindingsFrom(r, true /* json */)
		if err != nil {
			return nil, fmt.Errorf("unable to extract findings from %q: %w", filename, err)
		}
	}
	return inputFindings, nil
}

func loadConfig(filename string) (*config.Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open config: %w", err)
	}
	var newConfig config.Config // For current file.
	dec := yaml.NewDecoder(f)
	dec.SetStrict(true)
	if err := dec.Decode(&newConfig); err != nil {
		return nil, fmt.Errorf("unable to decode %q: %w", filename, err)
	}
	return &newConfig, nil
}

func loadConfigs(filenames []string) (*config.Config, error) {
	config := &config.Config{
		Global:    make(config.AnalyzerConfig),
		Analyzers: make(map[string]config.AnalyzerConfig),
	}
	for _, filename := range filenames {
		next, err := loadConfig(filename)
		if err != nil {
			return nil, err
		}
		config.Merge(next)
	}
	if err := config.Compile(); err != nil {
		return nil, fmt.Errorf("error compiling config: %w", err)
	}
	return config, nil
}

// Execute implements subcommands.Command.Execute.
func (f *Filter) Execute(ctx context.Context, fs *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Open and merge all configuations.
	config, err := loadConfigs(f.Configs)
	if err != nil {
		return failure("unable to load configurations: %v", err)
	}

	// Open the output file.
	output, err := openOutput(f.Output, os.Stdout)
	if err != nil {
		return failure("opening output: %v", err)
	}
	defer closeOutput(output)

	// Load and filer available findings.
	var filteredFindings check.FindingSet
	for _, filename := range fs.Args() {
		// Note that this applies a caching strategy to the filtered
		// findings, because *this is by far the most expensive part of
		// evaluation*. The set of findings is large and applying the
		// configuration is complex. Therefore, we segment this cache
		// on each individual raw findings input file and the
		// configuration files. Note that this cache is keyed on all
		// the configuration files and each individual raw findings, so
		// is guaranteed to be safe. This allows us to reuse the same
		// filter result many times over, because e.g. all standard
		// library findings will be available to all packages.
		inputFindings, err := loadFindings(filename)
		if err != nil {
			return failure("unable to load findings from %q: %v", filename, err)
		}
		for _, finding := range inputFindings {
			if ok := config.ShouldReport(finding); ok {
				filteredFindings = append(filteredFindings, finding)
			}
		}
	}

	// Write the output.
	if !f.Text && !isTerminal(output) {
		if err := check.WriteFindingsTo(output, filteredFindings, true /* json */); err != nil {
			return failure("write findings: %v", err)
		}
	} else {
		for _, finding := range filteredFindings {
			fmt.Fprintf(output, "%s\n", finding.String())
		}
	}

	// Treat the run as a test?
	if (f.Text || isTerminal(output)) && f.Test && len(filteredFindings) == 0 {
		fmt.Fprintf(output, "PASS\n")
	}
	if f.Test && len(filteredFindings) > 0 {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

// Render implements subcommands.Command for the "render" command.
type Render struct {
	Template string
	Output   string
}

// Name implements subcommands.Command.Name.
func (*Render) Name() string {
	return "render"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Render) Synopsis() string {
	return "Renders facts about a package using a template."
}

// Usage implements subcommands.Command.Usage.
func (*Render) Usage() string {
	return `render <srcs...>

	Loads all data and renders all known facts. Note that render is not
	currently compatible with binary analyzers, and these facts will not
	be included (unless they come from dependencies).

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Render) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&r.Template, "template", "", "text template file for rendering (required)")
	fs.StringVar(&r.Output, "output", "", "output file for rendering (or empty for stdout)")
}

// Execute implements subcommands.Command.Execute.
func (r *Render) Execute(ctx context.Context, fs *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Open the output file.
	output, err := openOutput(r.Output, os.Stdout)
	if err != nil {
		return failure("opening output: %v", err)
	}
	defer closeOutput(output)

	// Open the template file.
	t, err := template.ParseFiles(r.Template)
	if err != nil {
		return failure("loading template: %v", err)
	}

	// Process the facts.
	facts, err := check.Facts("main", fs.Args())
	if err != nil {
		return failure("%v", err)
	}

	// Render as a template.
	if err := t.Execute(output, facts); err != nil {
		return failure("during render: %v", err)
	}

	return subcommands.ExitSuccess
}

// Main is the main entrypoint.
func Main() {
	subcommands.Register(&Check{}, "")
	subcommands.Register(&Bundle{}, "")
	subcommands.Register(&Stdlib{}, "")
	subcommands.Register(&Filter{}, "")
	subcommands.Register(&Render{}, "")
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	flag.CommandLine.Parse(os.Args[1:])
	os.Exit(int(subcommands.Execute(context.Background())))
}
