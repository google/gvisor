// Copyright 2026 The gVisor Authors.
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

// Binary assemble creates the source archive published on the Go branch.
package main

import (
	"archive/zip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

const readme = `# gVisor

This branch is a synthetic branch, containing only Go sources, that is
compatible with standard Go tools. See the master branch for authoritative
sources and tests.
`

func readEntry(entry *zip.File) ([]byte, error) {
	r, err := entry.Open()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	return data, errors.Join(err, r.Close())
}

func assemble(gopath, goMod string, extraFiles []string, output io.Writer) error {
	data, err := os.ReadFile(goMod)
	if err != nil {
		return err
	}
	module, err := modfile.Parse(goMod, data, nil)
	if err != nil {
		return err
	}
	if module.Module == nil {
		return fmt.Errorf("%s has no module directive", goMod)
	}
	archive, err := zip.OpenReader(gopath)
	if err != nil {
		return err
	}
	defer archive.Close()

	prefix := "src/" + module.Module.Mod.Path + "/"
	files := make(map[string][]byte)
	for _, entry := range archive.File {
		name, ok := strings.CutPrefix(entry.Name, prefix)
		if !ok || entry.FileInfo().IsDir() {
			continue
		}
		if !fs.ValidPath(name) {
			return fmt.Errorf("invalid source archive path %q", entry.Name)
		}
		content, err := readEntry(entry)
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name, err)
		}
		files[name] = content
	}
	if len(files) == 0 {
		return fmt.Errorf("GOPATH archive contains no sources for %s", module.Module.Mod.Path)
	}
	// go_path consumes libraries, so add the explicitly selected command
	// entrypoints and module metadata from the source tree.
	for _, filename := range extraFiles {
		name, err := filepath.Rel(filepath.Dir(goMod), filename)
		if err != nil {
			return err
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("source %q is outside the module directory", filename)
		}
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(name)] = content
	}
	files["go.mod"] = data
	files["README.md"] = []byte(readme)

	out := zip.NewWriter(output)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		// Normalize inherited permissions and timestamps for the published
		// source tree. Even command entrypoints are non-executable files.
		header := &zip.FileHeader{
			Name:     name,
			Method:   zip.Deflate,
			Modified: time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC),
		}
		header.SetMode(0o644)
		w, err := out.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := w.Write(files[name]); err != nil {
			return err
		}
	}
	return out.Close()
}

func main() {
	gopath := flag.String("gopath", "", "GOPATH source archive")
	output := flag.String("output", "", "output ZIP archive")
	goMod := flag.String("go-mod", "", "source go.mod")
	flag.Parse()
	if *gopath == "" || *output == "" || *goMod == "" || flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	out, err := os.Create(*output)
	if err != nil {
		log.Fatal(err)
	}
	if err := errors.Join(assemble(*gopath, *goMod, flag.Args(), out), out.Close()); err != nil {
		log.Fatal(err)
	}
}
