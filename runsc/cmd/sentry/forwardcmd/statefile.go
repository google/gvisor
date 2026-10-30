// Copyright 2020 The gVisor Authors.
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

package forwardcmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/state/pretty"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Statefile implements subcommands.Command for the "statefile" command.
type Statefile struct {
	list    bool
	get     string
	bitmask bool
	key     string
	output  string
	html    bool
}

// Name implements subcommands.Command.
func (*Statefile) Name() string {
	return "statefile"
}

// Synopsis implements subcommands.Command.
func (*Statefile) Synopsis() string {
	return "shows information about a statefile"
}

// Usage implements subcommands.Command.
func (*Statefile) Usage() string {
	return "statefile [flags] <statefile>\n"
}

// SetFlags implements subcommands.Command.
func (s *Statefile) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&s.list, "list", false, "lists the metadata in the statefile.")
	f.StringVar(&s.get, "get", "", "extracts the given metadata key.")
	f.BoolVar(&s.bitmask, "bitmask", false, fmt.Sprintf("when used with -get %s, outputs CPU features as comma-separated hex uint32 block bitmasks.", sentryapi.CPUFeaturesKey))
	f.StringVar(&s.key, "key", "", "the integrity key for the file.")
	f.StringVar(&s.output, "output", "", "target to write the result.")
	f.BoolVar(&s.html, "html", false, "outputs in HTML format.")
}

// MetadataOnly reports whether the command only inspects statefile metadata
// without decoding the serialized object graph.
func (s *Statefile) MetadataOnly() bool {
	return s.list || s.get != "" || s.bitmask
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Statefile) FetchSpec(_ *config.Config, _ *flag.FlagSet) (string, *specs.Spec, error) {
	// This command does not operate on a single container, so nothing to fetch.
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (s *Statefile) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Validate flags and positional arguments before opening or modifying files.
	if s.list && s.get != "" {
		return util.Errorf("error: can't specify -list and -get simultaneously.")
	}
	if s.bitmask && s.get != sentryapi.CPUFeaturesKey {
		return util.Errorf("error: -bitmask requires -get %s.", sentryapi.CPUFeaturesKey)
	}
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	input, err := os.Open(f.Arg(0))
	if err != nil {
		return util.Errorf("error opening input: %v", err)
	}
	defer input.Close()
	inInfo, err := input.Stat()
	if err != nil {
		return util.Errorf("error statting input: %v", err)
	}

	if s.output == "" {
		if err := s.writeTo(os.Stdout, input); err != nil {
			return util.Errorf("%v", err)
		}
		return subcommands.ExitSuccess
	}

	var (
		outInfo os.FileInfo
		hasOut  bool
	)
	if info, err := os.Stat(s.output); err == nil {
		if os.SameFile(inInfo, info) {
			return util.Errorf("error: input and output refer to the same file: %s", s.output)
		}
		outInfo = info
		hasOut = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return util.Errorf("error statting output: %v", err)
	}

	targetPath, directOpen, err := resolveOutputPath(s.output)
	if err != nil {
		return util.Errorf("error resolving output: %v", err)
	}

	// Non-regular targets (such as /dev/null, FIFOs, or procfs file-descriptor
	// links) cannot be replaced via rename; write to them directly without O_TRUNC.
	if directOpen || (hasOut && !outInfo.Mode().IsRegular()) {
		outFile, err := os.OpenFile(s.output, os.O_WRONLY, 0)
		if err != nil {
			return util.Errorf("error opening output: %v", err)
		}
		writeErr := s.writeTo(outFile, input)
		closeErr := outFile.Close()
		if writeErr != nil {
			return util.Errorf("%v", writeErr)
		}
		if closeErr != nil {
			return util.Errorf("error flushing output: %v", closeErr)
		}
		return subcommands.ExitSuccess
	}

	// Stage regular output in a temporary file in the destination directory and
	// rename into place only on success so failures never clobber existing files
	// or leave truncated outputs behind.
	var existingPerm os.FileMode
	if hasOut {
		existingPerm = outInfo.Mode().Perm()
	}
	tmpFile, err := createTempOutput(filepath.Dir(targetPath), hasOut, existingPerm)
	if err != nil {
		return util.Errorf("error creating temporary output: %v", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()
	writeErr := s.writeTo(tmpFile, input)
	closeErr := tmpFile.Close()
	if writeErr != nil {
		return util.Errorf("%v", writeErr)
	}
	if closeErr != nil {
		return util.Errorf("error flushing output: %v", closeErr)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return util.Errorf("error renaming output: %v", err)
	}
	tmpPath = ""
	return subcommands.ExitSuccess
}

const maxSymlinkHops = 40

// resolveOutputPath walks symlinks along outPath so staged output is renamed
// onto the resolved regular-file destination without overwriting symlinks.
// When directOpen is true, outPath refers to a procfs magic link or non-regular
// path that must be opened directly rather than staged and renamed.
func resolveOutputPath(outPath string) (targetPath string, directOpen bool, err error) {
	cur := outPath
	for range maxSymlinkHops {
		if strings.HasSuffix(cur, string(filepath.Separator)) {
			return cur, true, nil
		}
		base := filepath.Base(cur)
		if base == "." || base == ".." || base == string(filepath.Separator) {
			return cur, true, nil
		}
		absDir, err := filepath.Abs(filepath.Dir(cur))
		if err != nil {
			return "", false, err
		}
		realDir, err := filepath.EvalSymlinks(absDir)
		if err != nil {
			return "", false, err
		}
		candidate := filepath.Join(realDir, base)
		if realDir == "/proc" || strings.HasPrefix(realDir, "/proc/") {
			return candidate, true, nil
		}
		linfo, err := os.Lstat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return candidate, false, nil
			}
			return "", false, err
		}
		if linfo.Mode()&os.ModeSymlink == 0 {
			return candidate, !linfo.Mode().IsRegular(), nil
		}
		linkDest, err := os.Readlink(candidate)
		if err != nil {
			return "", false, err
		}
		trailingSep := strings.HasSuffix(linkDest, string(filepath.Separator))
		if !filepath.IsAbs(linkDest) {
			linkDest = filepath.Join(realDir, linkDest)
			if trailingSep && !strings.HasSuffix(linkDest, string(filepath.Separator)) {
				linkDest += string(filepath.Separator)
			}
		}
		cur = linkDest
	}
	return "", false, fmt.Errorf("too many levels of symbolic links: %s", outPath)
}

// createTempOutput creates a temporary file in dir for staging output. When
// overwriting an existing file (hasOut), existingPerm is preserved; when
// creating a new file, mode 0644 is passed to open(O_CREAT|O_EXCL) so the
// kernel applies the process umask.
func createTempOutput(dir string, hasOut bool, existingPerm os.FileMode) (*os.File, error) {
	if hasOut {
		f, err := os.CreateTemp(dir, ".statefile-*")
		if err != nil {
			return nil, err
		}
		if err := f.Chmod(existingPerm); err != nil {
			name := f.Name()
			f.Close()
			os.Remove(name)
			return nil, err
		}
		return f, nil
	}
	for range 256 {
		var rnd [8]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, err
		}
		candidate := filepath.Join(dir, ".statefile-"+hex.EncodeToString(rnd[:]))
		f, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	return nil, os.ErrExist
}

func (s *Statefile) writeTo(output io.Writer, input *os.File) error {
	// Dump the full file?
	if !s.list && s.get == "" {
		var key []byte
		if s.key != "" {
			key = []byte(s.key)
		}
		rc, _, err := statefile.NewReader(input, key)
		if err != nil {
			return fmt.Errorf("error parsing statefile: %w", err)
		}
		defer rc.Close()
		if s.html {
			if _, err := fmt.Fprintf(output, "<html><body>\n"); err != nil {
				return fmt.Errorf("error writing output: %w", err)
			}
			if err := pretty.PrintHTML(output, rc); err != nil {
				return fmt.Errorf("error printing state: %w", err)
			}
			if _, err := fmt.Fprintf(output, "</body></html>\n"); err != nil {
				return fmt.Errorf("error writing output: %w", err)
			}
		} else {
			if err := pretty.PrintText(output, rc); err != nil {
				return fmt.Errorf("error printing state: %w", err)
			}
		}
		return nil
	}

	// Load just the metadata.
	metadata, err := statefile.MetadataUnsafe(input)
	if err != nil {
		return fmt.Errorf("error reading metadata: %w", err)
	}

	// Is it a single key?
	if s.get != "" {
		val, ok := metadata[s.get]
		if !ok {
			return fmt.Errorf("metadata key %s: not found", s.get)
		}
		if s.bitmask {
			mask, err := cpuid.FeatureMaskStringFromNames(strings.Split(val, ","))
			if err != nil {
				return fmt.Errorf("error converting %s to bitmask: %w", s.get, err)
			}
			val = mask
		}
		if s.html {
			if _, err := fmt.Fprintf(output, "<html><body>\n"); err != nil {
				return fmt.Errorf("error writing output: %w", err)
			}
		}
		if _, err := fmt.Fprintf(output, "%s\n", val); err != nil {
			return fmt.Errorf("error writing output: %w", err)
		}
		if s.html {
			if _, err := fmt.Fprintf(output, "</body></html>\n"); err != nil {
				return fmt.Errorf("error writing output: %w", err)
			}
		}
		return nil
	}

	// List all keys.
	if s.html {
		if _, err := fmt.Fprintf(output, "<html><body>\n <ul>\n"); err != nil {
			return fmt.Errorf("error writing output: %w", err)
		}
	}
	for key := range metadata {
		var err error
		if s.html {
			_, err = fmt.Fprintf(output, "  <li>%s</li>\n", key)
		} else {
			_, err = fmt.Fprintf(output, "%s\n", key)
		}
		if err != nil {
			return fmt.Errorf("error writing output: %w", err)
		}
	}
	if s.html {
		if _, err := fmt.Fprintf(output, " </ul>\n</body></html>\n"); err != nil {
			return fmt.Errorf("error writing output: %w", err)
		}
	}
	return nil
}
