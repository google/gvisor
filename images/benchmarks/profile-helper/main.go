// Copyright 2023 The gVisor Authors.
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

// Binary profilehelper helps exfiltrate benchmark profiles.
package main

// This must have no non-base-library dependencies!
import (
	"archive/tar"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Flags.
var (
	operation               = flag.String("operation", "", "Operation to do: make-dir, delete-dir, set-containerd-flag, remove-containerd-flag, stream-dir")
	flagName                = flag.String("flag", "", "Name of the flag to remove or add (for containerd flag operations)")
	flagValue               = flag.String("value", "", "Value of the flag to add (for add-containerd-flag operations)")
	containerdConfigPath    = flag.String("containerd-config", "", "Path to the containerd config file (for containerd flag operations)")
	containerdConfigSection = flag.String("containerd-section", "", "Name of the containerd section to modify (for containerd flag operations)")
	dirPath                 = flag.String("dir", "", "Path to the directory to (for make-dir, delete-dir, or stream-dir operations)")
	chmod                   = flag.Int("chmod", -1, "Permission of --dir in decimal (for chmod-dir)")
)

// exitf aborts the program after logging the given error message to stderr.
func exitf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}

// usagef aborts the program after logging the given error message and usage
// help to stderr.
func usagef(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	flag.Usage()
	os.Exit(2)
}

func main() {
	flag.Parse()
	switch *operation {
	case "":
		usagef("Must specify --operation.")
	case "set-containerd-flag":
		setContainerdFlag( /* remove= */ false)
	case "remove-containerd-flag":
		setContainerdFlag( /* remove= */ true)
	case "stream-dir":
		streamDir()
	default:
		usagef("Invalid --operation: %q", *operation)
	}
}

// setContainerdFlag sets or removes a flag from the containerd config.
func setContainerdFlag(remove bool) {
	if *containerdConfigPath == "" {
		usagef("Must provide --containerd-config")
	}
	if *containerdConfigSection == "" {
		usagef("Must provide --containerd-section")
	}
	sectionHeader := fmt.Sprintf("[%s]", *containerdConfigSection)
	st, err := os.Stat(*containerdConfigPath)
	if err != nil {
		exitf("Cannot stat containerd config %q: %v", *containerdConfigPath, err)
	}
	cfg, err := os.ReadFile(*containerdConfigPath)
	if err != nil {
		exitf("Cannot open containerd config %q: %v", *containerdConfigPath, err)
	}
	isCorrectSection := false
	lines := strings.Split(string(cfg), "\n")
	rewritten := make([]string, 0, len(lines))
	addedFlag := false
	lastFlagLine := ""
	addFlag := func() {
		whiteSpace := "  "
		if lastFlagLine != "" {
			whiteSpace = lastFlagLine[:strings.Index(lastFlagLine, strings.TrimSpace(lastFlagLine))]
		}
		rewritten = append(rewritten, fmt.Sprintf("%s%s = %q", whiteSpace, *flagName, *flagValue))
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line == sectionHeader {
			isCorrectSection = true
			rewritten = append(rewritten, line)
			continue
		}
		if !isCorrectSection {
			rewritten = append(rewritten, line)
			continue
		}
		if isCorrectSection && strings.HasPrefix(line, "[") {
			if !remove && !addedFlag {
				// Need to add the flag before we close out this section.
				addFlag()
			}
			isCorrectSection = false
			rewritten = append(rewritten, line)
			break
		}
		equalIndex := strings.IndexRune(line, '=')
		if equalIndex == -1 {
			rewritten = append(rewritten, line)
			continue
		}
		lastFlagLine = line
		if f := strings.TrimSpace(line[:equalIndex]); f != *flagName {
			rewritten = append(rewritten, line)
			continue
		}
		if remove || addedFlag {
			// Omit this line entirely.
			continue
		}
		// Replace this line.
		addedFlag = true
		// Use `line[:equalIndex]` to preserve correct indentation.
		rewritten = append(rewritten, fmt.Sprintf("%s= %q", line[:equalIndex], *flagValue))
	}
	if !remove && !addedFlag {
		addFlag()
	}

	newCfg := strings.TrimSpace(strings.Join(rewritten, "\n")) + "\n"
	if strings.TrimSpace(newCfg) == strings.TrimSpace(string(cfg)) {
		fmt.Fprintf(os.Stderr, "Containerd config is unchanged:\n%s\n\n", string(cfg))
	}
	fmt.Fprintf(os.Stderr, "Previous containerd config:\n%s\n\nNew containerd config:\n%s\n\n", string(cfg), newCfg)
	if err := os.WriteFile(*containerdConfigPath, []byte(newCfg), st.Mode()); err != nil {
		exitf("Cannot write to containerd config %q: %v", *containerdConfigPath, err)
	}
}

// dirStreamWriter handles stream-dir write requests.
// It is the last writer in the chain, after base64 encoding.
// Its role is to split up the base64 stream into lines, prefix it
// with "DATA:", and to rate-limit it. It also keeps track of the
// hash of the stream.
type dirStreamWriter struct {
	beganStream         bool
	estimatedTotalBytes int64
	dirPath             string
	lastLine            time.Time
	checksum            hash.Hash
}

// Write implements `io.WriteCloser.Write`.
func (w *dirStreamWriter) Write(b []byte) (int, error) {
	const (
		maxLineSize     = 984
		linesPerSecond  = 192
		durationPerLine = time.Second / time.Duration(linesPerSecond)
	)
	if !w.beganStream {
		if _, err := fmt.Fprintf(os.Stdout, "BEGIN:%d:%s\n", w.estimatedTotalBytes, w.dirPath); err != nil {
			return 0, err
		}
		w.beganStream = true
	}
	var written int
	for i := 0; i < len(b); i += maxLineSize {
		if sinceLastLine := time.Since(w.lastLine); sinceLastLine < durationPerLine {
			time.Sleep(durationPerLine - sinceLastLine)
		}
		w.lastLine = time.Now()
		_, err := os.Stdout.WriteString("DATA:")
		// We don't increase `written` here, because the write function's
		// bytes written should represent the bytes consumed from `b`.
		if err != nil {
			return written, err
		}
		endIndex := i + maxLineSize
		if endIndex > len(b) {
			endIndex = len(b)
		}
		n, err := os.Stdout.Write(b[i:endIndex])
		if n > 0 {
			written += n
			w.checksum.Write(b[i : i+n])
		}
		if err != nil {
			return written, err
		}
		_, err = os.Stdout.WriteString("\n")
		// We don't increase `written` here for the same reason.
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Close implements `io.WriteCloser.Close`.
func (w *dirStreamWriter) Close() error {
	if !w.beganStream {
		return nil
	}
	_, err := fmt.Fprintf(os.Stdout, "SHA256:%x\n", w.checksum.Sum(nil))
	if err != nil {
		return fmt.Errorf("cannot write SHA256: %w", err)
	}
	return nil
}

// streamDir tars up all the files in a target directory, then
// compresses it with flate, then base64 the compressed data, and then
// outputs it to stdout across multiple lines.
// Its goal is not to be efficient, but rather to work in very constrained
// environments where the only effective data exfiltration mechanism is
// a single standard buffered stdout log stream using printable ASCII
// characters only.
// Each line of stdout is prefixed with either "BEGIN:", "DATA:",
// or "SHA256:" (marking the end of the stream).
// The program will wait for 15 seconds before streaming any output;
// this gives time for a client to attach to the log stream before anything
// is output. This needs to happen before any output occurs, in case the
// log buffer isn't large enough to contain the entire directory's contents.
func streamDir() {
	if *dirPath == "" {
		usagef("Must provide --dir")
	}
	time.Sleep(15 * time.Second)
	var totalBytes int64
	err := filepath.Walk(*dirPath, func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Keep walking other directories, so return nil here.
			return nil
		}
		if info.IsDir() {
			return nil
		}
		totalBytes += info.Size()
		return nil
	})
	if err != nil {
		exitf("cannot walk directory %q: %w", *dirPath, err)
	}
	dsw := &dirStreamWriter{
		estimatedTotalBytes: totalBytes,
		dirPath:             *dirPath,
		checksum:            sha256.New(),
	}
	enc := base64.NewEncoder(base64.StdEncoding, dsw)
	fl, err := flate.NewWriter(enc, flate.BestCompression)
	if err != nil {
		exitf("Cannot create flate writer: %v", err)
	}
	tw := tar.NewWriter(fl)
	err = filepath.Walk(*dirPath, func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Keep walking other directories, so return nil here.
			return nil
		}
		if info.IsDir() {
			return nil
		}
		size := info.Size()
		clean, err := filepath.Rel(*dirPath, path)
		if err != nil {
			return fmt.Errorf("cannot express path %q relative to base path %q: %w", path, *dirPath, err)
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("cannot open %q: %w", path, err)
		}
		hdr := tar.Header{
			Name:   clean,
			Mode:   int64(info.Mode()),
			Size:   size,
			Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			return fmt.Errorf("cannot write tar header for %q: %w", path, err)
		}
		copied, err := io.Copy(tw, f)
		if err != nil {
			return fmt.Errorf("cannot write tar body for %q: %w", path, err)
		}
		if copied != size {
			return fmt.Errorf("file size for %q was inaccurate: stat claimed %d bytes, copied %d", path, size, copied)
		}
		return nil
	})
	if err != nil {
		exitf("Cannot walk directory %q: %v", *dirPath, err)
	}
	if err := tw.Close(); err != nil {
		exitf("Cannot close tar file: %v", err)
	}
	if err := fl.Close(); err != nil {
		exitf("Cannot close flate writer: %v", err)
	}
	if err := enc.Close(); err != nil {
		exitf("Cannot close base64 encoder: %v", err)
	}
	if err := dsw.Close(); err != nil {
		exitf("Cannot close directory stream: %v", err)
	}
}
