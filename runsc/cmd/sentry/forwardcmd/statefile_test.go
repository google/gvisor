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

package forwardcmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	pgallocpb "gvisor.dev/gvisor/pkg/sentry/pgalloc/pgalloc_metadata_go_proto"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/pretty"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/state/wire"
	"gvisor.dev/gvisor/runsc/flag"
)

// checkpointObject encodes one wire struct and any objects its field references.
func checkpointObject(t *testing.T, name, field string, value wire.Object, referenced ...wire.Object) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := wire.Writer{Writer: &buf}
	if err := state.WriteHeader(&w, uint64(1+len(referenced)), true); err != nil {
		t.Fatal(err)
	}
	wire.Save(&w, &wire.Type{Name: name, Fields: []string{field}})
	root := wire.Struct{TypeID: 1}
	root.Alloc(1)
	*root.Field(0) = value
	wire.Save(&w, wire.Uint(1))
	wire.Save(&w, &root)
	for i, ref := range referenced {
		wire.Save(&w, wire.Uint(i+2))
		wire.Save(&w, ref)
	}
	return buf.Bytes()
}

func checkpointRaw(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := state.WriteHeader(&wire.Writer{Writer: &buf}, uint64(len(data)), false); err != nil {
		t.Fatal(err)
	}
	buf.Write(data)
	return buf.Bytes()
}

// The generic printer can show an inline MemoryFile if its protobuf is given
// an ordinary raw frame in place of the historical little-endian byte count.
func checkpointMemoryFile(t *testing.T, pages int) (inline, framed []byte) {
	t.Helper()
	meta := &pgallocpb.MemoryFileMetadataProto{Version: 1}
	if pages != 0 {
		meta.MemAcct = []*pgallocpb.MemAcctRangeProto{{End: uint64(pages), KnownCommitted: true}}
	}
	data, err := proto.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	inline = append(binary.LittleEndian.AppendUint64(nil, uint64(len(data))), data...)
	framed = checkpointRaw(t, data)
	if pages != 0 {
		raw := checkpointRaw(t, make([]byte, pages))
		inline, framed = append(inline, raw...), append(framed, raw...)
	}
	return inline, framed
}

func dumpTestStatefile(t *testing.T, cmd Statefile, payload []byte) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "checkpoint")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := statefile.NewWriter(f, nil, map[string]string{"runsc_version": "test", "container_count": "1"})
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out strings.Builder
	err = cmd.writeTo(&out, r)
	return out.String(), err
}

func TestStatefileDumpMemoryFiles(t *testing.T) {
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cpu := checkpointObject(t, "pkg/cpuid.FeatureSet", "marker", wire.Uint(1))
	kernel := checkpointObject(t, "pkg/sentry/kernel.Kernel", "marker", wire.Uint(2))
	roots := join(cpu, kernel)
	const ownerType = "pkg/sentry/kernel.privateMemoryFileMetadata"
	noOwners := checkpointObject(t, ownerType, "owners", wire.Nil{})
	oneOwner := checkpointObject(t, ownerType, "owners", &wire.Slice{
		Length: 1, Capacity: 2, Ref: wire.Ref{Root: 2},
	}, &wire.Array{Contents: []wire.Object{wire.Nil{}, wire.Nil{}}})
	app, appFramed := checkpointMemoryFile(t, 17)
	private, privateFramed := checkpointMemoryFile(t, 29)
	tail := checkpointObject(t, "legacyMemoryFile", "marker", wire.Uint(3))
	for _, tc := range []struct {
		name             string
		payload, generic []byte
	}{
		{"Generic", tail, tail},
		{"CPUWithoutKernel", join(cpu, tail), join(cpu, tail)},
		{"Split", roots, roots},
		{"Legacy", join(roots, tail), join(roots, tail)},
		{"ZeroOwners", join(roots, app, noOwners), join(roots, appFramed, noOwners)},
		{"Inline", join(roots, app, oneOwner, private), join(roots, appFramed, oneOwner, privateFramed)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, html := range []bool{false, true} {
				got, err := dumpTestStatefile(t, Statefile{html: html}, tc.payload)
				if err != nil {
					t.Fatal(err)
				}
				print := pretty.PrintText
				var want strings.Builder
				if html {
					want.WriteString("<html><body>\n")
					print = pretty.PrintHTML
				}
				if err := print(&want, bytes.NewReader(tc.generic)); err != nil {
					t.Fatal(err)
				}
				if html {
					want.WriteString("</body></html>\n")
				}
				if tc.name == "Inline" {
					_, rest, found := strings.Cut(got, "(17 bytes non-object data)\n")
					if !found || !strings.Contains(rest, "(29 bytes non-object data)\n") {
						t.Fatalf("missing application or private page region in %q", got)
					}
				}
				if got != want.String() {
					t.Errorf("html=%t: got %q, want %q", html, got, want.String())
				}
			}
		})
	}
	t.Run("GenericCollision", func(t *testing.T) {
		// Eight empty raw frames also look like a zero-length protobuf.
		data := join(roots, bytes.Repeat(checkpointRaw(t, nil), 8), tail)
		if _, err := dumpTestStatefile(t, Statefile{}, data); err == nil {
			t.Error("accepted malformed MemoryFile data after the checkpoint roots")
		}
	})

	// Truncate the last owner's metadata or pages: there is no later frame
	// whose absence could mask a reader that accepted a short MemoryFile.
	for _, tc := range []struct {
		name string
		body []byte
		want error
	}{
		{"MissingOwners", app, io.ErrUnexpectedEOF},
		{"NonSliceOwners", join(app, checkpointObject(t, ownerType, "owners", wire.Uint(0))), nil},
		{"MissingPrivate", join(app, oneOwner), io.EOF},
		{"ExtraPrivate", join(app, noOwners, private), nil},
		{"ShortMetadata", join(app, oneOwner, private[:9]), io.ErrUnexpectedEOF},
		{"ShortPage", join(app, oneOwner, private[:len(private)-1]), io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := printState(io.Discard, bytes.NewReader(join(roots, tc.body)), false)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("printState error = %v, want rejection (cause %v)", err, tc.want)
			}
		})
	}
}

func TestCheckStickyDirOwnership(t *testing.T) {
	stickyWorld := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0777, Uid: 0}
	stickyNotWorld := &unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0775, Uid: 0}
	nonStickyWorld := &unix.Stat_t{Mode: unix.S_IFDIR | 0777, Uid: 0}

	if err := checkStickyDirOwnership(stickyWorld, 1000, 0); !errors.Is(err, unix.EACCES) {
		t.Errorf("root following uid=1000 entry in root-owned 1777 dir: got %v, want EACCES", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 1000, 2000); !errors.Is(err, unix.EACCES) {
		t.Errorf("uid=2000 following uid=1000 entry in root-owned 1777 dir: got %v, want EACCES", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 1000, 1000); err != nil {
		t.Errorf("owner following own entry in 1777 dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(stickyWorld, 0, 1000); err != nil {
		t.Errorf("following dir-owner entry in 1777 dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(stickyNotWorld, 1000, 0); err != nil {
		t.Errorf("following entry in non-world-writable sticky dir: got %v, want nil", err)
	}
	if err := checkStickyDirOwnership(nonStickyWorld, 1000, 0); err != nil {
		t.Errorf("following entry in non-sticky dir: got %v, want nil", err)
	}
}

func TestSplitParentAndBase(t *testing.T) {
	for _, tc := range []struct {
		in            string
		wantParent    string
		wantBase      string
		wantHasParent bool
		wantTrailing  bool
	}{
		{in: "file.txt", wantParent: "", wantBase: "file.txt", wantHasParent: false, wantTrailing: false},
		{in: "/file.txt", wantParent: "/", wantBase: "file.txt", wantHasParent: true, wantTrailing: false},
		{in: "link/../checkpoint", wantParent: "link/..", wantBase: "checkpoint", wantHasParent: true, wantTrailing: false},
		{in: "../checkpoint", wantParent: "..", wantBase: "checkpoint", wantHasParent: true, wantTrailing: false},
		{in: "dir/", wantParent: "", wantBase: "", wantHasParent: false, wantTrailing: true},
		{in: "/", wantParent: "", wantBase: "", wantHasParent: false, wantTrailing: true},
	} {
		parent, base, hasParent, trailing := splitParentAndBase(tc.in)
		if parent != tc.wantParent || base != tc.wantBase || hasParent != tc.wantHasParent || trailing != tc.wantTrailing {
			t.Errorf("splitParentAndBase(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
				tc.in, parent, base, hasParent, trailing,
				tc.wantParent, tc.wantBase, tc.wantHasParent, tc.wantTrailing)
		}
	}
}

func TestWriteOutputFileSymlinkDotDotTraversal(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	otherChild := filepath.Join(root, "other", "child")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("MkdirAll(workDir): %v", err)
	}
	if err := os.MkdirAll(otherChild, 0755); err != nil {
		t.Fatalf("MkdirAll(otherChild): %v", err)
	}
	// work/link -> ../other/child, so work/link/../checkpoint resolves in the
	// kernel to root/other/checkpoint, NOT work/checkpoint.
	if err := os.Symlink(filepath.Join("..", "other", "child"), filepath.Join(workDir, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	inputPath := filepath.Join(workDir, "checkpoint")
	wantInput := []byte("original-input-checkpoint")
	if err := os.WriteFile(inputPath, wantInput, 0644); err != nil {
		t.Fatalf("WriteFile(input): %v", err)
	}
	inFile, err := os.Open(inputPath)
	if err != nil {
		t.Fatalf("Open(input): %v", err)
	}
	defer inFile.Close()
	var inStat unix.Stat_t
	if err := unix.Fstat(int(inFile.Fd()), &inStat); err != nil {
		t.Fatalf("Fstat(input): %v", err)
	}

	outExpr := filepath.Join(workDir, "link") + "/../checkpoint"
	if err := writeOutputFile(outExpr, &inStat, func(f *os.File) error {
		_, werr := f.WriteString("decoded-output\n")
		return werr
	}); err != nil {
		t.Fatalf("writeOutputFile(%q) failed: %v", outExpr, err)
	}

	gotInput, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("ReadFile(input): %v", err)
	}
	if string(gotInput) != string(wantInput) {
		t.Errorf("input file %s was clobbered: got %q, want %q", inputPath, gotInput, wantInput)
	}

	resolvedOut := filepath.Join(root, "other", "checkpoint")
	gotOut, err := os.ReadFile(resolvedOut)
	if err != nil {
		t.Fatalf("ReadFile(resolvedOut): %v", err)
	}
	if string(gotOut) != "decoded-output\n" {
		t.Errorf("resolved output %s = %q, want %q", resolvedOut, gotOut, "decoded-output\n")
	}
}

func TestStatefileExecuteDirectoryWithoutReadPerm(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses DAC directory read permission check")
	}

	root := t.TempDir()
	imgPath := filepath.Join(root, "meta.img")
	f, err := os.Create(imgPath)
	if err != nil {
		t.Fatalf("Create(imgPath): %v", err)
	}
	w, err := statefile.NewWriter(f, nil, map[string]string{"k": "v"})
	if err != nil {
		f.Close()
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write([]byte("unused")); err != nil {
		w.Close()
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	runStatefile := func(args ...string) subcommands.ExitStatus {
		var cmd Statefile
		fs := flag.NewFlagSet("statefile", flag.ContinueOnError)
		cmd.SetFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("fs.Parse(%v): %v", args, err)
		}
		return cmd.Execute(context.Background(), fs)
	}

	wxDir := filepath.Join(root, "wx_only")
	if err := os.Mkdir(wxDir, 0700); err != nil {
		t.Fatalf("Mkdir(wxDir): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(wxDir, 0700) })
	if err := os.Chmod(wxDir, 0300); err != nil {
		t.Fatalf("Chmod(wxDir, 0300): %v", err)
	}

	wxOut := filepath.Join(wxDir, "out.txt")
	if status := runStatefile("-get=k", "-output="+wxOut, imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute in 0300 dir = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(wxOut); err != nil {
		t.Fatalf("ReadFile(%s): %v", wxOut, err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(%s) = %q, want %q", wxOut, got, "v\n")
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(wxDir); err != nil {
		t.Fatalf("Chdir(wxDir): %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	if status := runStatefile("-get=k", "-output=cwd_out.txt", imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute in 0300 cwd = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(filepath.Join(wxDir, "cwd_out.txt")); err != nil {
		t.Fatalf("ReadFile(cwd_out.txt): %v", err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(cwd_out.txt) = %q, want %q", got, "v\n")
	}
	if err := os.Chdir(origWD); err != nil {
		t.Fatalf("Chdir(origWD): %v", err)
	}

	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatalf("Mkdir(realDir): %v", err)
	}
	xDir := filepath.Join(root, "x_only")
	if err := os.Mkdir(xDir, 0700); err != nil {
		t.Fatalf("Mkdir(xDir): %v", err)
	}
	linkPath := filepath.Join(xDir, "outlink")
	targetPath := filepath.Join(realDir, "linked.txt")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(xDir, 0700) })
	if err := os.Chmod(xDir, 0100); err != nil {
		t.Fatalf("Chmod(xDir, 0100): %v", err)
	}

	if status := runStatefile("-get=k", "-output="+linkPath, imgPath); status != subcommands.ExitSuccess {
		t.Errorf("Statefile.Execute through 0100 dir symlink = %v, want ExitSuccess", status)
	} else if got, err := os.ReadFile(targetPath); err != nil {
		t.Fatalf("ReadFile(%s): %v", targetPath, err)
	} else if string(got) != "v\n" {
		t.Errorf("ReadFile(%s) = %q, want %q", targetPath, got, "v\n")
	}
}
