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

package timing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestExport(t *testing.T) {
	start := time.Unix(1700000000, 100)
	earlier := start.Add(time.Millisecond) // After start, before any Reached below.

	timer := New("root", start)
	timer.Reached("a")
	timer.ReachedAt("earlier", earlier)
	child := timer.Fork("child")
	child.Reached("b")
	child.Invalidate("broken")
	child.End()
	timer.Reached("c")

	got := timer.Export()
	if got == nil {
		t.Fatal("Export() = nil")
	}
	if got.Name != "root" {
		t.Errorf("Name = %q, want %q", got.Name, "root")
	}
	if !got.Start.Equal(start) {
		t.Errorf("Start = %v, want %v", got.Start, start)
	}
	if got.End.IsZero() || got.End.Before(got.Start) {
		t.Errorf("End = %v, want non-zero >= Start (%v)", got.End, got.Start)
	}
	var names []string
	for _, mid := range got.MidPoints {
		names = append(names, mid.Name)
	}
	if want := []string{"a", "earlier", "forked", "c"}; !slices.Equal(names, want) {
		t.Errorf("MidPoints names = %v, want %v", names, want)
	}
	if gotEarlier, err := got.Reached("earlier"); err != nil || !gotEarlier.Equal(earlier) {
		t.Errorf("Reached(%q) = (%v, %v), want (%v, nil)", "earlier", gotEarlier, err, earlier)
	}
	if _, err := got.Reached("missing"); err == nil {
		t.Errorf("Reached(%q) succeeded, want error", "missing")
	}

	if len(got.Children) != 1 {
		t.Fatalf("len(Children) = %d, want 1", len(got.Children))
	}
	gotChild := got.Children[0]
	if gotChild.Name != "child" {
		t.Errorf("child Name = %q, want %q", gotChild.Name, "child")
	}
	if gotChild.InvalidReason != "broken" {
		t.Errorf("child InvalidReason = %q, want %q", gotChild.InvalidReason, "broken")
	}
	if gotChild.End.IsZero() || gotChild.End.Before(gotChild.Start) {
		t.Errorf("child End = %v, want non-zero >= Start (%v)", gotChild.End, gotChild.Start)
	}
	if _, err := gotChild.Reached("b"); err != nil {
		t.Errorf("child Reached(%q) = %v, want nil", "b", err)
	}
}

func TestExportNil(t *testing.T) {
	if got := (*Timer)(nil).Export(); got != nil {
		t.Errorf("(*Timer)(nil).Export() = %+v, want nil", got)
	}
}

// TestExportJSON checks that an ExportedTimeline survives a JSON round trip
// without losing or altering data.
func TestExportJSON(t *testing.T) {
	start := time.Unix(1700000000, 123456789)
	timer := New("root", start)
	timer.ReachedAt("step", start.Add(5*time.Millisecond))
	child := timer.Fork("sub")
	child.Reached("sub step")
	child.Invalidate("broken")
	child.End()
	exported := timer.Export()

	encoded, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded ExportedTimeline
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// cmp compares time.Time values with Equal, so the monotonic clock
	// reading that decoding strips does not count as a difference.
	if diff := cmp.Diff(*exported, decoded); diff != "" {
		t.Errorf("timeline changed across JSON round trip (-before +after):\n%s", diff)
	}
}

// TestReadExportedTimeline checks that ReadExportedTimeline reads back what
// Timer.Export wrote, and fails on missing or malformed files.
func TestReadExportedTimeline(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid", func(t *testing.T) {
		timer := New("root", time.Unix(1700000000, 123456789))
		timer.Reached("step")
		exported := timer.Export()
		encoded, err := json.Marshal(exported)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		path := filepath.Join(dir, "valid.json")
		if err := os.WriteFile(path, encoded, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		got, err := ReadExportedTimeline(path)
		if err != nil {
			t.Fatalf("ReadExportedTimeline(%q): %v", path, err)
		}
		if diff := cmp.Diff(exported, got); diff != "" {
			t.Errorf("ReadExportedTimeline(%q) differs from what was written (-want +got):\n%s", path, diff)
		}
	})

	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(dir, "missing.json")
		if _, err := ReadExportedTimeline(path); err == nil {
			t.Errorf("ReadExportedTimeline(%q) succeeded, want error", path)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		path := filepath.Join(dir, "malformed.json")
		if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := ReadExportedTimeline(path); err == nil {
			t.Errorf("ReadExportedTimeline(%q) succeeded, want error", path)
		}
	})
}
