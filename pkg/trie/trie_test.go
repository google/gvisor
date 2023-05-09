// Copyright 2022 The gVisor Authors.
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

package trie

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type Entry struct {
	Key   string
	Value string
}

func collectPrefixes(tr *Trie, key string) []Entry {
	arr := make([]Entry, 0)
	tr.FindPrefixes(key, func(p string, v any) bool {
		arr = append(arr, Entry{Key: p, Value: v.(string)})
		return true
	})
	return arr
}

func collectSuffixes(tr *Trie, key string) []Entry {
	arr := make([]Entry, 0)
	tr.FindSuffixes(key, func(p string, v any) bool {
		arr = append(arr, Entry{Key: p, Value: v.(string)})
		return true
	})
	return arr
}

func sortEntries(a Entry, b Entry) bool {
	return a.Key < b.Key
}

func TestEmpty(t *testing.T) {
	tr := New()
	if tr.Size() != 0 {
		t.Errorf("tr.Size() = %d; want 0", tr.Size())
	}

	arr := collectPrefixes(tr, "foo")
	if d := cmp.Diff([]Entry{}, arr); d != "" {
		t.Errorf("collectPrefixes(tr, 'foo') returned diff (-want +got):\n%s", d)
	}

	arr = collectSuffixes(tr, "foo")
	if d := cmp.Diff([]Entry{}, arr); d != "" {
		t.Errorf("collectSuffixes(tr, '') returned diff (-want +got):\n%s", d)
	}

	arr = collectPrefixes(tr, "")
	if d := cmp.Diff([]Entry{}, arr); d != "" {
		t.Errorf("collectPrefixes(tr, '') returned diff (-want +got):\n%s", d)
	}

	arr = collectSuffixes(tr, "")
	if d := cmp.Diff([]Entry{}, arr); d != "" {
		t.Errorf("collectSuffixes(tr, '') returned diff (-want +got):\n%s", d)
	}
}

func TestAscendingSearch(t *testing.T) {
	tr := New()
	tr.SetValue("a", "value a")
	tr.SetValue("ab", "value ab")
	tr.SetValue("abc", "value abc")
	tr.SetValue("abcd", "value abcd")
	tr.SetValue("abcde", "value abcde")

	expected := []Entry{
		{Key: "a", Value: "value a"},
		{Key: "ab", Value: "value ab"},
		{Key: "abc", Value: "value abc"},
		{Key: "abcd", Value: "value abcd"},
		{Key: "abcde", Value: "value abcde"}}
	arr := collectPrefixes(tr, "abcdef")
	if d := cmp.Diff(expected, arr); d != "" {
		t.Errorf("collectPrefixes(tr, 'abcdef') returned diff (-want +got):\n%s", d)
	}

	suffixTests := []struct {
		key     string
		entries []Entry
	}{
		{"", expected},
		{"zzz", []Entry{}},
		{"a", expected},
		{"ab", expected[1:]},
		{"abc", expected[2:]},
		{"abd", []Entry{}},
		{"abcd", expected[3:]},
		{"abcde", expected[4:]},
	}
	for _, tt := range suffixTests {
		t.Run(tt.key, func(t *testing.T) {
			arr := collectSuffixes(tr, tt.key)
			if d := cmp.Diff(tt.entries, arr, cmpopts.SortSlices(sortEntries)); d != "" {
				t.Errorf("collectSuffixes(tr, %q) returned sorted diff (-want +got):\n%s", tt.key, d)
			}
		})
	}
}

func TestRoot(t *testing.T) {
	tr := New()
	tr.SetValue("", "root value")
	if tr.Size() != 1 {
		t.Errorf("tr.Size() = %d; want 1", tr.Size())
	}

	expected := []Entry{{Key: "", Value: "root value"}}
	arr := collectPrefixes(tr, "foo")
	if d := cmp.Diff(expected, arr); d != "" {
		t.Errorf("collectPrefixes(tr, 'foo') returned diff (-want +got):\n%s", d)
	}

	arr = collectPrefixes(tr, "")
	if d := cmp.Diff(expected, arr); d != "" {
		t.Errorf("collectPrefixes(tr, '') returned diff (-want +got):\n%s", d)
	}
}

func TestMultiplePrefixes(t *testing.T) {
	tr := New()
	tr.SetValue("foo", "old foo value")
	if tr.Size() != 1 {
		t.Errorf("tr.Size() = %d; want 1", tr.Size())
	}
	tr.SetValue("foobar", "foobar value")
	if tr.Size() != 2 {
		t.Errorf("tr.Size() = %d; want 2", tr.Size())
	}
	tr.SetValue("qux", "qux value")
	if tr.Size() != 3 {
		t.Errorf("tr.Size() = %d; want 3", tr.Size())
	}
	tr.SetValue("foo", "foo value")
	if tr.Size() != 3 {
		t.Errorf("tr.Size() = %d; want 3", tr.Size())
	}

	fooEntry := Entry{Key: "foo", Value: "foo value"}
	foobarEntry := Entry{Key: "foobar", Value: "foobar value"}
	quxEntry := Entry{Key: "qux", Value: "qux value"}

	prefixTests := []struct {
		key     string
		entries []Entry
	}{
		{"foobar", []Entry{fooEntry, foobarEntry}},
		{"fooba", []Entry{fooEntry}},
		{"foo", []Entry{fooEntry}},
		{"quxiho", []Entry{quxEntry}},
		{"fo", []Entry{}},
		{"qu", []Entry{}},
		{"nowhere", []Entry{}},
		{"", []Entry{}},
	}
	for _, tt := range prefixTests {
		t.Run(tt.key, func(t *testing.T) {
			arr := collectPrefixes(tr, tt.key)
			if d := cmp.Diff(tt.entries, arr); d != "" {
				t.Errorf("collectPrefixes(tr, %q) returned diff (-want +got):\n%s", tt.key, d)
			}
		})
	}
}
