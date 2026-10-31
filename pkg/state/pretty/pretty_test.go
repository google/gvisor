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

package pretty

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

func TestPrintHTMLEscapesUntrustedContent(t *testing.T) {
	var stream bytes.Buffer
	ww := wire.Writer{Writer: &stream}
	if err := state.WriteHeader(&ww, 2, true); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	wire.Save(&ww, &wire.Type{
		Name:   "pkg.<script>alert(1)</script>",
		Fields: []string{"field</pre><img src=x onerror=alert(2)>"},
	})

	s := wire.String("</pre><script>alert(3)</script>&")
	st := wire.Struct{TypeID: 1}
	st.Alloc(1)
	*st.Field(0) = &s
	wire.Save(&ww, wire.Uint(1))
	wire.Save(&ww, &st)

	fn := wire.FieldName("dot<script>alert(4)</script>")
	ref := &wire.Ref{
		Root: 1,
		Type: wire.TypeID(1),
		Dots: []wire.Dot{&fn},
	}
	wire.Save(&ww, wire.Uint(2))
	wire.Save(&ww, ref)

	var htmlOut bytes.Buffer
	if err := PrintHTML(&htmlOut, bytes.NewReader(stream.Bytes())); err != nil {
		t.Fatalf("PrintHTML: %v", err)
	}
	gotHTML := htmlOut.String()
	for _, forbidden := range []string{
		"<script>",
		"</script>",
		"<img",
		"</pre><script>",
	} {
		if strings.Contains(gotHTML, forbidden) {
			t.Errorf("PrintHTML output contains unescaped %q:\n%s", forbidden, gotHTML)
		}
	}
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;/pre&gt;&lt;img src=x onerror=alert(2)&gt;",
		"&lt;/pre&gt;&lt;script&gt;alert(3)&lt;/script&gt;&amp;",
		"dot&lt;script&gt;alert(4)&lt;/script&gt;",
	} {
		if !strings.Contains(gotHTML, want) {
			t.Errorf("PrintHTML output missing escaped %q:\n%s", want, gotHTML)
		}
	}
	if count := strings.Count(gotHTML, "</pre>"); count != 1 {
		t.Errorf("PrintHTML </pre> count = %d, want 1:\n%s", count, gotHTML)
	}

	var textOut bytes.Buffer
	if err := PrintText(&textOut, bytes.NewReader(stream.Bytes())); err != nil {
		t.Fatalf("PrintText: %v", err)
	}
	if !strings.Contains(textOut.String(), "</pre><script>alert(3)</script>&") {
		t.Errorf("PrintText unexpectedly HTML-escaped text output:\n%s", textOut.String())
	}
}

type errReader struct {
	err error
}

func (e errReader) Read([]byte) (int, error) {
	return 0, e.err
}

func TestPrintStreamNonObjectPropagatesReadError(t *testing.T) {
	var stream bytes.Buffer
	ww := wire.Writer{Writer: &stream}
	if err := state.WriteHeader(&ww, 64, false); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	wantErr := errors.New("corrupt stream")

	var out bytes.Buffer
	if err := PrintText(&out, io.MultiReader(bytes.NewReader(stream.Bytes()), errReader{err: wantErr})); !errors.Is(err, wantErr) {
		t.Errorf("PrintText err = %v, want %v", err, wantErr)
	}
	out.Reset()
	if err := PrintHTML(&out, io.MultiReader(bytes.NewReader(stream.Bytes()), errReader{err: wantErr})); !errors.Is(err, wantErr) {
		t.Errorf("PrintHTML err = %v, want %v", err, wantErr)
	}
}
