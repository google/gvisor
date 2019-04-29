// Copyright 2018 The gVisor Authors.
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

package p9

import (
	"fmt"
	"reflect"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	objs := []encoder{
		&QID{
			Type:    1,
			Version: 2,
			Path:    3,
		},
		&FSStat{
			Type:            1,
			BlockSize:       2,
			Blocks:          3,
			BlocksFree:      4,
			BlocksAvailable: 5,
			Files:           6,
			FilesFree:       7,
			FSID:            8,
			NameLength:      9,
		},
		&AttrMask{
			Mode:        true,
			NLink:       true,
			UID:         true,
			GID:         true,
			RDev:        true,
			ATime:       true,
			MTime:       true,
			CTime:       true,
			INo:         true,
			Size:        true,
			Blocks:      true,
			BTime:       true,
			Gen:         true,
			DataVersion: true,
		},
		&Attr{
			Mode:             Exec,
			UID:              2,
			GID:              3,
			NLink:            4,
			RDev:             5,
			Size:             6,
			BlockSize:        7,
			Blocks:           8,
			ATimeSeconds:     9,
			ATimeNanoSeconds: 10,
			MTimeSeconds:     11,
			MTimeNanoSeconds: 12,
			CTimeSeconds:     13,
			CTimeNanoSeconds: 14,
			BTimeSeconds:     15,
			BTimeNanoSeconds: 16,
			Gen:              17,
			DataVersion:      18,
		},
		&SetAttrMask{
			Permissions:        true,
			UID:                true,
			GID:                true,
			Size:               true,
			ATime:              true,
			MTime:              true,
			CTime:              true,
			ATimeNotSystemTime: true,
			MTimeNotSystemTime: true,
		},
		&SetAttr{
			Permissions:      1,
			UID:              2,
			GID:              3,
			Size:             4,
			ATimeSeconds:     5,
			ATimeNanoSeconds: 6,
			MTimeSeconds:     7,
			MTimeNanoSeconds: 8,
		},
		&Dirent{
			QID:    QID{Type: 1},
			Offset: 2,
			Type:   3,
			Name:   "a",
		},
		&Rlerror{
			Error: 1,
		},
		&Tstatfs{
			FID: 1,
		},
		&Rstatfs{
			FSStat: FSStat{Type: 1},
		},
		&Tlopen{
			FID:   1,
			Flags: WriteOnly,
		},
		&Rlopen{
			QID:    QID{Type: 1},
			IoUnit: 2,
		},
		&Tlconnect{
			FID: 1,
		},
		&Rlconnect{},
		&Tlcreate{
			FID:         1,
			Name:        "a",
			OpenFlags:   2,
			Permissions: 3,
			GID:         4,
		},
		&Rlcreate{
			Rlopen{QID: QID{Type: 1}},
		},
		&Tsymlink{
			Directory: 1,
			Name:      "a",
			Target:    "b",
			GID:       2,
		},
		&Rsymlink{
			QID: QID{Type: 1},
		},
		&Tmknod{
			Directory:   1,
			Name:        "a",
			Permissions: 2,
			Major:       3,
			Minor:       4,
			GID:         5,
		},
		&Rmknod{
			QID: QID{Type: 1},
		},
		&Trename{
			FID:       1,
			Directory: 2,
			Name:      "a",
		},
		&Rrename{},
		&Treadlink{
			FID: 1,
		},
		&Rreadlink{
			Target: "a",
		},
		&Tgetattr{
			FID:      1,
			AttrMask: AttrMask{Mode: true},
		},
		&Rgetattr{
			Valid: AttrMask{Mode: true},
			QID:   QID{Type: 1},
			Attr:  Attr{Mode: Write},
		},
		&Tsetattr{
			FID:     1,
			Valid:   SetAttrMask{Permissions: true},
			SetAttr: SetAttr{Permissions: Write},
		},
		&Rsetattr{},
		&Txattrwalk{
			FID:    1,
			NewFID: 2,
			Name:   "a",
		},
		&Rxattrwalk{
			Size: 1,
		},
		&Txattrcreate{
			FID:      1,
			Name:     "a",
			AttrSize: 2,
			Flags:    3,
		},
		&Rxattrcreate{},
		&Treaddir{
			Directory: 1,
			Offset:    2,
			Count:     3,
		},
		&Rreaddir{
			// Count must be sufficient to encode a dirent.
			Count:   0x18,
			Entries: []Dirent{{QID: QID{Type: 2}}},
		},
		&Tfsync{
			FID: 1,
		},
		&Rfsync{},
		&Tlink{
			Directory: 1,
			Target:    2,
			Name:      "a",
		},
		&Rlink{},
		&Tmkdir{
			Directory:   1,
			Name:        "a",
			Permissions: 2,
			GID:         3,
		},
		&Rmkdir{
			QID: QID{Type: 1},
		},
		&Trenameat{
			OldDirectory: 1,
			OldName:      "a",
			NewDirectory: 2,
			NewName:      "b",
		},
		&Rrenameat{},
		&Tunlinkat{
			Directory: 1,
			Name:      "a",
			Flags:     2,
		},
		&Runlinkat{},
		&Tversion{
			MSize:   1,
			Version: "a",
		},
		&Rversion{
			MSize:   1,
			Version: "a",
		},
		&Tauth{
			AuthenticationFID: 1,
			UserName:          "a",
			AttachName:        "b",
			UID:               2,
		},
		&Rauth{
			QID: QID{Type: 1},
		},
		&Tattach{
			FID:  1,
			Auth: Tauth{AuthenticationFID: 2},
		},
		&Rattach{
			QID: QID{Type: 1},
		},
		&Tflush{
			OldTag: 1,
		},
		&Rflush{},
		&Twalk{
			FID:    1,
			NewFID: 2,
			Names:  []string{"a"},
		},
		&Rwalk{
			QIDs: []QID{{Type: 1}},
		},
		&Tread{
			FID:    1,
			Offset: 2,
			Count:  3,
		},
		&Rread{
			Data: []byte{'a'},
		},
		&Twrite{
			FID:    1,
			Offset: 2,
			Data:   []byte{'a'},
		},
		&Rwrite{
			Count: 1,
		},
		&Tclunk{
			FID: 1,
		},
		&Rclunk{},
		&Tremove{
			FID: 1,
		},
		&Rremove{},
		&Tflushf{
			FID: 1,
		},
		&Rflushf{},
		&Twalkgetattr{
			FID:    1,
			NewFID: 2,
			Names:  []string{"a"},
		},
		&Rwalkgetattr{
			QIDs:  []QID{{Type: 1}},
			Valid: AttrMask{Mode: true},
			Attr:  Attr{Mode: Write},
		},
		&Tucreate{
			Tlcreate: Tlcreate{
				FID:         1,
				Name:        "a",
				OpenFlags:   2,
				Permissions: 3,
				GID:         4,
			},
			UID: 5,
		},
		&Rucreate{
			Rlcreate{Rlopen{QID: QID{Type: 1}}},
		},
		&Tumkdir{
			Tmkdir: Tmkdir{
				Directory:   1,
				Name:        "a",
				Permissions: 2,
				GID:         3,
			},
			UID: 4,
		},
		&Rumkdir{
			Rmkdir{QID: QID{Type: 1}},
		},
		&Tusymlink{
			Tsymlink: Tsymlink{
				Directory: 1,
				Name:      "a",
				Target:    "b",
				GID:       2,
			},
			UID: 3,
		},
		&Rusymlink{
			Rsymlink{QID: QID{Type: 1}},
		},
		&Tumknod{
			Tmknod: Tmknod{
				Directory:   1,
				Name:        "a",
				Permissions: 2,
				Major:       3,
				Minor:       4,
				GID:         5,
			},
			UID: 6,
		},
		&Rumknod{
			Rmknod{QID: QID{Type: 1}},
		},
	}

	for _, enc := range objs {
		// Encode the original.
		data := make([]byte, initialBufferLength)
		buf := buffer{data: data[:0]}
		enc.Encode(&buf)

		// Create a new object, same as the first.
		enc2 := reflect.New(reflect.ValueOf(enc).Elem().Type()).Interface().(encoder)
		buf2 := buffer{data: buf.data}

		// To be fair, we need to add any payloads (directly).
		if pl, ok := enc.(payloader); ok {
			enc2.(payloader).SetPayload(pl.Payload())
		}

		// And any file payloads (directly).
		if fl, ok := enc.(filer); ok {
			enc2.(filer).SetFilePayload(fl.FilePayload())
		}

		// Mark sure it was okay.
		enc2.Decode(&buf2)
		if buf2.isOverrun() {
			t.Errorf("object %#v->%#v got overrun on decode", enc, enc2)
			continue
		}

		// Check that they are equal.
		if !reflect.DeepEqual(enc, enc2) {
			t.Errorf("object %#v and %#v differ", enc, enc2)
			continue
		}
	}
}

func TestMessageStrings(t *testing.T) {
	for typ := range msgRegistry.factories {
		entry := &msgRegistry.factories[typ]
		if entry.create != nil {
			name := fmt.Sprintf("%+v", typ)
			t.Run(name, func(t *testing.T) {
				defer func() { // Ensure no panic.
					if r := recover(); r != nil {
						t.Errorf("printing %s failed: %v", name, r)
					}
				}()
				m := entry.create()
				_ = fmt.Sprintf("%v", m)
				err := ErrInvalidMsgType{MsgType(typ)}
				_ = err.Error()
			})
		}
	}
}

func TestRegisterDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			// We expect a panic.
			t.FailNow()
		}
	}()

	// Register a duplicate.
	msgRegistry.register(MsgRlerror, func() message { return &Rlerror{} })
}

func TestMsgCache(t *testing.T) {
	// Cache starts empty.
	if got, want := len(msgRegistry.factories[MsgRlerror].cache), 0; got != want {
		t.Errorf("Wrong cache size, got: %d, want: %d", got, want)
	}

	// Message can be created with an empty cache.
	msg, err := msgRegistry.get(0, MsgRlerror)
	if err != nil {
		t.Errorf("msgRegistry.get(): %v", err)
	}
	if got, want := len(msgRegistry.factories[MsgRlerror].cache), 0; got != want {
		t.Errorf("Wrong cache size, got: %d, want: %d", got, want)
	}

	// Check that message is added to the cache when returned.
	msgRegistry.put(msg)
	if got, want := len(msgRegistry.factories[MsgRlerror].cache), 1; got != want {
		t.Errorf("Wrong cache size, got: %d, want: %d", got, want)
	}

	// Check that returned message is reused.
	if got, err := msgRegistry.get(0, MsgRlerror); err != nil {
		t.Errorf("msgRegistry.get(): %v", err)
	} else if msg != got {
		t.Errorf("Message not reused, got: %d, want: %d", got, msg)
	}

	// Check that cache doesn't grow beyond max size.
	for i := 0; i < maxCacheSize+1; i++ {
		msgRegistry.put(&Rlerror{})
	}
	if got, want := len(msgRegistry.factories[MsgRlerror].cache), maxCacheSize; got != want {
		t.Errorf("Wrong cache size, got: %d, want: %d", got, want)
	}
}
