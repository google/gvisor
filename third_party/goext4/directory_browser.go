package goext4

import (
	"bytes"
	"io"
	"log"

	"encoding/binary"
)

// DirectoryBrowser provides high-level directory navigation.
type DirectoryBrowser struct {
	inodeReader *InodeReader

	dataSize uint64
	dataRead uint64
}

// NewDirectoryBrowser initializes the DirectoryBrowser which can be used to
// the directory represented by the inode.
func NewDirectoryBrowser(rs io.ReadSeeker, inode *Inode) *DirectoryBrowser {
	en := NewExtentNavigatorWithReadSeeker(rs, inode)
	ir := NewInodeReader(en)

	return &DirectoryBrowser{
		inodeReader: ir,
		dataSize:    inode.Size(),
	}
}

// Next parses the next directory entry from the underlying inode data reader.
// Returns `io.EOF` when done. This will also return the "." and ".." entries.
func (db *DirectoryBrowser) Next() (de *DirectoryEntry, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	// TODO(dustin): !! We should be seeing an extra `ext4_dir_entry_tail` as the last entry, which has a similar structure to a normal entry but provides a checksum. However, it doesn't appear to be present.

	if db.dataRead >= db.dataSize {
		return nil, io.EOF
	}

	raw := new(DirEntry2)

	err = binary.Read(db.inodeReader, binary.LittleEndian, &raw.Inode)
	if err != nil {
		panic(err)
	}

	err = binary.Read(db.inodeReader, binary.LittleEndian, &raw.RecLen)
	if err != nil {
		panic(err)
	}

	// Read the remaining data, which is variable-length.

	offset := 0
	needBytes := int(raw.RecLen) - 6
	record := make([]byte, needBytes)

	for offset < needBytes {
		n, err := db.inodeReader.Read(record[offset:])
		if err != nil {
			panic(err)
		}

		offset += n
	}

	b := bytes.NewBuffer(record)

	err = binary.Read(b, binary.LittleEndian, &raw.NameLen)
	if err != nil {
		panic(err)
	}

	err = binary.Read(b, binary.LittleEndian, &raw.FileType)
	if err != nil {
		panic(err)
	}

	raw.Name = record[2 : 2+raw.NameLen]

	// Done. Wrap up.

	db.dataRead += uint64(raw.RecLen)

	if db.dataRead > db.dataSize {
		log.Panicf("inode size is not aligned to the directory-entry record size (we ran over): (%d) > (%d)", db.dataRead, db.dataSize)
	}

	de = &DirectoryEntry{
		data: raw,
	}

	return de, nil
}
