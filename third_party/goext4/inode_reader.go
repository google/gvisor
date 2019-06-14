package goext4

import (
	"io"
	"log"
	"math"
)

// InodeReader fulfills the `io.Reader` interface to read arbitrary amounts of
// data.
type InodeReader struct {
	en           *ExtentNavigator
	currentBlock []byte
	bytesRead    uint64
	bytesTotal   uint64
}

// NewInodeReader initializes an InodeReader.
func NewInodeReader(en *ExtentNavigator, offset uint64) *InodeReader {
	return &InodeReader{
		en:           en,
		currentBlock: make([]byte, 0),
		bytesRead:    offset,
		bytesTotal:   en.inode.Size(),
	}
}

// Offset returns the number of bytes read until now.
func (ir *InodeReader) Offset() uint64 {
	return ir.bytesRead
}

func (ir *InodeReader) fill() (err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	if len(ir.currentBlock) == 0 {
		if ir.bytesRead >= ir.bytesTotal {
			return io.EOF
		}

		data, err := ir.en.Read(ir.bytesRead)
		if err != nil {
			panic(err)
		}

		ir.currentBlock = data
		ir.bytesRead += uint64(len(data))
	}

	return nil
}

// Read fills the given slice with data and returns an `io.EOF` error with (0)
// bytes when done. (`n`) may be less than `len(p)`.
func (ir *InodeReader) Read(p []byte) (n int, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	err = ir.fill()
	if err == io.EOF {
		return 0, io.EOF
	} else if err != nil {
		panic(err)
	}

	// Determine how much of the buffer we can fill.
	currentBytesReadCount := uint64(math.Min(float64(len(ir.currentBlock)), float64(len(p))))

	copy(p, ir.currentBlock[:currentBytesReadCount])
	ir.currentBlock = ir.currentBlock[currentBytesReadCount:]

	return int(currentBytesReadCount), nil
}

// Skip simulates a read but just discards the data.
func (ir *InodeReader) Skip(n uint64) (skipped uint64, err error) {
	defer func() {
		if state := recover(); state != nil {
			err = WrapError(state)
		}
	}()

	err = ir.fill()
	if err == io.EOF {
		return 0, io.EOF
	} else if err != nil {
		log.Panic(err)
	}

	currentBytesReadCount := uint64(math.Min(float64(len(ir.currentBlock)), float64(n)))
	ir.currentBlock = ir.currentBlock[currentBytesReadCount:]

	return currentBytesReadCount, nil
}
