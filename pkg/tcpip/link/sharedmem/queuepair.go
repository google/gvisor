// Copyright 2021 The gVisor Authors.
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

//go:build linux
// +build linux

package sharedmem

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/eventfd"
)

const (
	// DefaultQueueDataSize is the size of the shared memory data region that
	// holds the scatter/gather buffers.
	DefaultQueueDataSize = 1 << 20 // 1MiB

	// DefaultQueuePipeSize is the size of the pipe that holds the packet descriptors.
	//
	// Assuming each packet data is approximately 1280 bytes (IPv6 Minimum MTU)
	// then we can hold approximately 1024*1024/1280 ~ 819 packets in the data
	// area. Which means the pipe needs to be big enough to hold 819
	// descriptors.
	//
	// Each descriptor is approximately 8 (slot descriptor in pipe) +
	// 16 (packet descriptor) + 12 (for buffer descriptor) assuming each packet is
	// stored in exactly 1 buffer descriptor (see queue/tx.go and pipe/tx.go.)
	//
	// Which means we need approximately 36*819 ~ 29 KiB to store all packet
	// descriptors. We could go with a 32 KiB pipe but to give it some slack in
	// how the upper layer may make use of the scatter gather buffers we double
	// this to hold enough descriptors.
	DefaultQueuePipeSize = 64 << 10 // 64KiB

	// DefaultSharedDataSize is the size of the sharedData region used to
	// enable/disable notifications.
	DefaultSharedDataSize = 4 << 10 // 4KiB

	// DefaultBufferSize is the size of each individual buffer that the data
	// region is broken down into to hold packet data. Should be larger than
	// 1500 + 14 (Ethernet header) + 10 (VirtIO header) to fit each packet
	// in a single buffer.
	DefaultBufferSize = 2048

	// DefaultTmpDir is the path used to create the memory files if a path
	// is not provided.
	DefaultTmpDir = "/dev/shm"
)

// A QueuePair represents a pair of TX/RX queues.
type QueuePair struct {
	// txCfg is the QueueConfig to be used for transmit queue.
	txCfg QueueConfig

	// rxCfg is the QueueConfig to be used for receive queue.
	rxCfg QueueConfig
}

// QueueOptions allows queue specific configuration to be specified when
// creating a QueuePair.
type QueueOptions struct {
	// SharedMemPath is the path to use to create the shared memory backing
	// files for the queue.
	//
	// If unspecified it defaults to "/dev/shm".
	SharedMemPath string
}

// NewQueuePair creates a shared memory QueuePair.
func NewQueuePair(opts QueueOptions) (*QueuePair, error) {
	txCfg, err := createQueueFDs(opts.SharedMemPath, queueSizes{
		dataSize:       DefaultQueueDataSize,
		txPipeSize:     DefaultQueuePipeSize,
		rxPipeSize:     DefaultQueuePipeSize,
		sharedDataSize: DefaultSharedDataSize,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create tx queue: %s", err)
	}

	rxCfg, err := createQueueFDs(opts.SharedMemPath, queueSizes{
		dataSize:       DefaultQueueDataSize,
		txPipeSize:     DefaultQueuePipeSize,
		rxPipeSize:     DefaultQueuePipeSize,
		sharedDataSize: DefaultSharedDataSize,
	})

	if err != nil {
		closeFDs(txCfg)
		return nil, fmt.Errorf("failed to create rx queue: %s", err)
	}

	return &QueuePair{
		txCfg: txCfg,
		rxCfg: rxCfg,
	}, nil
}

// Close closes underlying tx/rx queue fds.
func (q *QueuePair) Close() {
	closeFDs(q.txCfg)
	closeFDs(q.rxCfg)
}

// TXQueueConfig returns the QueueConfig for the receive queue.
func (q *QueuePair) TXQueueConfig() QueueConfig {
	return q.txCfg
}

// RXQueueConfig returns the QueueConfig for the transmit queue.
func (q *QueuePair) RXQueueConfig() QueueConfig {
	return q.rxCfg
}

type queueSizes struct {
	dataSize       int64
	txPipeSize     int64
	rxPipeSize     int64
	sharedDataSize int64
}

func createQueueFDs(sharedMemPath string, s queueSizes) (QueueConfig, error) {
	success := false
	var eventFD eventfd.Eventfd
	var dataFD, txPipeFD, rxPipeFD, sharedDataFD int
	defer func() {
		if success {
			return
		}
		closeFDs(QueueConfig{
			EventFD:      eventFD,
			DataFD:       dataFD,
			TxPipeFD:     txPipeFD,
			RxPipeFD:     rxPipeFD,
			SharedDataFD: sharedDataFD,
		})
	}()
	eventFD, err := eventfd.Create()
	if err != nil {
		return QueueConfig{}, fmt.Errorf("eventfd failed: %v", err)
	}
	dataFD, err = createFile(sharedMemPath, s.dataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create dataFD: %s", err)
	}
	txPipeFD, err = createFile(sharedMemPath, s.txPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create txPipeFD: %s", err)
	}
	rxPipeFD, err = createFile(sharedMemPath, s.rxPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create rxPipeFD: %s", err)
	}
	sharedDataFD, err = createFile(sharedMemPath, s.sharedDataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create sharedDataFD: %s", err)
	}
	success = true
	return QueueConfig{
		EventFD:      eventFD,
		DataFD:       dataFD,
		TxPipeFD:     txPipeFD,
		RxPipeFD:     rxPipeFD,
		SharedDataFD: sharedDataFD,
	}, nil
}

func createFile(sharedMemPath string, size int64, initQueue bool) (fd int, err error) {
	var tmpDir = DefaultTmpDir
	if sharedMemPath != "" {
		tmpDir = sharedMemPath
	}
	f, err := ioutil.TempFile(tmpDir, "sharedmem_test")
	if err != nil {
		return -1, fmt.Errorf("TempFile failed: %v", err)
	}
	defer f.Close()
	unix.Unlink(f.Name())

	if initQueue {
		// Write the "slot-free" flag in the initial queue.
		if _, err := f.WriteAt([]byte{0, 0, 0, 0, 0, 0, 0, 0x80}, 0); err != nil {
			return -1, fmt.Errorf("WriteAt failed: %v", err)
		}
	}

	fd, err = unix.Dup(int(f.Fd()))
	if err != nil {
		return -1, fmt.Errorf("unix.Dup(%d) failed: %v", f.Fd(), err)
	}

	if err := unix.Ftruncate(fd, size); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("ftruncate(%d, %d) failed: %v", fd, size, err)
	}

	return fd, nil
}

func closeFDs(c QueueConfig) {
	unix.Close(c.DataFD)
	c.EventFD.Close()
	unix.Close(c.TxPipeFD)
	unix.Close(c.RxPipeFD)
	unix.Close(c.SharedDataFD)
}
