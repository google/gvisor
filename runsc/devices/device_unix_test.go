//go:build !windows
// +build !windows

package devices

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func cleanupTest() {
	unixLstat = unix.Lstat
	osReadDir = os.ReadDir
}

func TestDeviceFromPathLstatFailure(t *testing.T) {
	testError := errors.New("test error")

	// Override unix.Lstat to inject error.
	unixLstat = func(path string, stat *unix.Stat_t) error {
		return testError
	}
	defer cleanupTest()

	_, err := DeviceFromPath("", "")
	if !errors.Is(err, testError) {
		t.Fatalf("Unexpected error %v, expected %v", err, testError)
	}
}

func TestHostDevicesIoutilReadDirFailure(t *testing.T) {
	testError := errors.New("test error")

	// Override os.ReadDir to inject error.
	osReadDir = func(dirname string) ([]fs.DirEntry, error) {
		return nil, testError
	}
	defer cleanupTest()

	_, err := HostDevices()
	if !errors.Is(err, testError) {
		t.Fatalf("Unexpected error %v, expected %v", err, testError)
	}
}

func TestHostDevicesIoutilReadDirDeepFailure(t *testing.T) {
	testError := errors.New("test error")
	called := false

	// Override os.ReadDir to inject error after the first call.
	osReadDir = func(dirname string) ([]fs.DirEntry, error) {
		if called {
			return nil, testError
		}
		called = true

		// Provoke a second call.
		fi, err := os.Lstat("/tmp")
		if err != nil {
			t.Fatalf("Unexpected error %v", err)
		}

		return []fs.DirEntry{fileInfoToDirEntry(fi)}, nil
	}
	defer cleanupTest()

	_, err := HostDevices()
	if !errors.Is(err, testError) {
		t.Fatalf("Unexpected error %v, expected %v", err, testError)
	}
}

func TestHostDevicesAllValid(t *testing.T) {
	devices, err := HostDevices()
	if err != nil {
		t.Fatalf("failed to get host devices: %v", err)
	}

	for _, device := range devices {
		// Devices can't have major number 0.
		if device.Major == 0 {
			t.Errorf("device entry %+v has zero major number", device)
		}
		switch device.Type {
		case BlockDevice, CharDevice:
		case FifoDevice:
			t.Logf("fifo devices shouldn't show up from HostDevices")
			fallthrough
		default:
			t.Errorf("device entry %+v has unexpected type %v", device, device.Type)
		}
	}
}
