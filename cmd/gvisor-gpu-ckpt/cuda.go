//go:build linux

package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// Function pointer types matching cuCheckpointProcess* signatures.
// Each takes (int pid, void* args) and returns int (CUresult).
typedef int (*cuCheckpointFn)(int, void*);
typedef int (*cuInitFn)(unsigned int);

static void* libcuda_handle = NULL;
static cuInitFn fn_init = NULL;
static cuCheckpointFn fn_lock = NULL;
static cuCheckpointFn fn_checkpoint = NULL;
static cuCheckpointFn fn_restore = NULL;
static cuCheckpointFn fn_unlock = NULL;

// load_libcuda opens libcuda.so.1, initializes CUDA, and resolves
// all checkpoint symbols.
// Returns 0 on success, -1 if dlopen fails, -2 if any dlsym fails,
// -3 if cuInit fails.
static int load_libcuda() {
	if (libcuda_handle != NULL) return 0;

	libcuda_handle = dlopen("libcuda.so.1", RTLD_NOW);
	if (!libcuda_handle) return -1;

	fn_init = (cuInitFn)dlsym(libcuda_handle, "cuInit");
	fn_lock = (cuCheckpointFn)dlsym(libcuda_handle, "cuCheckpointProcessLock");
	fn_checkpoint = (cuCheckpointFn)dlsym(libcuda_handle, "cuCheckpointProcessCheckpoint");
	fn_restore = (cuCheckpointFn)dlsym(libcuda_handle, "cuCheckpointProcessRestore");
	fn_unlock = (cuCheckpointFn)dlsym(libcuda_handle, "cuCheckpointProcessUnlock");

	if (!fn_init || !fn_lock || !fn_checkpoint || !fn_restore || !fn_unlock) return -2;

	int rc = fn_init(0);
	if (rc != 0) return -3;
	return 0;
}

// call_checkpoint_fn invokes a cuCheckpointProcess* function with a
// zeroed 64-byte args buffer (matches NVIDIA's API expectation).
static int call_checkpoint_fn(cuCheckpointFn fn, int pid) {
	char args[64];
	memset(args, 0, sizeof(args));
	return fn(pid, args);
}

static int cuda_lock(int pid) { return call_checkpoint_fn(fn_lock, pid); }
static int cuda_checkpoint(int pid) { return call_checkpoint_fn(fn_checkpoint, pid); }
static int cuda_restore(int pid) { return call_checkpoint_fn(fn_restore, pid); }
static int cuda_unlock(int pid) { return call_checkpoint_fn(fn_unlock, pid); }
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func loadLibcuda() error {
	rc := C.load_libcuda()
	switch rc {
	case 0:
		return nil
	case -1:
		return fmt.Errorf("dlopen(libcuda.so.1) failed: %s", C.GoString(C.dlerror()))
	case -2:
		return fmt.Errorf("dlsym failed: one or more cuCheckpointProcess* symbols not found (driver 570+ required)")
	case -3:
		return fmt.Errorf("cuInit(0) failed")
	default:
		return fmt.Errorf("load_libcuda returned unknown error: %d", rc)
	}
}

func checkpointLock(pid int) error {
	rc := C.cuda_lock(C.int(pid))
	if rc != 0 {
		return fmt.Errorf("cuCheckpointProcessLock(pid=%d) failed: rc=%d", pid, rc)
	}
	return nil
}

func checkpointCheckpoint(pid int) error {
	rc := C.cuda_checkpoint(C.int(pid))
	if rc != 0 {
		return fmt.Errorf("cuCheckpointProcessCheckpoint(pid=%d) failed: rc=%d", pid, rc)
	}
	return nil
}

func checkpointRestore(pid int) error {
	rc := C.cuda_restore(C.int(pid))
	if rc != 0 {
		return fmt.Errorf("cuCheckpointProcessRestore(pid=%d) failed: rc=%d", pid, rc)
	}
	return nil
}

func checkpointUnlock(pid int) error {
	rc := C.cuda_unlock(C.int(pid))
	if rc != 0 {
		return fmt.Errorf("cuCheckpointProcessUnlock(pid=%d) failed: rc=%d", pid, rc)
	}
	return nil
}

// Ensure unsafe import is used (needed for cgo).
var _ = unsafe.Pointer(nil)
