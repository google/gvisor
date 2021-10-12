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

package sync

// WaitGroupErr is similar to WaitGroup but allows goroutines to report error.
// Only the first error is retained and reported back.
//
// Example usage:
// 	wg := WaitGroupErr{}
// 	wg.Add(1)
// 	go func() {
//			defer wg.Done()
//			if err := ...; err != nil {
//				wg.ReportError(err)
//				return
// 			}
// 	}()
//	return wg.Error()
//
type WaitGroupErr struct {
	WaitGroup

	// mu protects firstErr.
	mu Mutex

	// firstErr holds the first error reported. nil is no error occurred.
	firstErr error
}

// ReportError reports an error. Note it does not call Done().
func (w *WaitGroupErr) ReportError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.firstErr == nil {
		w.firstErr = err
	}
}

// Error waits for the counter to reach 0 and returns the first reported error
// if any.
func (w *WaitGroupErr) Error() error {
	w.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.firstErr
}
