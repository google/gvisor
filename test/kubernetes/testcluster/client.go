// Copyright 2024 The gVisor Authors.
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

package testcluster

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/rand"
	"k8s.io/client-go/kubernetes"
)

// KubernetesReq is a function that performs a request with a Kubernetes
// client.
type KubernetesReq func(context.Context, kubernetes.Interface) error

// KubernetesClient is an interface that wraps Kubernetes requests.
type KubernetesClient interface {
	// Do performs a request with a Kubernetes client.
	Do(context.Context, KubernetesReq) error
}

// simpleClient is a KubernetesClient that wraps a simple Kubernetes client.
// The `Do` function simply calls the function with the given `client`.
type simpleClient struct {
	client kubernetes.Interface
}

// Do implements `KubernetesClient.Do`.
func (sc *simpleClient) Do(ctx context.Context, fn KubernetesReq) error {
	return fn(ctx, sc.client)
}

// retryableClient is a KubernetesClient that can retry requests by creating
// *new instances* of Kubernetes clients, rather than just retrying requests.
type retryableClient struct {
	// client is a Kubernetes client factory, used to create new instances of
	// Kubernetes clients and to determine whether a request should be retried.
	client UnstableClient

	// clientCh is a channel used to share Kubernetes clients between multiple
	// requests.
	clientCh chan kubernetes.Interface
}

// UnstableClient is a Kubernetes client factory that can create new instances
// of Kubernetes clients and determine whether a request should be retried.
type UnstableClient interface {
	// Client creates a new instance of a Kubernetes client.
	// This function may also block (in a context-respecting manner)
	// in order to implement backoff between Kubernetes client creation
	// attempts.
	Client(context.Context) (kubernetes.Interface, error)

	// RetryError returns whether the given error should be retried.
	// numAttempt is the number of attempts made so far.
	// This function may also block (in a context-respecting manner)
	// in order to implement backoff between request retries.
	RetryError(ctx context.Context, err error, numAttempt int) bool
}

// NewRetryableClient creates a new retryable Kubernetes client.
// It takes an `UnstableClient` as input, which is used to create new
// instances of Kubernetes clients as needed, and to determine whether
// a request should be retried.
// This can be safely used concurrently, in which case additional
// Kubernetes clients will be created as needed, and reused when
// possible (but never garbage-collected, unless they start emitting
// retriable errors).
// It will immediately create an initial Kubernetes client from the
// `UnstableClient` as the initial client to use.
func NewRetryableClient(ctx context.Context, client UnstableClient) (KubernetesClient, error) {
	initialClient, err := client.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get initial client: %w", err)
	}
	clientCh := make(chan kubernetes.Interface, 128)
	clientCh <- initialClient
	return &retryableClient{client: client, clientCh: clientCh}, nil
}

// getClient returns a Kubernetes client.
// It will either return the client from the clientCh, or create a new one
// if none are available.
func (rc *retryableClient) getClient(ctx context.Context) (kubernetes.Interface, error) {
	select {
	case client := <-rc.clientCh:
		return client, nil
	default:
		client, err := rc.client.Client(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot get client: %w", err)
		}
		return client, nil
	}
}

// putClient puts a Kubernetes client back into the `clientCh`.
func (rc *retryableClient) putClient(client kubernetes.Interface) {
	select {
	case rc.clientCh <- client:
	default:
		// If full, just spawn a goroutine to put it back when possible.
		go func() { rc.clientCh <- client }()
	}
}

// Do implements `KubernetesClient.Do`.
// It retries the request if the error is retryable.
func (rc *retryableClient) Do(ctx context.Context, fn KubernetesReq) error {
	client, err := rc.getClient(ctx)
	if err != nil {
		return fmt.Errorf("cannot get client: %w", err)
	}
	if err = fn(ctx, client); err == nil || !rc.client.RetryError(ctx, err, 0) { // Happy path.
		rc.putClient(client)
		return err
	}

	// We generate a random ID here to distinguish between multiple retriable
	// operations in the logs.
	var operationIDBytes [8]byte
	if _, err := io.ReadFull(rand.Reader, operationIDBytes[:]); err != nil {
		return fmt.Errorf("cannot read random bytes: %w", err)
	}
	operationID := hex.EncodeToString(operationIDBytes[:])

	logger := log.BasicRateLimitedLogger(30 * time.Second)
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		logger.Infof("Retryable operation [%s] @ %s failed on initial attempt with retryable error (%v); retrying until %v...", operationID, time.Now().Format(time.TimeOnly), err, deadline)
	} else {
		logger.Infof("Retryable operation [%s] @ %s failed on initial attempt with retryable error (%v); retrying...", operationID, time.Now().Format(time.TimeOnly), err)
	}
	lastErr := err
	numAttempt := 1
	for ctx.Err() == nil {
		numAttempt++
		client, err := rc.getClient(ctx)
		if err != nil {
			return fmt.Errorf("cannot get client: %w", err)
		}
		if err = fn(ctx, client); err == nil || !rc.client.RetryError(ctx, err, numAttempt) {
			// We don't use `logger` here because we want to make sure it is logged
			// so that the logs reflect that the operation succeeded upon a retry.
			// Otherwise the logs can be confusing because it may seem that we are
			// still in the retry loop.
			if err == nil {
				log.Infof("Retryable operation [%s] @ %s succeeded on attempt %d.", operationID, time.Now().Format(time.TimeOnly), numAttempt)
			} else {
				log.Infof("Retryable operation [%s] @ %s attempt %d returned non-retryable error: %v.", operationID, time.Now().Format(time.TimeOnly), numAttempt, err)
			}
			rc.putClient(client)
			return err
		}
		logger.Infof("Retryable operation [%s] @ %s failed on attempt %d (retryable error: %v); will retry again...", operationID, time.Now().Format(time.TimeOnly), numAttempt, err)
		lastErr = err
	}
	log.Infof("Retryable operation [%s] @ %s failed after %d attempts with retryable error (%v) but context was cancelled (%v); bailing out.", operationID, time.Now().Format(time.TimeOnly), numAttempt, lastErr)
	return lastErr
}

// request wraps a function that takes a KubernetesClient and returns a value of
// type T. It is useful for functions that return more than just an error,
// e.g. lookup functions that return a pod info or other Kubernetes resources.
func request[T any](ctx context.Context, client KubernetesClient, fn func(context.Context, kubernetes.Interface) (T, error)) (T, error) {
	var result T
	err := client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		var err error
		result, err = fn(ctx, client)
		return err
	})
	return result, err
}
