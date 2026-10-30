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

// Package client provides programmatic access to gVisor sandboxes and
// containers without spawning runsc subprocesses.
package client

import (
	"context"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
)

// Client provides programmatic access to containers managed in a runsc root directory.
type Client struct {
	conf *config.Config
}

// New creates a new Client configured with the specified Config.
// If conf is nil or has an empty RootDir, config.DefaultRootDir() is used.
func New(conf *config.Config) *Client {
	if conf == nil {
		conf = &config.Config{}
	}
	if conf.RootDir == "" {
		conf.RootDir = config.DefaultRootDir()
	}
	return &Client{conf: conf}
}

// NewFromRootDir creates a new Client configured for the specified root directory.
// If rootDir is empty, config.DefaultRootDir() is used.
func NewFromRootDir(rootDir string) *Client {
	return New(&config.Config{RootDir: rootDir})
}

// RootDir returns the root directory associated with this client.
func (c *Client) RootDir() string {
	return c.conf.RootDir
}

// Config returns the configuration associated with this client.
func (c *Client) Config() *config.Config {
	return c.conf
}

// Load loads a container by ID from the root directory.
func (c *Client) Load(ctx context.Context, id string, opts container.LoadOpts) (*container.Container, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return container.Load(c.conf.RootDir, container.FullID{ContainerID: id}, opts)
}

// List returns the full IDs of all containers in the root directory.
func (c *Client) List(ctx context.Context) ([]container.FullID, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return container.List(c.conf.RootDir)
}

// State returns the OCI state metadata for the container with the given ID.
func (c *Client) State(ctx context.Context, id string) (specs.State, error) {
	if err := ctx.Err(); err != nil {
		return specs.State{}, err
	}
	cont, err := c.Load(ctx, id, container.LoadOpts{ReadOnly: true})
	if err != nil {
		return specs.State{}, fmt.Errorf("loading container %q: %w", id, err)
	}
	return cont.State(), nil
}

// Spec returns the OCI specification for the container with the given ID.
func (c *Client) Spec(ctx context.Context, id string) (*specs.Spec, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cont, err := c.Load(ctx, id, container.LoadOpts{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("loading container %q: %w", id, err)
	}
	return cont.Spec, nil
}

// Pause pauses the container with the given ID.
func (c *Client) Pause(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cont, err := c.Load(ctx, id, container.LoadOpts{})
	if err != nil {
		return fmt.Errorf("loading container %q: %w", id, err)
	}
	return cont.Pause()
}

// Resume resumes the container with the given ID.
func (c *Client) Resume(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cont, err := c.Load(ctx, id, container.LoadOpts{})
	if err != nil {
		return fmt.Errorf("loading container %q: %w", id, err)
	}
	return cont.Resume()
}
