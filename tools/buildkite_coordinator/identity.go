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

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/idtoken"
)

// instanceIdentity is the verified identity of a GCE instance.
//
// All fields of instanceIdentity are immutable.
type instanceIdentity struct {
	email        string
	projectID    string
	zone         string
	instanceID   string
	instanceName string
}

// verifyInstanceIdentity verifies the instance identity token of an agent VM and
// returns the identity of the instance that provided it.
func verifyInstanceIdentity(ctx context.Context, cfg config, token, audience string) (instanceIdentity, error) {
	payload, err := idtoken.Validate(ctx, token, audience)
	if err != nil {
		return instanceIdentity{}, fmt.Errorf("invalid identity token: %w", err)
	}
	google, _ := payload.Claims["google"].(map[string]any)
	gce, _ := google["compute_engine"].(map[string]any)
	if gce == nil {
		return instanceIdentity{}, fmt.Errorf("identity token has no compute_engine claims")
	}
	str := func(v any) string {
		s, _ := v.(string)
		return s
	}
	id := instanceIdentity{
		email:        str(payload.Claims["email"]),
		projectID:    str(gce["project_id"]),
		zone:         str(gce["zone"]),
		instanceID:   str(gce["instance_id"]),
		instanceName: str(gce["instance_name"]),
	}
	if id.email != cfg.agentServiceAccount {
		return instanceIdentity{}, fmt.Errorf("identity token is for service account %q, want %q", id.email, cfg.agentServiceAccount)
	}
	if id.projectID != cfg.project {
		return instanceIdentity{}, fmt.Errorf("identity token is for project %q, want %q", id.projectID, cfg.project)
	}
	return id, nil
}

const (
	// pinMetadataKey is the metadata key recording an agent's pin status.
	// For unassigned agents, it is not set; for untrusted agents, it
	// contains the pinned build UUID; and for trusted agents, it contains
	// pinTrustedValue.
	pinMetadataKey = "buildkite-agent-pin"

	// pinTrustedValue is the pinMetadataKey value for trusted agents.
	pinTrustedValue = "trusted"

	// expiryMetadataKey is the metadata key recording when an agent's current
	// job times out, as an RFC 3339 timestamp.
	expiryMetadataKey = "buildkite-agent-expiry"
)

// metadata fetches the instance's metadata key/value pairs from the Compute
// Engine API.
func (id *instanceIdentity) metadata(ctx context.Context, svc *compute.Service) (map[string]string, error) {
	inst, err := svc.Instances.Get(id.projectID, id.zone, id.instanceID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance %s: %w", id.instanceID, err)
	}
	md := make(map[string]string)
	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			if item.Value != nil {
				md[item.Key] = *item.Value
			}
		}
	}
	return md, nil
}

func (id *instanceIdentity) queue(ctx context.Context, svc *compute.Service) (string, error) {
	metadata, err := id.metadata(ctx, svc)
	if err != nil {
		return "", err
	}
	return metadata["queue"], nil
}

// setMetadataAttempts is how many times setMetadata retries if
// it races with another metadata change.
const setMetadataAttempts = 5

// setMetadata sets a single metadata key on the instance and waits for the change
// to take effect.
//
// If the key is already set and replace is false, setMetadata returns an error.
// If replace is true, pre-existing keys are silently overwritten.
func (id *instanceIdentity) setMetadata(ctx context.Context, svc *compute.Service, key, value string, replace bool) error {
	var op *compute.Operation
	attempts := 0
	err := gax.Invoke(ctx, func(ctx context.Context, _ gax.CallSettings) error {
		attempts++
		if attempts > setMetadataAttempts {
			return fmt.Errorf("failed to set metadata %q on instance %v after %d attempts", key, id, attempts)
		}

		inst, err := svc.Instances.Get(id.projectID, id.zone, id.instanceID).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get instance %v: %w", id, err)
		}
		metadata := inst.Metadata
		if metadata == nil {
			metadata = &compute.Metadata{}
		}
		found := false
		for _, item := range metadata.Items {
			if item.Key == key {
				item.Value = &value
				found = true
			}
		}
		if found && !replace {
			return fmt.Errorf("metadata key %v already present in metadata for instance %v", key, id)
		}
		if !found {
			metadata.Items = append(metadata.Items, &compute.MetadataItems{Key: key, Value: &value})
		}
		op, err = svc.Instances.SetMetadata(id.projectID, id.zone, id.instanceID, metadata).Context(ctx).Do()
		if err == nil {
			return nil
		}
		log.Printf("Failed to set metadata %q on instance %s (attempt %d/%d): %v", key, id.instanceID, attempts, setMetadataAttempts, err)
		return err
	}, gax.WithRetry(func() gax.Retryer {
		return gax.OnHTTPCodes(gax.Backoff{
			Initial:    200 * time.Millisecond,
			Max:        5 * time.Second,
			Multiplier: 2,
		}, http.StatusPreconditionFailed)
	}))
	if err != nil {
		return err
	}

	// SetMetadata is asynchronous. Wait for apply
	for op.Status != "DONE" {
		var err error
		op, err = svc.ZoneOperations.Wait(id.projectID, id.zone, op.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to wait for metadata update on instance %s: %w", id.instanceID, err)
		}
	}
	if op.Error != nil && len(op.Error.Errors) > 0 {
		return fmt.Errorf("metadata update on instance %s failed: %s", id.instanceID, op.Error.Errors[0].Message)
	}
	return nil
}

// getAgent returns the agent running on this instance according to its pin.
func (id *instanceIdentity) getAgent(ctx context.Context, svc *compute.Service) (agent, error) {
	md, err := id.metadata(ctx, svc)
	if err != nil {
		return nil, err
	}
	agentMetadata := agentMetadata{queue: md["queue"]}
	pin, ok := md[pinMetadataKey]
	if ok && pin == "" {
		// Shouldn't be possible, but worth a sanity check
		return nil, fmt.Errorf("agent %v has pin metadata key present but empty", id)
	}
	switch pin {
	case "":
		return &unassignedAgent{instanceIdentity: *id, agentMetadata: agentMetadata}, nil
	case pinTrustedValue:
		return &trustedAgent{instanceIdentity: *id, agentMetadata: agentMetadata}, nil
	default:
		return &untrustedAgent{instanceIdentity: *id, agentMetadata: agentMetadata, buildUUID: BuildUUID(pin)}, nil
	}
}

type agent interface {
	getQueue() string
	String() string
}

type agentMetadata struct {
	queue string
}

func (m *agentMetadata) getQueue() string {
	return m.queue
}

// String describes the instance.
func (id instanceIdentity) String() string {
	return fmt.Sprintf("instance %s (%s/%s)", id.instanceID, id.zone, id.instanceName)
}

// unassignedAgent represents an agent that has not yet been designated as
// trusted or untrusted.
//
// unassignedAgent MUST NOT be constructed manually.
type unassignedAgent struct {
	instanceIdentity
	agentMetadata
}

// String implements agent.String().
func (a unassignedAgent) String() string {
	return fmt.Sprintf("unassigned agent on %v, metadata %v", a.instanceIdentity, a.agentMetadata)
}

func (a unassignedAgent) pinToBuild(ctx context.Context, svc *compute.Service, buildUUID BuildUUID) (untrustedAgent, error) {
	if err := a.setMetadata(ctx, svc, pinMetadataKey, string(buildUUID), false); err != nil {
		return untrustedAgent{}, err
	}
	return untrustedAgent{
		instanceIdentity: a.instanceIdentity,
		agentMetadata:    a.agentMetadata,
		buildUUID:        buildUUID,
	}, nil
}

func (a unassignedAgent) pinTrusted(ctx context.Context, svc *compute.Service) (trustedAgent, error) {
	if err := a.setMetadata(ctx, svc, pinMetadataKey, pinTrustedValue, false); err != nil {
		return trustedAgent{}, err
	}
	return trustedAgent{
		instanceIdentity: a.instanceIdentity,
		agentMetadata:    a.agentMetadata,
	}, nil
}

// trustedAgent represents an agent that only runs trusted jobs.
//
// trustedAgent MUST NOT be constructed manually.
type trustedAgent struct {
	instanceIdentity
	agentMetadata
}

// String implements agent.String().
func (a trustedAgent) String() string {
	return fmt.Sprintf("trusted agent on %v, metadata %v", a.instanceIdentity, a.agentMetadata)
}

// untrustedAgent represents an agent that is pinned to a specific build.
//
// untrustedAgent MUST NOT be constructed manually.
type untrustedAgent struct {
	instanceIdentity
	agentMetadata

	// buildUUID stores the build to which this agent is pinned.
	//
	// It is immutable.
	buildUUID BuildUUID
}

// String implements agent.String().
func (a untrustedAgent) String() string {
	return fmt.Sprintf("untrusted agent on %v, metadata %v, pinned to build %v", a.instanceIdentity, a.agentMetadata, a.buildUUID)
}
