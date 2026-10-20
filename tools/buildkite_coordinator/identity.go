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
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
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
		return nil, fmt.Errorf("failed to get %v: %w", id, err)
	}
	return parseMetadata(inst.Metadata), nil
}

// parseMetadata parses an instance's metadata into a map[string]string.
// metadata may be nil.
func parseMetadata(metadata *compute.Metadata) map[string]string {
	ret := make(map[string]string)
	if metadata == nil {
		return ret
	}
	for _, item := range metadata.Items {
		if item.Value != nil {
			ret[item.Key] = *item.Value
		}
	}
	return ret
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
			return fmt.Errorf("failed to set metadata %q on %v after %d attempts", key, id, attempts)
		}

		inst, err := svc.Instances.Get(id.projectID, id.zone, id.instanceID).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get %v: %w", id, err)
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
			return fmt.Errorf("metadata key %v already present in metadata for %v", key, id)
		}
		if !found {
			metadata.Items = append(metadata.Items, &compute.MetadataItems{Key: key, Value: &value})
		}
		op, err = svc.Instances.SetMetadata(id.projectID, id.zone, id.instanceID, metadata).Context(ctx).Do()
		if err == nil {
			return nil
		}
		log.Printf("Failed to set metadata %q on %v (attempt %d/%d): %v", key, id, attempts, setMetadataAttempts, err)
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
			return fmt.Errorf("failed to wait for metadata update on %v: %w", id, err)
		}
	}
	if op.Error != nil && len(op.Error.Errors) > 0 {
		return fmt.Errorf("metadata update on %v failed: %s", id, op.Error.Errors[0].Message)
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

// setExpiryTime records when the instance's current job times out.
func (id *instanceIdentity) setExpiryTime(ctx context.Context, svc *compute.Service, expiry time.Time) error {
	return id.setMetadata(ctx, svc, expiryMetadataKey, expiry.UTC().Format(time.RFC3339), true /* replace */)
}

// forceDelete deletes the instance without a graceful shutdown, and waits for
// the deletion to finish.
func (id *instanceIdentity) forceDelete(ctx context.Context, svc *compute.Service) error {
	op, err := svc.Instances.Delete(id.projectID, id.zone, id.instanceID).Context(ctx).
		Do(googleapi.QueryParameter("noGracefulShutdown", "true"))
	if err != nil {
		var gerr *googleapi.Error
		if errors.As(err, &gerr) && gerr.Code == http.StatusNotFound {
			// Instance already doesn't exist, which is fine.
			return nil
		}
		return fmt.Errorf("failed to delete %v: %w", id, err)
	}

	// Delete is asynchronous; wait for it to succeed
	for op.Status != "DONE" {
		op, err = svc.ZoneOperations.Wait(id.projectID, id.zone, op.Name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to wait for deletion of %v: %w", id, err)
		}
	}
	if op.Error != nil && len(op.Error.Errors) > 0 {
		return fmt.Errorf("deletion of %v failed: %s", id, op.Error.Errors[0].Message)
	}
	return nil
}

// listAllInstances returns every instance in the project that runs as the
// given service account.
func listAllInstances(ctx context.Context, svc *compute.Service, project, serviceAccount string) ([]instanceIdentity, error) {
	var ids []instanceIdentity
	err := svc.Instances.AggregatedList(project).Context(ctx).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, scoped := range page.Items {
			for _, inst := range scoped.Instances {
				id := newInstanceIdentity(project, inst)
				if id.email != serviceAccount {
					continue
				}

				ids = append(ids, id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list instances in project %s: %w", project, err)
	}
	return ids, nil
}

func getInstanceExpiryBulk(ctx context.Context, svc *compute.Service, ids []instanceIdentity) (map[instanceIdentity]time.Time, error) {
	projects := make(map[string]struct{})
	idToIdentity := make(map[string]instanceIdentity)
	for _, id := range ids {
		projects[id.projectID] = struct{}{}
		idToIdentity[id.instanceID] = id
	}

	expiries := make(map[instanceIdentity]time.Time)
	for project := range projects {
		err := svc.Instances.AggregatedList(project).Context(ctx).Pages(ctx, func(page *compute.InstanceAggregatedList) error {
			for _, scoped := range page.Items {
				for _, inst := range scoped.Instances {
					id, ok := idToIdentity[strconv.FormatUint(inst.Id, 10)]
					if !ok {
						// This instance wasn't specified.
						continue
					}
					value, ok := parseMetadata(inst.Metadata)[expiryMetadataKey]
					if !ok {
						// Instance has no expiry metadata entry. Skip.
						continue
					}

					// Parse and return the expiry time
					expiry, err := time.Parse(time.RFC3339, value)
					if err != nil {
						log.Printf("Warning: %v has invalid expiry time (%s) %q", id, expiryMetadataKey, value)
						continue
					}
					expiries[id] = expiry
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list instances in project %s: %w", project, err)
		}
	}
	return expiries, nil
}

// newInstanceIdentity returns the identity of an instance from the Compute
// Engine API.
func newInstanceIdentity(project string, inst *compute.Instance) instanceIdentity {
	id := instanceIdentity{
		projectID:    project,
		zone:         path.Base(inst.Zone),
		instanceID:   strconv.FormatUint(inst.Id, 10),
		instanceName: inst.Name,
	}
	if len(inst.ServiceAccounts) > 0 {
		id.email = inst.ServiceAccounts[0].Email
	}
	return id
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
	if err := a.setMetadata(ctx, svc, pinMetadataKey, string(buildUUID), false /* replace */); err != nil {
		return untrustedAgent{}, err
	}
	return untrustedAgent{
		instanceIdentity: a.instanceIdentity,
		agentMetadata:    a.agentMetadata,
		buildUUID:        buildUUID,
	}, nil
}

func (a unassignedAgent) pinTrusted(ctx context.Context, svc *compute.Service) (trustedAgent, error) {
	if err := a.setMetadata(ctx, svc, pinMetadataKey, pinTrustedValue, false /* replace */); err != nil {
		return trustedAgent{}, err
	}
	return trustedAgent(a), nil
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
