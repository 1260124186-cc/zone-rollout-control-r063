package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// AssessmentSnapshot bundles every state item an assessment is derived from.
// All probes and leases must already be filtered to the assessed plan.
type AssessmentSnapshot struct {
	Plan     RolloutPlan
	Revision ZoneRevision
	Probes   []Probe
	Leases   []NodeLease
	Nodes    []ResolverNode
}

func BuildAssessment(
	id string,
	snapshot AssessmentSnapshot,
	now time.Time,
) (RolloutAssessment, error) {
	plan := snapshot.Plan
	revision := snapshot.Revision
	probes := snapshot.Probes
	leaseByID := make(map[string]NodeLease, len(snapshot.Leases))
	for _, lease := range snapshot.Leases {
		leaseByID[lease.ID] = lease
	}
	nodeByID := make(map[string]ResolverNode, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		nodeByID[node.ID] = node
	}

	// Every probe reference must resolve to a lease and node captured by the
	// assessment; a dangling reference is reported rather than silently
	// dropped from the detail snapshot.
	sortedProbes := make([]Probe, len(probes))
	copy(sortedProbes, probes)
	sort.Slice(sortedProbes, func(i, j int) bool {
		return sortedProbes[i].ID < sortedProbes[j].ID
	})
	references := make([]ProbeReference, 0, len(sortedProbes))
	observedNodeSet := make(map[string]struct{})
	for _, probe := range sortedProbes {
		lease, ok := leaseByID[probe.LeaseID]
		if !ok {
			return RolloutAssessment{}, NewError(CodeStorageFailure, "probe references a missing lease", map[string]any{
				"probe_id": probe.ID,
				"lease_id": probe.LeaseID,
			})
		}
		if lease.PlanID != probe.PlanID || lease.NodeID != probe.NodeID {
			return RolloutAssessment{}, NewError(CodeStorageFailure, "probe does not match its lease", map[string]any{
				"probe_id": probe.ID,
				"lease_id": probe.LeaseID,
			})
		}
		if _, ok := nodeByID[probe.NodeID]; !ok {
			return RolloutAssessment{}, NewError(CodeStorageFailure, "probe references a missing node", map[string]any{
				"probe_id": probe.ID,
				"node_id":  probe.NodeID,
			})
		}
		observedNodeSet[probe.NodeID] = struct{}{}
		references = append(references, ProbeReference{
			ProbeID:        probe.ID,
			LeaseID:        probe.LeaseID,
			NodeID:         probe.NodeID,
			RequestKey:     probe.RequestKey,
			Success:        probe.Success,
			ObservedSerial: probe.ObservedSerial,
			LatencyMS:      probe.LatencyMS,
			ObservedAt:     probe.ObservedAt.UTC(),
		})
	}

	// The expected node set is every node that received a lease for the
	// plan, regardless of the lease lifecycle; nodes that never reported a
	// probe are surfaced as missing.
	expectedNodeSet := make(map[string]struct{})
	for _, lease := range snapshot.Leases {
		expectedNodeSet[lease.NodeID] = struct{}{}
	}
	missingNodeIDs := make([]string, 0)
	for nodeID := range expectedNodeSet {
		if _, observed := observedNodeSet[nodeID]; !observed {
			missingNodeIDs = append(missingNodeIDs, nodeID)
		}
	}
	sort.Strings(missingNodeIDs)

	type nodeAggregate struct {
		probeCount   int
		successCount int
		failureCount int
		serials      map[uint32]struct{}
		maxLatency   int
		lastObserved time.Time
	}
	aggregates := make(map[string]*nodeAggregate)
	successCount := 0
	maximumLatency := 0
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	for _, probe := range probes {
		aggregate := aggregates[probe.NodeID]
		if aggregate == nil {
			aggregate = &nodeAggregate{serials: make(map[uint32]struct{})}
			aggregates[probe.NodeID] = aggregate
		}
		aggregate.probeCount++
		aggregate.serials[probe.ObservedSerial] = struct{}{}
		if probe.LatencyMS > aggregate.maxLatency {
			aggregate.maxLatency = probe.LatencyMS
		}
		if probe.ObservedAt.After(aggregate.lastObserved) {
			aggregate.lastObserved = probe.ObservedAt.UTC()
		}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			aggregate.successCount++
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		} else {
			aggregate.failureCount++
		}
	}
	if len(observedNodeSet) < plan.ExpectedNodes || len(missingNodeIDs) > 0 {
		reasons["node_not_observed"] = struct{}{}
	}

	observationNodeIDs := make([]string, 0, len(aggregates))
	for nodeID := range aggregates {
		observationNodeIDs = append(observationNodeIDs, nodeID)
	}
	sort.Strings(observationNodeIDs)
	observations := make([]NodeObservation, 0, len(observationNodeIDs))
	for _, nodeID := range observationNodeIDs {
		aggregate := aggregates[nodeID]
		serials := make([]uint32, 0, len(aggregate.serials))
		for serial := range aggregate.serials {
			serials = append(serials, serial)
		}
		sort.Slice(serials, func(i, j int) bool {
			return serials[i] < serials[j]
		})
		observations = append(observations, NodeObservation{
			NodeID:           nodeID,
			ProbeCount:       aggregate.probeCount,
			SuccessCount:     aggregate.successCount,
			FailureCount:     aggregate.failureCount,
			ObservedSerials:  serials,
			MaximumLatencyMS: aggregate.maxLatency,
			LastObservedAt:   aggregate.lastObserved,
		})
	}

	probeCount := len(probes)
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		NodeObservations: observations,
		ProbeReferences:  references,
		MissingNodeIDs:   missingNodeIDs,
		CreatedAt:        now.UTC(),
	}, nil
}

// VerifyAssessmentSnapshot confirms that a stored assessment can still resolve
// every captured probe reference and node observation against current state.
// The detail snapshot itself is immutable; this only turns a dangling
// reference into an explicit failure instead of serving a partial result.
func VerifyAssessmentSnapshot(assessment RolloutAssessment, state *State) error {
	if len(assessment.ProbeReferences) != assessment.ProbeCount {
		return NewError(CodeStorageFailure, "assessment reference count is inconsistent", map[string]any{
			"assessment_id": assessment.ID,
		})
	}
	observationCounts := make(map[string]int, len(assessment.NodeObservations))
	for index, observation := range assessment.NodeObservations {
		if index > 0 && assessment.NodeObservations[index-1].NodeID >= observation.NodeID {
			return NewError(CodeStorageFailure, "assessment node observations are not stably ordered", map[string]any{
				"assessment_id": assessment.ID,
			})
		}
		observationCounts[observation.NodeID] = observation.ProbeCount
	}
	for index, reference := range assessment.ProbeReferences {
		if index > 0 && assessment.ProbeReferences[index-1].ProbeID >= reference.ProbeID {
			return NewError(CodeStorageFailure, "assessment probe references are not stably ordered", map[string]any{
				"assessment_id": assessment.ID,
			})
		}
		probe, ok := state.Probes[reference.ProbeID]
		if !ok {
			return NewError(CodeStorageFailure, "assessment references a missing probe", map[string]any{
				"assessment_id": assessment.ID,
				"probe_id":      reference.ProbeID,
			})
		}
		if probe.PlanID != assessment.PlanID ||
			probe.LeaseID != reference.LeaseID ||
			probe.NodeID != reference.NodeID {
			return NewError(CodeStorageFailure, "assessment probe reference does not match the stored probe", map[string]any{
				"assessment_id": assessment.ID,
				"probe_id":      reference.ProbeID,
			})
		}
		observationCounts[reference.NodeID]--
	}
	for nodeID := range observationCounts {
		if observationCounts[nodeID] != 0 {
			return NewError(CodeStorageFailure, "assessment node observations do not match probe references", map[string]any{
				"assessment_id": assessment.ID,
				"node_id":       nodeID,
			})
		}
	}
	for index, nodeID := range assessment.MissingNodeIDs {
		if index > 0 && assessment.MissingNodeIDs[index-1] >= nodeID {
			return NewError(CodeStorageFailure, "assessment missing node list is not stably ordered", map[string]any{
				"assessment_id": assessment.ID,
			})
		}
		if _, ok := state.Nodes[nodeID]; !ok {
			return NewError(CodeStorageFailure, "assessment references a missing node", map[string]any{
				"assessment_id": assessment.ID,
				"node_id":       nodeID,
			})
		}
	}
	return nil
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
