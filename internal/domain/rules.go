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

// AssessmentSnapshot carries the plan-scoped state captured at the moment an
// assessment is generated. It is resolved under the store transaction so the
// resulting assessment is a stable, replayable record that can never observe
// probes registered later.
type AssessmentSnapshot struct {
	// Probes are all probes currently stored for the plan.
	Probes []Probe
	// ParticipatingNodeIDs are the nodes holding at least one lease for the
	// plan, i.e. the nodes required to be observed.
	ParticipatingNodeIDs []string
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	snapshot AssessmentSnapshot,
	now time.Time,
) RolloutAssessment {
	probes := snapshot.Probes
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	observedNodes := make(map[string]struct{})
	for _, probe := range probes {
		observedNodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}

	// Deterministic probe ordering feeds both the reference list and every
	// per-node summary.
	references := make([]ProbeReference, 0, len(probes))
	observations := make([]NodeObservation, 0, len(observedNodes))
	summaryByNode := make(map[string]int)
	for _, nodeID := range sortedNodeIDs(observedNodes) {
		summaryByNode[nodeID] = len(observations)
		observations = append(observations, NodeObservation{NodeID: nodeID})
	}
	// Latest probe per node is decided by stored time, with probe ID as a
	// deterministic tie breaker for identical clocks.
	latestProbeByNode := make(map[string]Probe)
	for _, probe := range probes {
		references = append(references, ProbeReference{
			ProbeID:  probe.ID,
			LeaseID:  probe.LeaseID,
			NodeID:   probe.NodeID,
			Success:  probe.Success,
			StoredAt: probe.StoredAt.UTC(),
		})
		observation := &observations[summaryByNode[probe.NodeID]]
		observation.ProbeCount++
		if probe.Success {
			observation.SuccessCount++
		} else {
			observation.FailureCount++
		}
		if probe.LatencyMS > observation.MaximumLatencyMS {
			observation.MaximumLatencyMS = probe.LatencyMS
		}
		latest, exists := latestProbeByNode[probe.NodeID]
		if !exists || probe.StoredAt.After(latest.StoredAt) ||
			probe.StoredAt.Equal(latest.StoredAt) && probe.ID > latest.ID {
			latestProbeByNode[probe.NodeID] = probe
		}
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].NodeID != references[j].NodeID {
			return references[i].NodeID < references[j].NodeID
		}
		return references[i].ProbeID < references[j].ProbeID
	})
	for index := range observations {
		observations[index].LastObservedSerial = latestProbeByNode[observations[index].NodeID].ObservedSerial
	}

	participating := make(map[string]struct{}, len(snapshot.ParticipatingNodeIDs))
	for _, nodeID := range snapshot.ParticipatingNodeIDs {
		participating[nodeID] = struct{}{}
	}
	missingNodeIDs := make([]string, 0)
	for nodeID := range participating {
		if _, observed := observedNodes[nodeID]; !observed {
			missingNodeIDs = append(missingNodeIDs, nodeID)
		}
	}
	sort.Strings(missingNodeIDs)

	if len(observedNodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
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
	}
}

func sortedNodeIDs(nodes map[string]struct{}) []string {
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

// VerifyAssessmentReferences checks that every reference frozen into a stored
// assessment still resolves in the current state and still points at the same
// probe and node. It never collects additional probes, so assessment details
// stay pinned to what existed at generation time. A dangling reference is an
// error rather than a silently omitted detail.
func VerifyAssessmentReferences(assessment RolloutAssessment, state *State) error {
	for _, reference := range assessment.ProbeReferences {
		probe, ok := state.Probes[reference.ProbeID]
		if !ok {
			return NewError(CodeStorageFailure, "assessment references a missing probe", map[string]any{
				"assessment_id": assessment.ID,
				"probe_id":      reference.ProbeID,
			})
		}
		if probe.PlanID != assessment.PlanID ||
			probe.LeaseID != reference.LeaseID ||
			probe.NodeID != reference.NodeID ||
			probe.Success != reference.Success ||
			!probe.StoredAt.UTC().Equal(reference.StoredAt.UTC()) {
			return NewError(CodeStorageFailure, "assessment probe reference no longer matches the stored probe", map[string]any{
				"assessment_id": assessment.ID,
				"probe_id":      reference.ProbeID,
			})
		}
	}
	for _, nodeID := range assessment.MissingNodeIDs {
		if _, ok := state.Nodes[nodeID]; !ok {
			return NewError(CodeStorageFailure, "assessment references a missing node", map[string]any{
				"assessment_id": assessment.ID,
				"node_id":       nodeID,
			})
		}
	}
	for _, observation := range assessment.NodeObservations {
		if _, ok := state.Nodes[observation.NodeID]; !ok {
			return NewError(CodeStorageFailure, "assessment references a missing node", map[string]any{
				"assessment_id": assessment.ID,
				"node_id":       observation.NodeID,
			})
		}
	}
	return nil
}

func timePointer(value time.Time) *time.Time {
	return &value
}
