package workflowprobe

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runConsistencyAssessment() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	node1, err := enrollNode(harness, "resolver-assess-01", "west")
	if err != nil {
		return err
	}
	node2, err := enrollNode(harness, "resolver-assess-02", "west")
	if err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "assess.example", 3001, 2, 1, 40)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "assess-lease-0001", "west", 2)
	if err != nil {
		return err
	}
	submitted := make([]domain.Probe, 0, len(group.LeaseIDs))
	for index, leaseID := range group.LeaseIDs {
		requestKey := fmt.Sprintf("assess-probe-%s", leaseID)
		probe, err := submitProbe(harness, leaseID, requestKey, true, revision.Serial, 10+index)
		if err != nil {
			return err
		}
		submitted = append(submitted, probe)
	}

	var consistent domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "assess-request-0001",
	}, &consistent); err != nil {
		return err
	}
	if consistent.Verdict != domain.VerdictConsistent || consistent.ProbeCount != 2 {
		return ensure(false, "consistent assessment did not include both probes")
	}
	if err := checkObservationSummary(consistent, submitted); err != nil {
		return err
	}
	if len(consistent.ProbeReferences) != len(submitted) {
		return ensure(false, "assessment did not reference every submitted probe")
	}
	for index, probe := range submitted {
		reference := consistent.ProbeReferences[index]
		if reference.ProbeID != probe.ID || reference.LeaseID != probe.LeaseID ||
			reference.NodeID != probe.NodeID || !reference.Success {
			return ensure(false, "assessment probe reference does not point back to the submitted probe")
		}
	}
	if !slices.IsSortedFunc(consistent.ProbeReferences, func(a, b domain.ProbeReference) int {
		if a.NodeID != b.NodeID {
			return compareStrings(a.NodeID, b.NodeID)
		}
		return compareStrings(a.ProbeID, b.ProbeID)
	}) {
		return ensure(false, "probe references are not stably sorted")
	}
	if len(consistent.MissingNodeIDs) != 0 {
		return ensure(false, "fully observed plan unexpectedly lists missing nodes")
	}

	var replay domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "assess-request-0001",
	}, &replay); err != nil {
		return err
	}
	if replay.ID != consistent.ID {
		return ensure(false, "assessment replay returned another result")
	}
	if !reflect.DeepEqual(replay, consistent) {
		return ensure(false, "assessment replay did not return the frozen detail")
	}
	var latest domain.RolloutAssessment
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID+"/assessments/latest", nil, &latest); err != nil {
		return err
	}
	if latest.ID != consistent.ID {
		return ensure(false, "latest assessment does not match")
	}
	if !reflect.DeepEqual(latest, consistent) {
		return ensure(false, "latest query did not return the frozen detail")
	}

	// Probes registered after the assessment existed must never enter its
	// frozen detail, even though they are valid new observations.
	laterGroup, err := allocate(harness, plan.ID, "assess-lease-0002", "west", 2)
	if err != nil {
		return err
	}
	for index, leaseID := range laterGroup.LeaseIDs {
		requestKey := fmt.Sprintf("assess-later-probe-%s", leaseID)
		if _, err := submitProbe(harness, leaseID, requestKey, true, revision.Serial, 12+index); err != nil {
			return err
		}
	}
	var after domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "assess-request-0001",
	}, &after); err != nil {
		return err
	}
	if !reflect.DeepEqual(after, consistent) {
		return ensure(false, "replayed assessment observed probes registered after it was generated")
	}

	reviewPlan, reviewRevision, err := createActivePlan(harness, "review.example", 4001, 1, 1, 20)
	if err != nil {
		return err
	}
	reviewGroup, err := allocate(harness, reviewPlan.ID, "review-lease-0001", "west", 1)
	if err != nil {
		return err
	}
	reviewProbe, err := submitProbe(
		harness,
		reviewGroup.LeaseIDs[0],
		"review-probe-0001",
		true,
		reviewRevision.Serial+1,
		30,
	)
	if err != nil {
		return err
	}
	var review domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+reviewPlan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "review-request-0001",
	}, &review); err != nil {
		return err
	}
	if review.Verdict != domain.VerdictReviewRequired {
		return ensure(false, "mismatched serial did not require review")
	}
	if len(review.ProbeReferences) != 1 || review.ProbeReferences[0].ProbeID != reviewProbe.ID {
		return ensure(false, "review assessment lost the failing-condition probe reference")
	}

	missingPlan, missingRevision, err := createActivePlan(harness, "missing.example", 5001, 2, 1, 40)
	if err != nil {
		return err
	}
	missingGroup, err := allocate(harness, missingPlan.ID, "missing-lease-0001", "west", 2)
	if err != nil {
		return err
	}
	// Only the first leased node reports (and it reports a failed probe); the
	// second node stays silent so it must appear in the missing set.
	failedProbe, err := submitProbe(
		harness,
		missingGroup.LeaseIDs[0],
		"missing-probe-0001",
		false,
		missingRevision.Serial,
		8,
	)
	if err != nil {
		return err
	}
	silentNodeID := node2.ID
	if failedProbe.NodeID == node2.ID {
		silentNodeID = node1.ID
	}
	var missing domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+missingPlan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "missing-request-0001",
	}, &missing); err != nil {
		return err
	}
	if missing.Verdict != domain.VerdictReviewRequired ||
		!slices.Contains(missing.Reasons, "node_not_observed") {
		return ensure(false, "silent node did not trigger node_not_observed")
	}
	if len(missing.MissingNodeIDs) != 1 || missing.MissingNodeIDs[0] != silentNodeID {
		return ensure(false, "missing node set does not identify the silent node")
	}
	if !slices.IsSorted(missing.MissingNodeIDs) {
		return ensure(false, "missing node set is not sorted")
	}
	if len(missing.NodeObservations) != 1 {
		return ensure(false, "silent node must not appear in the observation summary")
	}
	observation := missing.NodeObservations[0]
	if observation.NodeID != failedProbe.NodeID || observation.ProbeCount != 1 ||
		observation.SuccessCount != 0 || observation.FailureCount != 1 {
		return ensure(false, "observation summary does not record the failed probe")
	}
	if len(missing.ProbeReferences) != 1 ||
		missing.ProbeReferences[0].ProbeID != failedProbe.ID ||
		missing.ProbeReferences[0].Success {
		return ensure(false, "failed probe reference is missing or mislabelled")
	}
	return nil
}

func checkObservationSummary(assessment domain.RolloutAssessment, probes []domain.Probe) error {
	if len(assessment.NodeObservations) != len(probes) {
		return ensure(false, "assessment does not summarize every observed node")
	}
	nodeIDs := make([]string, 0, len(probes))
	for _, probe := range probes {
		nodeIDs = append(nodeIDs, probe.NodeID)
	}
	slices.Sort(nodeIDs)
	for index, nodeID := range nodeIDs {
		if assessment.NodeObservations[index].NodeID != nodeID {
			return ensure(false, "node observations are not stably sorted by node id")
		}
		summary := assessment.NodeObservations[index]
		var matched domain.Probe
		for _, probe := range probes {
			if probe.NodeID == nodeID {
				matched = probe
				break
			}
		}
		if summary.ProbeCount != 1 || summary.SuccessCount != 1 || summary.FailureCount != 0 ||
			summary.MaximumLatencyMS != matched.LatencyMS ||
			summary.LastObservedSerial != matched.ObservedSerial {
			return ensure(false, "node observation summary does not match its probe")
		}
	}
	return nil
}

func compareStrings(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
