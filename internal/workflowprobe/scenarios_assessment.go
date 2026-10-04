package workflowprobe

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runConsistencyAssessment() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	if _, err := enrollNode(harness, "resolver-assess-01", "west"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-assess-02", "west"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-review-01", "central"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-missing-01", "east"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-missing-02", "east"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-missing-03", "east"); err != nil {
		return err
	}

	// --- consistent plan: two nodes, two successful probes -----------------
	plan, revision, err := createActivePlan(harness, "assess.example", 3001, 2, 1, 40)
	if err != nil {
		return err
	}
	group, err := allocate(harness, plan.ID, "assess-lease-0001", "west", 2)
	if err != nil {
		return err
	}
	submitted := make(map[string]domain.Probe, len(group.LeaseIDs))
	for index, leaseID := range group.LeaseIDs {
		requestKey := fmt.Sprintf("assess-probe-%s", leaseID)
		probe, err := submitProbe(harness, leaseID, requestKey, true, revision.Serial, 10+index)
		if err != nil {
			return err
		}
		submitted[leaseID] = probe
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
	if err := assertAssessmentDetails(consistent, submitted); err != nil {
		return err
	}
	if len(consistent.MissingNodeIDs) != 0 {
		return ensure(false, "consistent assessment reported missing nodes")
	}
	var replay domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "assess-request-0001",
	}, &replay); err != nil {
		return err
	}
	if replay.ID != consistent.ID || !reflect.DeepEqual(replay, consistent) {
		return ensure(false, "assessment replay returned different content")
	}
	var latest domain.RolloutAssessment
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID+"/assessments/latest", nil, &latest); err != nil {
		return err
	}
	if latest.ID != consistent.ID || !reflect.DeepEqual(latest, consistent) {
		return ensure(false, "latest assessment does not match the stored result")
	}

	// --- serial mismatch review -------------------------------------------
	reviewPlan, reviewRevision, err := createActivePlan(harness, "review.example", 4001, 1, 1, 20)
	if err != nil {
		return err
	}
	reviewGroup, err := allocate(harness, reviewPlan.ID, "review-lease-0001", "central", 1)
	if err != nil {
		return err
	}
	if _, err := submitProbe(
		harness,
		reviewGroup.LeaseIDs[0],
		"review-probe-0001",
		true,
		reviewRevision.Serial+1,
		10,
	); err != nil {
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
	if !hasReason(review.Reasons, "serial_mismatch") {
		return ensure(false, "mismatched serial did not surface the serial_mismatch reason")
	}
	if len(review.ProbeReferences) != 1 || !review.ProbeReferences[0].Success {
		return ensure(false, "review assessment did not reference its probe")
	}

	// --- node_not_observed with one failed probe --------------------------
	// Three east nodes are leased for a plan expecting three observations;
	// only two report, one successfully and one failing. The third node must
	// be surfaced by id in the missing-node set, while the failed probe must
	// still be referenced explicitly.
	missingPlan, missingRevision, err := createActivePlan(harness, "missing.example", 5001, 3, 1, 60)
	if err != nil {
		return err
	}
	missingGroup, err := allocate(harness, missingPlan.ID, "missing-lease-0001", "east", 3)
	if err != nil {
		return err
	}
	if len(missingGroup.LeaseIDs) != 3 {
		return ensure(false, "missing-node plan needed three leases")
	}
	successProbe, err := submitProbe(
		harness,
		missingGroup.LeaseIDs[0],
		"missing-probe-success",
		true,
		missingRevision.Serial,
		5,
	)
	if err != nil {
		return err
	}
	failedProbe, err := submitProbe(
		harness,
		missingGroup.LeaseIDs[1],
		"missing-probe-failure",
		false,
		missingRevision.Serial+1,
		70,
	)
	if err != nil {
		return err
	}
	var missing domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+missingPlan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "missing-request-0001",
	}, &missing); err != nil {
		return err
	}
	if missing.Verdict != domain.VerdictReviewRequired || !hasReason(missing.Reasons, "node_not_observed") {
		return ensure(false, "an unobserved leased node did not surface node_not_observed")
	}
	if !hasReason(missing.Reasons, "latency_limit_exceeded") {
		return ensure(false, "failing probe latency did not surface latency_limit_exceeded")
	}
	if len(missing.MissingNodeIDs) != 1 {
		return ensure(false, "missing-node assessment did not list exactly one missing node")
	}
	missingNodeID := missing.MissingNodeIDs[0]
	if missingNodeID == successProbe.NodeID || missingNodeID == failedProbe.NodeID {
		return ensure(false, "missing node set names an observed node")
	}
	if err := assertMissingDetails(missing, successProbe, failedProbe); err != nil {
		return err
	}

	// --- frozen snapshot: a fourth node is leased and reports -------------
	// after the assessment exists. Subsequent latest queries and same-key
	// replays must keep returning the exact stored content instead of
	// reading the newly arrived probe.
	harness.clock.Advance(30 * time.Second)
	lateProbe, err := submitLateProbe(harness, missingPlan.ID, missingRevision.Serial)
	if err != nil {
		return err
	}
	if lateProbe.NodeID == missingNodeID {
		return ensure(false, "test setup did not provide a distinct late-reporting node")
	}
	var frozenReplay domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+missingPlan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "missing-request-0001",
	}, &frozenReplay); err != nil {
		return err
	}
	if !reflect.DeepEqual(frozenReplay, missing) {
		return ensure(false, "same-key replay picked up a probe stored after the assessment")
	}
	var frozenLatest domain.RolloutAssessment
	if err := harness.call(http.MethodGet, "/v1/plans/"+missingPlan.ID+"/assessments/latest", nil, &frozenLatest); err != nil {
		return err
	}
	if !reflect.DeepEqual(frozenLatest, missing) {
		return ensure(false, "latest query picked up a probe stored after the assessment")
	}
	return nil
}

// submitLateProbe enrolls a fourth node in a fresh region after the assessment
// was created, leases it for the plan and stores one probe. The probe API is
// the only entry used, so no extra read route is needed.
func submitLateProbe(harness *harness, planID string, serial uint32) (domain.Probe, error) {
	if _, err := enrollNode(harness, "resolver-late-01", "south"); err != nil {
		return domain.Probe{}, err
	}
	group, err := allocate(harness, planID, "missing-lease-0002", "south", 1)
	if err != nil {
		return domain.Probe{}, err
	}
	if len(group.LeaseIDs) != 1 {
		return domain.Probe{}, ensure(false, "late allocation should lease exactly one node")
	}
	return submitProbe(harness, group.LeaseIDs[0], "missing-probe-late", true, serial, 8)
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func assertAssessmentDetails(assessment domain.RolloutAssessment, submitted map[string]domain.Probe) error {
	if len(assessment.NodeObservations) != 2 {
		return ensure(false, "consistent assessment did not summarize both observed nodes")
	}
	if !sort.SliceIsSorted(assessment.NodeObservations, func(i, j int) bool {
		return assessment.NodeObservations[i].NodeID < assessment.NodeObservations[j].NodeID
	}) {
		return ensure(false, "node observations are not stably sorted")
	}
	for _, observation := range assessment.NodeObservations {
		if observation.ProbeCount != 1 || observation.SuccessCount != 1 || observation.FailureCount != 0 {
			return ensure(false, "node observation counts are incorrect")
		}
		if len(observation.ObservedSerials) != 1 {
			return ensure(false, "node observation did not capture the observed serial")
		}
		if observation.LastObservedAt == (time.Time{}) {
			return ensure(false, "node observation did not capture the last observed time")
		}
	}
	if len(assessment.ProbeReferences) != len(submitted) {
		return ensure(false, "assessment did not reference every probe")
	}
	if !sort.SliceIsSorted(assessment.ProbeReferences, func(i, j int) bool {
		return assessment.ProbeReferences[i].ProbeID < assessment.ProbeReferences[j].ProbeID
	}) {
		return ensure(false, "probe references are not stably sorted")
	}
	for _, reference := range assessment.ProbeReferences {
		probe, ok := submitted[reference.LeaseID]
		if !ok {
			return ensure(false, "assessment references an unrelated lease")
		}
		if reference.ProbeID != probe.ID || reference.NodeID != probe.NodeID ||
			reference.RequestKey != probe.RequestKey || reference.ObservedSerial != probe.ObservedSerial ||
			reference.LatencyMS != probe.LatencyMS || !reference.Success {
			return ensure(false, "probe reference does not match the stored probe")
		}
	}
	return nil
}

func assertMissingDetails(assessment domain.RolloutAssessment, successProbe, failedProbe domain.Probe) error {
	if len(assessment.NodeObservations) != 2 {
		return ensure(false, "missing-node assessment did not summarize both observed nodes")
	}
	if !sort.SliceIsSorted(assessment.NodeObservations, func(i, j int) bool {
		return assessment.NodeObservations[i].NodeID < assessment.NodeObservations[j].NodeID
	}) {
		return ensure(false, "missing-node observations are not stably sorted")
	}
	observationByNode := make(map[string]domain.NodeObservation)
	for _, observation := range assessment.NodeObservations {
		observationByNode[observation.NodeID] = observation
	}
	successObservation, ok := observationByNode[successProbe.NodeID]
	if !ok || successObservation.SuccessCount != 1 || successObservation.FailureCount != 0 {
		return ensure(false, "successful node observation is incorrect")
	}
	failureObservation, ok := observationByNode[failedProbe.NodeID]
	if !ok || failureObservation.FailureCount != 1 || failureObservation.SuccessCount != 0 {
		return ensure(false, "failed node observation is incorrect")
	}
	if len(assessment.ProbeReferences) != 2 {
		return ensure(false, "missing-node assessment must reference both successful and failed probes")
	}
	if !sort.SliceIsSorted(assessment.ProbeReferences, func(i, j int) bool {
		return assessment.ProbeReferences[i].ProbeID < assessment.ProbeReferences[j].ProbeID
	}) {
		return ensure(false, "missing-node probe references are not stably sorted")
	}
	referenceByID := make(map[string]domain.ProbeReference)
	for _, reference := range assessment.ProbeReferences {
		referenceByID[reference.ProbeID] = reference
	}
	failedReference, ok := referenceByID[failedProbe.ID]
	if !ok {
		return ensure(false, "failed probe reference was silently omitted")
	}
	if failedReference.Success || failedReference.LeaseID != failedProbe.LeaseID ||
		failedReference.NodeID != failedProbe.NodeID {
		return ensure(false, "failed probe reference does not match the stored probe")
	}
	successReference, ok := referenceByID[successProbe.ID]
	if !ok || !successReference.Success {
		return ensure(false, "successful probe reference is missing or incorrect")
	}
	if !sort.StringsAreSorted(assessment.MissingNodeIDs) {
		return ensure(false, "missing node list is not stably sorted")
	}
	return nil
}
