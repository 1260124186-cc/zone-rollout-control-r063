package assessment

import (
	"context"
	"sort"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

type Service struct {
	store *store.Store
	clock platform.Clock
	ids   platform.IDGenerator
}

func New(stateStore *store.Store, clock platform.Clock, ids platform.IDGenerator) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids}
}

func (s *Service) Evaluate(
	ctx context.Context,
	planID string,
	input domain.AssessmentInput,
) (domain.RolloutAssessment, error) {
	if err := domain.ValidateAssessmentInput(input); err != nil {
		return domain.RolloutAssessment{}, err
	}
	now := s.clock.Now().UTC()
	requestIndex := planID + "\x00" + input.RequestKey
	var result domain.RolloutAssessment
	err := s.store.Write(ctx, func(state *domain.State) error {
		plan, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if plan.State == domain.PlanDraft {
			return domain.InvalidState("plan must be active or completed for assessment", map[string]any{
				"plan_id": planID,
				"state":   plan.State,
			})
		}
		if existingID, exists := state.AssessmentRequestKeys[requestIndex]; exists {
			existing, found := state.Assessments[existingID]
			if !found {
				return domain.NewError(domain.CodeStorageFailure, "assessment index is inconsistent", map[string]any{
					"assessment_id": existingID,
				})
			}
			// Replay returns the frozen record as-is; references must still
			// resolve explicitly rather than being silently dropped.
			if err := domain.VerifyAssessmentReferences(existing, state); err != nil {
				return err
			}
			result = existing
			return nil
		}
		if plan.LatestRevisionID == "" {
			return domain.InvalidState("plan has no zone revision", map[string]any{
				"plan_id": planID,
			})
		}
		revision, ok := state.Revisions[plan.LatestRevisionID]
		if !ok {
			return domain.NewError(domain.CodeStorageFailure, "plan references a missing revision", map[string]any{
				"revision_id": plan.LatestRevisionID,
			})
		}
		snapshot := collectSnapshot(state, planID)
		if len(snapshot.Probes) == 0 {
			return domain.NewError(domain.CodeNoProbes, "plan has no probes to assess", map[string]any{
				"plan_id": planID,
			})
		}
		result = domain.BuildAssessment(s.ids.New("asm"), plan, revision, snapshot, now)
		result.RequestKey = input.RequestKey
		if err := domain.VerifyAssessmentReferences(result, state); err != nil {
			return err
		}
		state.Assessments[result.ID] = result
		state.AssessmentRequestKeys[requestIndex] = result.ID
		plan.LatestAssessmentID = result.ID
		plan.Version++
		state.Plans[planID] = plan
		store.AddAudit(state, s.ids, "assessment", result.ID, "completed", now, map[string]any{
			"plan_id": planID,
			"verdict": result.Verdict,
		})
		return nil
	})
	return result, err
}

func (s *Service) Latest(ctx context.Context, planID string) (domain.RolloutAssessment, error) {
	var result domain.RolloutAssessment
	err := s.store.Read(ctx, func(state *domain.State) error {
		plan, ok := state.Plans[planID]
		if !ok {
			return domain.NotFound("plan", planID)
		}
		if plan.LatestAssessmentID == "" {
			return domain.NotFound("assessment", planID)
		}
		found, ok := state.Assessments[plan.LatestAssessmentID]
		if !ok {
			return domain.NewError(domain.CodeStorageFailure, "plan references a missing assessment", map[string]any{
				"assessment_id": plan.LatestAssessmentID,
			})
		}
		// Return the frozen detail; a missing reference fails the query
		// instead of being quietly omitted.
		if err := domain.VerifyAssessmentReferences(found, state); err != nil {
			return err
		}
		result = found
		return nil
	})
	return result, err
}

// collectSnapshot gathers the probes and participating nodes that currently
// exist for a plan. Everything downstream is derived only from this snapshot,
// so an assessment can never observe probes registered after it was stored.
func collectSnapshot(state *domain.State, planID string) domain.AssessmentSnapshot {
	snapshot := domain.AssessmentSnapshot{
		Probes:               make([]domain.Probe, 0),
		ParticipatingNodeIDs: make([]string, 0),
	}
	participating := make(map[string]struct{})
	for _, lease := range state.Leases {
		if lease.PlanID != planID {
			continue
		}
		participating[lease.NodeID] = struct{}{}
	}
	for _, probe := range state.Probes {
		if probe.PlanID == planID {
			snapshot.Probes = append(snapshot.Probes, probe)
		}
	}
	for nodeID := range participating {
		snapshot.ParticipatingNodeIDs = append(snapshot.ParticipatingNodeIDs, nodeID)
	}
	sort.Strings(snapshot.ParticipatingNodeIDs)
	return snapshot
}
