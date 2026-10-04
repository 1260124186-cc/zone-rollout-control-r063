package assessment

import (
	"context"

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
			// Same-key replay returns the frozen snapshot, but a dangling
			// reference is reported instead of being silently dropped.
			if err := domain.VerifyAssessmentSnapshot(existing, state); err != nil {
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
		probes := make([]domain.Probe, 0)
		leases := make([]domain.NodeLease, 0)
		leaseNodeIDs := make(map[string]struct{})
		for _, lease := range state.Leases {
			if lease.PlanID != planID {
				continue
			}
			leases = append(leases, lease)
			leaseNodeIDs[lease.NodeID] = struct{}{}
		}
		nodes := make([]domain.ResolverNode, 0, len(leaseNodeIDs))
		for nodeID := range leaseNodeIDs {
			node, ok := state.Nodes[nodeID]
			if !ok {
				return domain.NewError(domain.CodeStorageFailure, "lease references a missing node", map[string]any{
					"node_id": nodeID,
				})
			}
			nodes = append(nodes, node)
		}
		for _, probe := range state.Probes {
			if probe.PlanID != planID {
				continue
			}
			if _, ok := leaseNodeIDs[probe.NodeID]; !ok {
				return domain.NewError(domain.CodeStorageFailure, "probe references a node without a plan lease", map[string]any{
					"probe_id": probe.ID,
					"node_id":  probe.NodeID,
				})
			}
			probes = append(probes, probe)
		}
		if len(probes) == 0 {
			return domain.NewError(domain.CodeNoProbes, "plan has no probes to assess", map[string]any{
				"plan_id": planID,
			})
		}
		built, err := domain.BuildAssessment(s.ids.New("asm"), domain.AssessmentSnapshot{
			Plan:     plan,
			Revision: revision,
			Probes:   probes,
			Leases:   leases,
			Nodes:    nodes,
		}, now)
		if err != nil {
			return err
		}
		result = built
		result.RequestKey = input.RequestKey
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
		// The stored detail snapshot is immutable; only verify that its
		// references still resolve so missing links surface as failures.
		if err := domain.VerifyAssessmentSnapshot(found, state); err != nil {
			return err
		}
		result = found
		return nil
	})
	return result, err
}
