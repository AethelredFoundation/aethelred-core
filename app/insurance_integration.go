package app

import (
	"context"
	"sort"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// PoUWTribunalValidatorSource builds tribunal candidates from online PoUW validators.
type PoUWTribunalValidatorSource struct {
	pouwKeeper *pouwkeeper.Keeper
}

func NewPoUWTribunalValidatorSource(pouwKeeper *pouwkeeper.Keeper) PoUWTribunalValidatorSource {
	return PoUWTribunalValidatorSource{pouwKeeper: pouwKeeper}
}

func (s PoUWTribunalValidatorSource) ListValidators(ctx context.Context) ([]string, error) {
	if s.pouwKeeper == nil {
		return nil, nil
	}

	candidates := make([]string, 0, 64)
	_ = s.pouwKeeper.ValidatorCapabilities.Walk(ctx, nil, func(addr string, capability pouwtypes.ValidatorCapability) (bool, error) {
		if capability.IsOnline {
			candidates = append(candidates, addr)
		}
		return false, nil
	})

	sort.Strings(candidates)
	return candidates, nil
}

func (s PoUWTribunalValidatorSource) IsValidatorSlashed(_ context.Context, _ string) bool {
	// Dedicated slashing status source can be wired later; current tribunal selection
	// already excludes validators with active insurance escrows.
	return false
}
