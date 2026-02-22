package app

import "github.com/cosmos/cosmos-sdk/types"

// processEndBlockEvidence processes all pending evidence at EndBlock.
// It uses the integrated evidence processor if available (AS-16 compliance),
// falling back to the basic evidence processor.
func (app *AethelredApp) processEndBlockEvidence(ctx types.Context) {
	// Prefer integrated processor with full slashing module integration (AS-16)
	if app.integratedEvidenceProcessor != nil {
		result := app.integratedEvidenceProcessor.ProcessEndBlockEvidence(ctx)
		if result == nil {
			return
		}

		if len(result.DowntimeSlashes) > 0 || len(result.DoubleSignSlashes) > 0 {
			app.Logger().Warn("Integrated evidence processing applied slashing",
				"height", result.BlockHeight,
				"downtime_slashes", len(result.DowntimeSlashes),
				"double_sign_slashes", len(result.DoubleSignSlashes),
				"total_slashed", result.TotalSlashed().String(),
			)

			// Update metrics if available
			if metrics := app.PouwKeeper.Metrics(); metrics != nil {
				metrics.SlashingPenaltiesApplied.Add(int64(len(result.DowntimeSlashes)))
				metrics.SlashingPenaltiesApplied.Add(int64(len(result.DoubleSignSlashes)))
			}
		}
		return
	}

	// Fall back to basic evidence processor
	if app.evidenceProcessor == nil {
		return
	}

	result := app.evidenceProcessor.ProcessEndBlockEvidence(ctx)
	if result == nil {
		return
	}

	if len(result.DowntimePenalties) > 0 || len(result.EquivocationSlashes) > 0 {
		app.Logger().Warn("Evidence processing applied penalties",
			"height", result.BlockHeight,
			"downtime_penalties", len(result.DowntimePenalties),
			"equivocation_slashes", len(result.EquivocationSlashes),
		)
	}
}
