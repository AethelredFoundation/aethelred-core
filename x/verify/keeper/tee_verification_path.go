package keeper

import (
	"bytes"
	"context"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/verify/types"
)

const maxTEEAttestationFutureSkew = 2 * time.Minute

// VerifyTEEAttestation verifies a TEE attestation.
func (k Keeper) VerifyTEEAttestation(ctx context.Context, attestation *types.TEEAttestation) (*types.VerificationResult, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	startTime := time.Now()

	result := &types.VerificationResult{
		VerificationType: types.VerificationTypeTEE,
		Timestamp:        timestamppb.Now(),
	}

	// Validate attestation structure.
	if attestation == nil {
		result.Success = false
		result.ErrorMessage = "attestation cannot be nil"
		return result, nil
	}
	if err := attestation.Validate(); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("invalid attestation: %v", err)
		return result, nil
	}

	// Get TEE config for this platform.
	config, err := k.TEEConfigs.Get(ctx, attestation.Platform.String())
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("unknown TEE platform: %s", attestation.Platform.String())
		return result, nil
	}

	params, _ := k.GetParams(ctx)
	if params == nil {
		params = types.DefaultParams()
	}

	if !config.IsActive {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("TEE platform %s is not active", attestation.Platform.String())
		return result, nil
	}

	// SECURITY: production configurations must explicitly bound attestation age.
	if config.MaxQuoteAge == nil && !params.AllowSimulated {
		result.Success = false
		result.ErrorMessage = "SECURITY: max quote age must be configured in production"
		return result, nil
	}

	// Check quote age.
	if attestation.Timestamp == nil {
		result.Success = false
		result.ErrorMessage = "attestation timestamp missing"
		return result, nil
	}
	if config.MaxQuoteAge != nil {
		blockTime := sdkCtx.BlockTime()
		if blockTime.IsZero() {
			if params.AllowSimulated {
				sdkCtx.Logger().Warn("Block time not set; skipping attestation freshness check in simulated mode")
			} else {
				result.Success = false
				result.ErrorMessage = "missing block time for deterministic attestation freshness check"
				return result, nil
			}
		} else {
			attestationTime := attestation.Timestamp.AsTime()
			if attestationTime.After(blockTime.Add(maxTEEAttestationFutureSkew)) {
				result.Success = false
				result.ErrorMessage = "attestation timestamp is too far in the future"
				return result, nil
			}
			if blockTime.Sub(attestationTime) > config.MaxQuoteAge.AsDuration() {
				result.Success = false
				result.ErrorMessage = "attestation quote is too old"
				return result, nil
			}
		}
	}

	// Verify the measurement is trusted.
	measurementTrusted := false
	for _, trusted := range config.TrustedMeasurements {
		if bytes.Equal(trusted, attestation.Measurement) {
			measurementTrusted = true
			break
		}
	}

	// SECURITY FIX: In production, we MUST have trusted measurements configured.
	if len(config.TrustedMeasurements) == 0 {
		if params.AllowSimulated {
			sdkCtx.Logger().Warn("SECURITY WARNING: No trusted measurements configured - allowing any measurement (dev mode only)",
				"platform", attestation.Platform.String(),
				"measurement", fmt.Sprintf("%x", attestation.Measurement),
			)
			measurementTrusted = true
		} else {
			result.Success = false
			result.ErrorMessage = "SECURITY: no trusted measurements configured for this TEE platform"
			return result, nil
		}
	}

	if !measurementTrusted {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("enclave measurement %x not in trusted list", attestation.Measurement)
		return result, nil
	}

	// SECURITY: require an anti-replay nonce for AWS Nitro attestations in production.
	if attestation.Platform == types.TEEPlatformAWSNitro && !params.AllowSimulated && len(attestation.Nonce) == 0 {
		result.Success = false
		result.ErrorMessage = "SECURITY: AWS Nitro attestation nonce is required in production"
		return result, nil
	}

	// Verify the attestation quote.
	verified, err := k.verifyAttestationInternal(ctx, attestation, &config, params.AllowSimulated)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("attestation verification failed: %v", err)
		return result, nil
	}
	if verified {
		if err := k.checkAndRecordTEEReplay(ctx, attestation, &config, params); err != nil {
			result.Success = false
			result.ErrorMessage = fmt.Sprintf("attestation replay check failed: %v", err)
			return result, nil
		}
	}

	result.Success = verified
	result.TeeAttestationVerified = verified
	result.VerificationTimeMs = time.Since(startTime).Milliseconds()

	// Emit event.
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"tee_attestation_verified",
			sdk.NewAttribute("platform", attestation.Platform.String()),
			sdk.NewAttribute("success", fmt.Sprintf("%t", verified)),
			sdk.NewAttribute("verification_time_ms", fmt.Sprintf("%d", result.VerificationTimeMs)),
		),
	)

	return result, nil
}

// verifyAttestationInternal performs the actual TEE attestation verification.
// SECURITY: This function MUST NOT return true without cryptographic verification
// in production mode (AllowSimulated=false).
func (k Keeper) verifyAttestationInternal(ctx context.Context, attestation *types.TEEAttestation, config *types.TEEConfig, allowSimulated bool) (bool, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// SECURITY: Remote verification is the primary path for production.
	if config.AttestationEndpoint != "" {
		sdkCtx.Logger().Info("Calling remote TEE attestation verifier",
			"endpoint", config.AttestationEndpoint,
			"platform", attestation.Platform.String(),
		)
		return k.callRemoteAttestationVerifier(ctx, config.AttestationEndpoint, attestation)
	}

	// SECURITY: In production mode, verification MUST NOT pass without a configured verifier.
	if !allowSimulated {
		sdkCtx.Logger().Error("TEE attestation verification failed: no verifier endpoint configured",
			"platform", attestation.Platform.String(),
			"allow_simulated", allowSimulated,
		)
		return false, fmt.Errorf("SECURITY: attestation endpoint not configured and simulation disabled - cannot verify attestation")
	}

	// WARNING: Simulated verification (DEVELOPMENT/TESTING ONLY).
	sdkCtx.Logger().Warn("SIMULATED TEE ATTESTATION - NOT FOR PRODUCTION",
		"platform", attestation.Platform.String(),
		"quote_size", len(attestation.Quote),
	)

	// Even in simulation mode, perform structural validation.
	if len(attestation.Quote) == 0 {
		return false, fmt.Errorf("attestation quote cannot be empty")
	}
	if len(attestation.Measurement) == 0 {
		return false, fmt.Errorf("attestation measurement cannot be empty")
	}

	// Adapter dispatch for hardware-specific attestation formats.
	return k.verifyPlatformAttestationAdapter(attestation)
}

func (k Keeper) verifyPlatformAttestationAdapter(attestation *types.TEEAttestation) (bool, error) {
	switch attestation.Platform {
	case types.TEEPlatformAWSNitro:
		return verifyAWSNitroAttestation(attestation)
	case types.TEEPlatformIntelSGX:
		return verifyIntelSGXAttestation(attestation)
	case types.TEEPlatformIntelTDX:
		return verifyIntelTDXAttestation(attestation)
	case types.TEEPlatformAMDSEV:
		return verifyAMDSEVAttestation(attestation)
	default:
		return false, fmt.Errorf("unsupported TEE platform: %s", attestation.Platform.String())
	}
}

func verifyAWSNitroAttestation(attestation *types.TEEAttestation) (bool, error) {
	if len(attestation.Quote) < 1000 {
		return false, fmt.Errorf("AWS Nitro attestation document too small: %d bytes", len(attestation.Quote))
	}
	allZero := true
	for _, b := range attestation.Quote {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false, fmt.Errorf("AWS Nitro attestation document cannot be all zeros")
	}
	return true, nil
}

func verifyIntelSGXAttestation(attestation *types.TEEAttestation) (bool, error) {
	if len(attestation.Quote) < 432 {
		return false, fmt.Errorf("Intel SGX quote too small: %d bytes (minimum 432)", len(attestation.Quote))
	}
	return true, nil
}

func verifyIntelTDXAttestation(attestation *types.TEEAttestation) (bool, error) {
	if len(attestation.Quote) < 584 {
		return false, fmt.Errorf("Intel TDX quote too small: %d bytes (minimum 584)", len(attestation.Quote))
	}
	return true, nil
}

func verifyAMDSEVAttestation(attestation *types.TEEAttestation) (bool, error) {
	// SEV-SNP report blobs are expected to be >= 672 bytes in our adapter.
	if len(attestation.Quote) < 672 {
		return false, fmt.Errorf("AMD SEV attestation report too small: %d bytes (minimum 672)", len(attestation.Quote))
	}
	return true, nil
}
