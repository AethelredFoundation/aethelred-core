package keeper

import (
	"context"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/verify/types"
)

// VerifyZKMLProof verifies a zero-knowledge ML proof.
func (k Keeper) VerifyZKMLProof(ctx context.Context, proof *types.ZKMLProof) (*types.VerificationResult, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	startTime := time.Now()

	result := &types.VerificationResult{
		VerificationType: types.VerificationTypeZKML,
		Timestamp:        timestamppb.Now(),
	}

	// Validate proof structure.
	if proof == nil {
		result.Success = false
		result.ErrorMessage = "proof cannot be nil"
		return result, nil
	}
	if err := proof.Validate(); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("invalid proof: %v", err)
		return result, nil
	}

	// Check if proof system is supported.
	params, _ := k.GetParams(ctx)
	if params == nil {
		params = types.DefaultParams()
	}
	supported := false
	for _, sys := range params.SupportedProofSystems {
		if sys == proof.ProofSystem {
			supported = true
			break
		}
	}
	if !supported {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("unsupported proof system: %s", proof.ProofSystem)
		return result, nil
	}

	// Get the verifying key.
	vkHashKey := fmt.Sprintf("%x", proof.VerifyingKeyHash)
	vk, err := k.VerifyingKeys.Get(ctx, vkHashKey)
	if err != nil {
		result.Success = false
		result.ErrorMessage = "verifying key not found"
		return result, nil
	}

	if !vk.IsActive {
		result.Success = false
		result.ErrorMessage = "verifying key is inactive"
		return result, nil
	}

	// Verify the proof.
	verified, err := k.verifyProofInternal(ctx, proof, &vk, params)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("verification failed: %v", err)
		return result, nil
	}

	result.Success = verified
	result.ZkProofVerified = verified
	result.VerificationTimeMs = time.Since(startTime).Milliseconds()

	// Emit event.
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"zkml_proof_verified",
			sdk.NewAttribute("proof_system", proof.ProofSystem),
			sdk.NewAttribute("success", fmt.Sprintf("%t", verified)),
			sdk.NewAttribute("verification_time_ms", fmt.Sprintf("%d", result.VerificationTimeMs)),
		),
	)

	return result, nil
}

// verifyProofInternal performs the actual proof verification.
// SECURITY: This function MUST NOT return true without cryptographic verification
// in production mode (AllowSimulated=false).
func (k Keeper) verifyProofInternal(ctx context.Context, proof *types.ZKMLProof, vk *types.VerifyingKey, params *types.Params) (bool, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// SECURITY: Remote verification is the primary path.
	if params.ZkVerifierEndpoint != "" {
		sdkCtx.Logger().Info("Calling remote ZK verifier",
			"endpoint", params.ZkVerifierEndpoint,
			"proof_system", proof.ProofSystem,
		)
		return k.callRemoteZKVerifier(ctx, params.ZkVerifierEndpoint, proof, vk)
	}

	// SECURITY: In production mode, verification MUST NOT pass without a configured verifier.
	if !params.AllowSimulated {
		sdkCtx.Logger().Error("ZK verification failed: no verifier endpoint configured",
			"proof_system", proof.ProofSystem,
			"allow_simulated", params.AllowSimulated,
		)
		return false, fmt.Errorf("SECURITY: zk verifier endpoint not configured and simulation disabled - cannot verify proof")
	}

	// WARNING: Simulated verification (DEVELOPMENT/TESTING ONLY).
	sdkCtx.Logger().Warn("SIMULATED VERIFICATION - NOT FOR PRODUCTION",
		"proof_system", proof.ProofSystem,
		"proof_size", len(proof.ProofBytes),
	)

	// Even in simulation mode, perform structural validation.
	if len(proof.ProofBytes) == 0 {
		return false, fmt.Errorf("proof bytes cannot be empty")
	}
	if len(proof.PublicInputs) == 0 {
		return false, fmt.Errorf("public inputs cannot be empty")
	}

	// Validate proof system is known.
	switch proof.ProofSystem {
	case "groth16":
		if len(proof.ProofBytes) < 192 {
			return false, fmt.Errorf("groth16 proof too small: %d bytes (minimum 192)", len(proof.ProofBytes))
		}
		return true, nil
	case "ezkl":
		if len(proof.ProofBytes) < 256 {
			return false, fmt.Errorf("ezkl proof too small: %d bytes (minimum 256)", len(proof.ProofBytes))
		}
		return true, nil
	case "halo2":
		if len(proof.ProofBytes) < 384 {
			return false, fmt.Errorf("halo2 proof too small: %d bytes (minimum 384)", len(proof.ProofBytes))
		}
		return true, nil
	case "plonky2":
		if len(proof.ProofBytes) < 256 {
			return false, fmt.Errorf("plonky2 proof too small: %d bytes (minimum 256)", len(proof.ProofBytes))
		}
		return true, nil
	case "risc0":
		if len(proof.ProofBytes) < 512 {
			return false, fmt.Errorf("risc0 proof too small: %d bytes (minimum 512)", len(proof.ProofBytes))
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown proof system: %s", proof.ProofSystem)
	}
}
