package app

import (
	"encoding/json"
	"fmt"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/verify"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// Compile-time interface satisfaction check.
var _ pouwkeeper.JobVerifier = (*OrchestratorBridge)(nil)

// OrchestratorBridge adapts a verify.VerificationOrchestrator so it can be used
// as a pouwkeeper.JobVerifier. It lives in the app package (the composition root)
// to avoid circular imports between x/pouw/keeper and x/verify.
type OrchestratorBridge struct {
	orchestrator *verify.VerificationOrchestrator
}

// NewOrchestratorBridge creates a new bridge that delegates job verification to
// the given VerificationOrchestrator.
func NewOrchestratorBridge(orchestrator *verify.VerificationOrchestrator) *OrchestratorBridge {
	return &OrchestratorBridge{
		orchestrator: orchestrator,
	}
}

// VerifyJob implements pouwkeeper.JobVerifier.
//
// It translates the PoUW domain types (ComputeJob, RegisteredModel) into a
// verify.VerificationRequest, delegates to the orchestrator, and maps the
// verify.VerificationResponse back into a pouwtypes.VerificationResult.
func (ob *OrchestratorBridge) VerifyJob(
	ctx sdk.Context,
	job *pouwtypes.ComputeJob,
	model *pouwtypes.RegisteredModel,
	validatorAddr string,
) (pouwtypes.VerificationResult, error) {
	if job == nil {
		return pouwtypes.VerificationResult{}, fmt.Errorf("job cannot be nil")
	}
	if model == nil {
		return pouwtypes.VerificationResult{}, fmt.Errorf("model cannot be nil")
	}

	// Map PoUW proof type → verify verification type.
	vType, err := mapProofType(job.ProofType)
	if err != nil {
		return pouwtypes.VerificationResult{
			ValidatorAddress: validatorAddr,
			Success:          false,
			ErrorMessage:     err.Error(),
			Timestamp:        timestamppb.Now(),
		}, nil
	}

	// Build the verification request.
	req := &verify.VerificationRequest{
		RequestID:        fmt.Sprintf("%s-%s", job.Id, validatorAddr),
		ModelHash:        job.ModelHash,
		InputHash:        job.InputHash,
		VerificationType: vType,
		CircuitHash:      model.CircuitHash,
		VerifyingKeyHash: model.VerifyingKeyHash,
		Priority:         int(job.Priority),
		Metadata: map[string]string{
			"job_id":        job.Id,
			"validator":     validatorAddr,
			"requested_by":  job.RequestedBy,
			"purpose":       job.Purpose,
			"input_data_uri": job.InputDataUri,
		},
	}

	// If the job has a previously computed output, supply it as the expected
	// output so the orchestrator can compare.
	if len(job.OutputHash) > 0 {
		req.ExpectedOutputHash = job.OutputHash
	}

	// sdk.Context implements context.Context, so it can be passed directly.
	resp, err := ob.orchestrator.Verify(ctx, req)
	if err != nil {
		return pouwtypes.VerificationResult{
			ValidatorAddress: validatorAddr,
			Success:          false,
			ErrorMessage:     fmt.Sprintf("orchestrator error: %v", err),
			Timestamp:        timestamppb.Now(),
		}, nil
	}

	// Map the orchestrator response back to the PoUW verification result.
	result := mapResponse(resp, validatorAddr)
	return result, nil
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

// mapProofType converts a pouwtypes.ProofType enum to a verifytypes.VerificationType.
func mapProofType(pt pouwtypes.ProofType) (verifytypes.VerificationType, error) {
	switch pt {
	case pouwtypes.ProofTypeTEE:
		return verifytypes.VerificationTypeTEE, nil
	case pouwtypes.ProofTypeZKML:
		return verifytypes.VerificationTypeZKML, nil
	case pouwtypes.ProofTypeHybrid:
		return verifytypes.VerificationTypeHybrid, nil
	default:
		return verifytypes.VerificationTypeUnspecified, fmt.Errorf("unsupported proof type: %s", pt)
	}
}

// mapResponse converts a verify.VerificationResponse into a pouwtypes.VerificationResult.
func mapResponse(resp *verify.VerificationResponse, validatorAddr string) pouwtypes.VerificationResult {
	result := pouwtypes.VerificationResult{
		ValidatorAddress: validatorAddr,
		Success:          resp.Success,
		OutputHash:       resp.OutputHash,
		ExecutionTimeMs:  resp.TotalTimeMs,
		Timestamp:        timestamppb.New(resp.Timestamp),
	}

	if !resp.Success {
		result.ErrorMessage = resp.Error
	}

	// Determine attestation type and platform from the response.
	switch resp.VerificationType {
	case verifytypes.VerificationTypeTEE:
		result.AttestationType = "tee"
		if resp.TEEResult != nil {
			result.TeePlatform = resp.TEEResult.Platform
			result.AttestationData = marshalAttestationData(resp.TEEResult, nil)
		}

	case verifytypes.VerificationTypeZKML:
		result.AttestationType = "zkml"
		if resp.ZKMLResult != nil {
			result.AttestationData = marshalAttestationData(nil, resp.ZKMLResult)
		}

	case verifytypes.VerificationTypeHybrid:
		result.AttestationType = "hybrid"
		if resp.TEEResult != nil {
			result.TeePlatform = resp.TEEResult.Platform
		}
		result.AttestationData = marshalAttestationData(resp.TEEResult, resp.ZKMLResult)

	default:
		result.AttestationType = "unknown"
	}

	return result
}

// ---------------------------------------------------------------------------
// Attestation data serialisation
// ---------------------------------------------------------------------------

// bridgeAttestationData is a JSON-serialisable envelope that carries the
// attestation and/or proof artefacts produced by the orchestrator. It is
// stored in pouwtypes.VerificationResult.AttestationData.
type bridgeAttestationData struct {
	TEE  *verify.TEEVerificationResult  `json:"tee,omitempty"`
	ZKML *verify.ZKMLVerificationResult `json:"zkml,omitempty"`
}

// marshalAttestationData serialises the TEE attestation and/or ZK proof
// results into a JSON byte slice suitable for the AttestationData field.
// If both arguments are nil the function returns nil.
func marshalAttestationData(teeResult *verify.TEEVerificationResult, zkmlResult *verify.ZKMLVerificationResult) []byte {
	if teeResult == nil && zkmlResult == nil {
		return nil
	}
	data := bridgeAttestationData{
		TEE:  teeResult,
		ZKML: zkmlResult,
	}
	b, err := json.Marshal(data)
	if err != nil {
		// Fallback: return the error description so that callers still get
		// visibility into what went wrong.
		return []byte(fmt.Sprintf(`{"marshal_error":%q,"time":%q}`, err.Error(), time.Now().UTC().Format(time.RFC3339)))
	}
	return b
}
