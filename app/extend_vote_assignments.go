package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// assignedJobsForValidator returns the scheduler assignments for the validator
// identified by consensus address. In dev/test (AllowSimulated=true), it can
// fall back to pending jobs when scheduler or validator mapping is unavailable.
func (app *AethelredApp) assignedJobsForValidator(ctx sdk.Context, consAddr []byte) ([]*pouwtypes.ComputeJob, string, error) {
	if app.isPoUWAllocationHalted(ctx) {
		return nil, "", nil
	}

	validatorAccountAddr, addrErr := app.validatorAccountAddress(ctx, consAddr)
	if addrErr != nil {
		if !app.allowSimulated(ctx) {
			return nil, "", addrErr
		}
		// Dev fallback: use pending jobs even if we can't map validator address.
		return app.PouwKeeper.GetPendingJobs(ctx), "unknown", nil
	}

	if app.consensusHandler == nil || app.consensusHandler.Scheduler() == nil {
		if !app.allowSimulated(ctx) {
			return nil, validatorAccountAddr, fmt.Errorf("scheduler not initialized")
		}
		return app.PouwKeeper.GetPendingJobs(ctx), validatorAccountAddr, nil
	}

	jobs := app.consensusHandler.Scheduler().GetJobsForValidator(ctx, validatorAccountAddr)
	return jobs, validatorAccountAddr, nil
}

func (app *AethelredApp) isPoUWAllocationHalted(ctx sdk.Context) bool {
	defer func() {
		_ = recover()
	}()
	return app.SovereignCrisisKeeper.IsPoUWHalted(ctx)
}

// validatorAccountAddress derives the bech32 account address for a validator
// from its consensus address.
func (app *AethelredApp) validatorAccountAddress(ctx sdk.Context, consAddr []byte) (string, error) {
	if app.StakingKeeper == nil {
		return "", fmt.Errorf("staking keeper not configured")
	}
	if len(consAddr) == 0 {
		return "", fmt.Errorf("validator consensus address is empty")
	}

	validator, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(consAddr))
	if err != nil {
		return "", fmt.Errorf("validator not found for consensus address: %w", err)
	}
	operatorAddr := validator.GetOperator()
	if len(operatorAddr) == 0 {
		return "", fmt.Errorf("validator operator address missing")
	}

	return sdk.AccAddress(operatorAddr).String(), nil
}

// executeAssignedVerification runs the verification pipeline for a scheduled job
// and maps the result into a ComputeVerification for vote extension inclusion.
func (app *AethelredApp) executeAssignedVerification(ctx sdk.Context, job *pouwtypes.ComputeJob, validatorAddr string) ComputeVerification {
	startTime := time.Now()

	verification := ComputeVerification{
		JobID:           job.Id,
		ModelHash:       job.ModelHash,
		InputHash:       job.InputHash,
		AttestationType: AttestationTypeNone,
		Success:         false,
	}

	nonce, err := generateNonce()
	if err != nil {
		verification.ErrorCode = ErrorCodeInternalError
		verification.ErrorMessage = "failed to generate nonce"
		verification.Nonce = make([]byte, 32)
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}
	verification.Nonce = nonce

	model, err := app.PouwKeeper.GetRegisteredModel(ctx, job.ModelHash)
	if err != nil {
		verification.ErrorCode = ErrorCodeModelNotFound
		verification.ErrorMessage = err.Error()
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	if app.orchestrator == nil {
		verification.ErrorCode = ErrorCodeInternalError
		verification.ErrorMessage = "verification orchestrator not configured"
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	vType, err := mapProofType(job.ProofType)
	if err != nil {
		verification.ErrorCode = ErrorCodeInvalidInput
		verification.ErrorMessage = err.Error()
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	req := &verify.VerificationRequest{
		RequestID:        fmt.Sprintf("%s-%s", job.Id, validatorAddr),
		ModelHash:        job.ModelHash,
		InputHash:        job.InputHash,
		VerificationType: vType,
		CircuitHash:      model.CircuitHash,
		VerifyingKeyHash: model.VerifyingKeyHash,
		Priority:         int(job.Priority),
		Metadata: map[string]string{
			"job_id":         job.Id,
			"validator":      validatorAddr,
			"requested_by":   job.RequestedBy,
			"purpose":        job.Purpose,
			"input_data_uri": job.InputDataUri,
		},
	}

	if len(job.OutputHash) > 0 {
		req.ExpectedOutputHash = job.OutputHash
	}

	resp, err := app.orchestrator.Verify(ctx, req)
	if err != nil {
		verification.ErrorCode = ErrorCodeInternalError
		verification.ErrorMessage = fmt.Sprintf("orchestrator error: %v", err)
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	verification.ExecutionTimeMs = resp.TotalTimeMs
	if verification.ExecutionTimeMs <= 0 {
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	}

	verification.OutputHash = resp.OutputHash
	verification.Success = resp.Success

	if !resp.Success {
		verification.ErrorMessage = resp.Error
		verification.AttestationType = AttestationTypeNone
		switch vType {
		case verifytypes.VerificationTypeTEE:
			verification.ErrorCode = ErrorCodeTEEFailure
		case verifytypes.VerificationTypeZKML:
			verification.ErrorCode = ErrorCodeZKMLFailure
		case verifytypes.VerificationTypeHybrid:
			verification.ErrorCode = ErrorCodeOutputMismatch
		default:
			verification.ErrorCode = ErrorCodeInternalError
		}
		return verification
	}

	verification.TEEAttestation = mapTEEAttestation(resp.TEEResult)
	verification.ZKProof = mapZKProof(resp.ZKMLResult, model)

	switch job.ProofType {
	case pouwtypes.ProofTypeTEE:
		if verification.TEEAttestation == nil {
			verification.Success = false
			verification.ErrorCode = ErrorCodeTEEFailure
			verification.ErrorMessage = "missing TEE attestation data"
			verification.AttestationType = AttestationTypeNone
			return verification
		}
		verification.AttestationType = AttestationTypeTEE
	case pouwtypes.ProofTypeZKML:
		if verification.ZKProof == nil {
			verification.Success = false
			verification.ErrorCode = ErrorCodeZKMLFailure
			verification.ErrorMessage = "missing zkML proof data"
			verification.AttestationType = AttestationTypeNone
			return verification
		}
		verification.AttestationType = AttestationTypeZKML
	case pouwtypes.ProofTypeHybrid:
		if verification.TEEAttestation == nil || verification.ZKProof == nil {
			verification.Success = false
			verification.ErrorCode = ErrorCodeOutputMismatch
			verification.ErrorMessage = "hybrid verification missing TEE and/or zkML data"
			verification.AttestationType = AttestationTypeNone
			return verification
		}
		verification.AttestationType = AttestationTypeHybrid
	default:
		verification.Success = false
		verification.ErrorCode = ErrorCodeInvalidInput
		verification.ErrorMessage = fmt.Sprintf("unsupported proof type: %s", job.ProofType)
		verification.AttestationType = AttestationTypeNone
	}

	return verification
}

func mapTEEAttestation(result *verify.TEEVerificationResult) *TEEAttestationData {
	if result == nil || result.AttestationDoc == nil {
		return nil
	}

	doc := result.AttestationDoc
	measurement := nitroMeasurement(doc)
	quote := marshalNitroQuote(doc)

	data := &TEEAttestationData{
		Platform:    result.Platform,
		EnclaveID:   result.EnclaveID,
		Measurement: measurement,
		Quote:       quote,
		UserData:    doc.UserData,
		Timestamp:   doc.Timestamp,
		Nonce:       doc.Nonce,
	}

	if len(doc.Certificate) > 0 || len(doc.CABundle) > 0 {
		var chain [][]byte
		if len(doc.Certificate) > 0 {
			chain = append(chain, doc.Certificate)
		}
		if len(doc.CABundle) > 0 {
			chain = append(chain, doc.CABundle)
		}
		data.CertificateChain = chain
	}

	if data.EnclaveID == "" {
		data.EnclaveID = doc.ModuleID
	}

	return data
}

func mapZKProof(result *verify.ZKMLVerificationResult, model *pouwtypes.RegisteredModel) *ZKProofData {
	if result == nil {
		return nil
	}

	publicInputs := marshalZKPublicInputs(result.PublicInputs)

	return &ZKProofData{
		ProofSystem:      result.ProofSystem,
		Proof:            result.Proof,
		PublicInputs:     publicInputs,
		VerifyingKeyHash: model.VerifyingKeyHash,
		CircuitHash:      model.CircuitHash,
		ProofSize:        result.ProofSizeBytes,
	}
}

func nitroMeasurement(doc *tee.NitroAttestationDocument) []byte {
	if doc == nil || doc.PCRs == nil {
		return nil
	}
	if pcr0 := doc.PCRs[0]; len(pcr0) > 0 {
		return pcr0
	}
	if len(doc.PCRs) == 0 {
		return nil
	}
	keys := make([]int, 0, len(doc.PCRs))
	for k := range doc.PCRs {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var combined []byte
	for _, k := range keys {
		combined = append(combined, doc.PCRs[k]...)
	}
	return combined
}

type nitroQuotePCR struct {
	Index int    `json:"index"`
	Value []byte `json:"value"`
}

type nitroQuote struct {
	ModuleID    string          `json:"module_id"`
	Timestamp   int64           `json:"timestamp_unix"`
	Digest      string          `json:"digest"`
	PCRs        []nitroQuotePCR `json:"pcrs"`
	Certificate []byte          `json:"certificate,omitempty"`
	CABundle    []byte          `json:"cabundle,omitempty"`
	PublicKey   []byte          `json:"public_key,omitempty"`
	UserData    []byte          `json:"user_data,omitempty"`
	Nonce       []byte          `json:"nonce,omitempty"`
}

func marshalNitroQuote(doc *tee.NitroAttestationDocument) []byte {
	if doc == nil {
		return nil
	}

	var pcrs []nitroQuotePCR
	for idx, val := range doc.PCRs {
		pcrs = append(pcrs, nitroQuotePCR{
			Index: idx,
			Value: val,
		})
	}
	sort.Slice(pcrs, func(i, j int) bool {
		return pcrs[i].Index < pcrs[j].Index
	})

	payload := nitroQuote{
		ModuleID:    doc.ModuleID,
		Timestamp:   doc.Timestamp.Unix(),
		Digest:      doc.Digest,
		PCRs:        pcrs,
		Certificate: doc.Certificate,
		CABundle:    doc.CABundle,
		PublicKey:   doc.PublicKey,
		UserData:    doc.UserData,
		Nonce:       doc.Nonce,
	}

	quote, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return quote
}

func marshalZKPublicInputs(inputs *ezkl.PublicInputs) []byte {
	if inputs == nil {
		return nil
	}

	buf := bytes.NewBuffer(nil)
	writeLenPrefixed(buf, inputs.ModelCommitment)
	writeLenPrefixed(buf, inputs.InputCommitment)
	writeLenPrefixed(buf, inputs.OutputCommitment)

	instances := inputs.Instances
	_ = binary.Write(buf, binary.BigEndian, uint32(len(instances)))
	for _, inst := range instances {
		writeLenPrefixed(buf, inst)
	}

	return buf.Bytes()
}

func writeLenPrefixed(buf *bytes.Buffer, data []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(data)))
	if len(data) > 0 {
		_, _ = buf.Write(data)
	}
}
