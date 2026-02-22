package app

import (
	cryptoRand "crypto/rand"
	"fmt"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// NOTE: All vote extension types (VoteExtension, ComputeVerification,
// TEEAttestationData, ZKProofData, AggregatedVerification, etc.) are
// defined in vote_extension.go. This file only contains ABCI++ handlers.

// ExtendVoteHandler returns the ABCI++ ExtendVote handler for Proof-of-Useful-Work.
// This is called during the consensus voting phase, allowing validators to
// include compute verification results in their votes.
//
// CRITICAL: This handler includes panic recovery to prevent a single validator
// panic from halting consensus. Any panic is logged and results in an empty
// vote extension rather than crashing the node.
func (app *AethelredApp) ExtendVoteHandler() sdk.ExtendVoteHandler {
	return func(ctx sdk.Context, req *abci.RequestExtendVote) (resp *abci.ResponseExtendVote, err error) {
		// CRITICAL: Panic recovery for consensus safety
		// A panic in ExtendVote should not crash the validator node
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in ExtendVoteHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// Return empty extension on panic - consensus continues
				resp = &abci.ResponseExtendVote{VoteExtension: nil}
				err = nil // Don't propagate error to consensus
			}
		}()

		app.Logger().Info("ExtendVote called for Proof-of-Useful-Work",
			"height", req.Height,
			"round", 0,
		)

		validatorAddr := app.validatorConsAddr
		if len(validatorAddr) == 0 {
			var addrErr error
			validatorAddr, addrErr = app.validatorConsensusAddress()
			if addrErr != nil {
				app.Logger().Error("Failed to derive validator consensus address for vote extension",
					"height", req.Height,
					"error", addrErr,
				)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
		}

		// Resolve assigned jobs for this validator via the scheduler.
		assignedJobs, validatorAccountAddr, jobsErr := app.assignedJobsForValidator(ctx, validatorAddr)
		if jobsErr != nil {
			app.Logger().Error("Failed to resolve assigned jobs for validator",
				"height", req.Height,
				"error", jobsErr,
			)
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}
		if len(assignedJobs) == 0 {
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}

		// Create vote extension using deterministic block time.
		blockTime := req.Time
		if blockTime.IsZero() {
			blockTime = ctx.BlockTime()
		}
		voteExt := NewVoteExtensionAtBlockTime(req.Height, validatorAddr, blockTime)

		// Perform verifications for each assigned job (respects proof type).
		for _, job := range assignedJobs {
			if len(voteExt.Verifications) >= MaxVerificationsPerExtension {
				app.Logger().Warn("Max verifications per extension reached; truncating",
					"max", MaxVerificationsPerExtension,
				)
				break
			}
			verification := app.executeAssignedVerification(ctx, job, validatorAccountAddr)
			voteExt.AddVerification(verification)
		}

		validationMode := app.voteExtensionValidationMode(ctx)

		// Sign the vote extension with validator's ed25519 private key
		// This is CRITICAL for production security - unsigned extensions are rejected
		if app.validatorPrivKey != nil {
			if err := SignVoteExtension(voteExt, app.validatorPrivKey); err != nil {
				app.Logger().Error("Failed to sign vote extension", "error", err)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
		} else {
			if validationMode == ValidationModeStrict {
				app.Logger().Error("SECURITY: validator private key not configured in strict mode; refusing unsigned vote extension",
					"height", req.Height,
				)
				return &abci.ResponseExtendVote{VoteExtension: nil}, nil
			}
			// Dev/test mode only.
			app.Logger().Warn("SECURITY WARNING: Vote extension created without signature - " +
				"validator private key not configured. This is only acceptable for testing.")
		}

		extBytes, err := voteExt.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vote extension: %w", err)
		}

		// Enforce size limit (trim from end if needed).
		originalCount := len(voteExt.Verifications)
		for len(extBytes) > MaxVoteExtensionSizeBytes && len(voteExt.Verifications) > 0 {
			voteExt.Verifications = voteExt.Verifications[:len(voteExt.Verifications)-1]
			if app.validatorPrivKey != nil {
				if err := SignVoteExtension(voteExt, app.validatorPrivKey); err != nil {
					app.Logger().Error("Failed to re-sign vote extension after trimming", "error", err)
					return &abci.ResponseExtendVote{VoteExtension: nil}, nil
				}
			}
			extBytes, err = voteExt.Marshal()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal vote extension: %w", err)
			}
		}

		if originalCount != len(voteExt.Verifications) {
			app.Logger().Warn("Vote extension trimmed to satisfy size limit",
				"original", originalCount,
				"final", len(voteExt.Verifications),
				"size_bytes", len(extBytes),
			)
		}

		if len(extBytes) > MaxVoteExtensionSizeBytes {
			app.Logger().Error("Vote extension exceeds size limit after trimming",
				"size_bytes", len(extBytes),
			)
			return &abci.ResponseExtendVote{VoteExtension: nil}, nil
		}

		app.Logger().Info("Vote extension created",
			"num_verifications", len(voteExt.Verifications),
			"extension_size", len(extBytes),
		)

		return &abci.ResponseExtendVote{
			VoteExtension: extBytes,
		}, nil
	}
}

// VerifyVoteExtensionHandler returns the ABCI++ VerifyVoteExtension handler.
// This validates that vote extensions from other validators are well-formed
// and contain valid verification data.
//
// In production mode (AllowSimulated=false on either x/pouw or x/verify params):
//   - Unsigned extensions are REJECTED
//   - Simulated TEE platforms are REJECTED
//   - Extension hash MUST be present
//
// In dev mode (AllowSimulated=true): permissive validation is used.
//
// CRITICAL: This handler includes panic recovery. A panic during verification
// results in REJECT to maintain safety without crashing the node.
func (app *AethelredApp) VerifyVoteExtensionHandler() sdk.VerifyVoteExtensionHandler {
	return func(ctx sdk.Context, req *abci.RequestVerifyVoteExtension) (resp *abci.ResponseVerifyVoteExtension, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in VerifyVoteExtensionHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// REJECT on panic - safer than accepting potentially malformed data
				if metrics := app.PouwKeeper.Metrics(); metrics != nil {
					metrics.VoteExtensionsRejected.Inc()
				}
				resp = &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
				err = nil
			}
		}()

		// Empty extensions are always valid (no jobs to verify)
		if len(req.VoteExtension) == 0 {
			if app.voteExtensionCache != nil && len(req.ValidatorAddress) > 0 {
				app.voteExtensionCache.Store(req.Height, req.ValidatorAddress, []byte{})
			}
			return &abci.ResponseVerifyVoteExtension{
				Status: abci.ResponseVerifyVoteExtension_ACCEPT,
			}, nil
		}

		if len(req.VoteExtension) > MaxVoteExtensionSizeBytes {
			app.Logger().Error("Vote extension too large",
				"size_bytes", len(req.VoteExtension),
			)
			return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}, nil
		}

		metrics := app.PouwKeeper.Metrics()
		if metrics != nil {
			metrics.VoteExtensionsProcessed.Inc()
		}
		reject := func() *abci.ResponseVerifyVoteExtension {
			if metrics != nil {
				metrics.VoteExtensionsRejected.Inc()
			}
			return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
		}

		// Determine validation mode based on module params.
		// If EITHER x/pouw or x/verify has AllowSimulated=false, use strict mode.
		validationMode := app.voteExtensionValidationMode(ctx)

		// Parse the vote extension
		voteExt, err := UnmarshalVoteExtension(req.VoteExtension)
		if err != nil {
			app.Logger().Error("Failed to unmarshal vote extension", "error", err)
			return reject(), nil
		}

		if len(voteExt.Verifications) > MaxVerificationsPerExtension {
			app.Logger().Error("Vote extension exceeds max verifications",
				"count", len(voteExt.Verifications),
			)
			return reject(), nil
		}

		// Validate the vote extension using mode-appropriate validation.
		// Strict mode rejects unsigned extensions, simulated TEE, missing hashes.
		now, ok := app.lastBlockTime(ctx)
		if !ok && validationMode == ValidationModeStrict {
			app.Logger().Error("Missing last block time for deterministic vote extension validation",
				"height", req.Height,
			)
			return reject(), nil
		}
		maxPastSkew, maxFutureSkew := app.voteExtensionTimeBounds(ctx)
		if validationMode == ValidationModeStrict {
			if err := voteExt.validateAtWithWindow(validationMode, now, maxPastSkew, maxFutureSkew); err != nil {
				app.Logger().Error("Vote extension strict validation failed",
					"error", err,
					"mode", "production",
				)
				return reject(), nil
			}
		} else {
			if err := voteExt.validateAtWithWindow(validationMode, now, maxPastSkew, maxFutureSkew); err != nil {
				app.Logger().Error("Vote extension validation failed", "error", err)
				return reject(), nil
			}
		}

		// Strict boundary check: validate TEE quote schema at ABCI layer before aggregation.
		if validationMode == ValidationModeStrict {
			if err := app.validateVoteExtensionTEESchemas(voteExt); err != nil {
				app.Logger().Error("Vote extension TEE schema validation failed", "error", err)
				return reject(), nil
			}
		}

		// Verify signature on vote extension using validator's ed25519 public key.
		// In strict mode, the signature is guaranteed present by ValidateStrict().
		// In permissive mode, we still verify if a signature IS provided.
		if len(voteExt.Signature) > 0 {
			// Look up validator public key from staking keeper via consensus address
			consAddr := sdk.ConsAddress(voteExt.ValidatorAddress)
			validator, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
			if err != nil {
				app.Logger().Error("Unknown validator in vote extension",
					"cons_addr", consAddr.String(),
				)
				return reject(), nil
			}

			// Get the validator's consensus public key
			pubKey, err := validator.ConsPubKey()
			if err != nil {
				app.Logger().Error("Failed to get validator public key", "error", err)
				return reject(), nil
			}

			// Verify ed25519 signature
			if !VerifyVoteExtensionSignature(voteExt, pubKey.Bytes()) {
				app.Logger().Error("Vote extension signature verification failed",
					"validator", consAddr.String(),
				)
				return reject(), nil
			}
		} else if validationMode == ValidationModeStrict {
			app.Logger().Error("SECURITY: unsigned vote extension rejected in strict mode")
			return reject(), nil
		}

		if app.voteExtensionCache != nil {
			app.voteExtensionCache.Store(req.Height, req.ValidatorAddress, req.VoteExtension)
		}

		return &abci.ResponseVerifyVoteExtension{
			Status: abci.ResponseVerifyVoteExtension_ACCEPT,
		}, nil
	}
}

// PrepareProposalHandler returns the ABCI++ PrepareProposal handler.
// This aggregates vote extensions from validators and includes verified
// computation results in the block proposal.
//
// CRITICAL: This handler includes panic recovery. A panic during proposal
// preparation results in returning the original transactions without any
// injected seal transactions.
func (app *AethelredApp) PrepareProposalHandler() sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestPrepareProposal) (resp *abci.ResponsePrepareProposal, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in PrepareProposalHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// Return original transactions on panic - block can still be proposed
				resp = &abci.ResponsePrepareProposal{Txs: req.Txs}
				err = nil
			}
		}()

		app.Logger().Info("PrepareProposal called",
			"height", req.Height,
			"num_local_votes", len(req.LocalLastCommit.Votes),
		)

		// Start with the original transactions
		proposalTxs := req.Txs

		if app.consensusHandler != nil {
			// Canonical consensus pipeline (keeper-based) to avoid divergence.
			results := app.consensusHandler.AggregateVoteExtensions(ctx, req.LocalLastCommit.Votes)
			sealTxs := app.consensusHandler.CreateSealTransactions(ctx, results)
			if len(sealTxs) > 0 {
				proposalTxs = append(sealTxs, proposalTxs...)
			}
		} else {
			// Legacy fallback (dev/test only).
			var extensions []VoteExtensionWithPower
			for _, vote := range req.LocalLastCommit.Votes {
				if len(vote.VoteExtension) == 0 {
					continue
				}
				ext, err := UnmarshalVoteExtension(vote.VoteExtension)
				if err != nil {
					app.Logger().Warn("Failed to unmarshal vote extension in PrepareProposal", "error", err)
					continue
				}
				extensions = append(extensions, VoteExtensionWithPower{
					Extension: ext,
					Power:     vote.Validator.Power,
				})
			}

			consensusThreshold := app.getConsensusThreshold(ctx)
			allowSimulated := app.allowSimulated(ctx)
			aggregatedResults := AggregateVoteExtensions(ctx, extensions, consensusThreshold, allowSimulated)
			for _, agg := range aggregatedResults {
				if !agg.HasConsensus {
					continue
				}
				injectedTx := NewInjectedVoteExtensionTx(agg, req.Height)
				txBytes, err := injectedTx.Marshal()
				if err != nil {
					app.Logger().Error("Failed to marshal injected tx", "error", err)
					continue
				}
				proposalTxs = append([][]byte{txBytes}, proposalTxs...)
			}
		}

		return &abci.ResponsePrepareProposal{
			Txs: proposalTxs,
		}, nil
	}
}

// ProcessProposalHandler returns the ABCI++ ProcessProposal handler.
// This validates that the proposed block contains valid verification results
// with sufficient validator agreement.
//
// CRITICAL: This handler includes panic recovery. A panic during proposal
// processing results in REJECT to prevent potentially invalid blocks from
// being accepted.
func (app *AethelredApp) ProcessProposalHandler() sdk.ProcessProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (resp *abci.ResponseProcessProposal, err error) {
		// CRITICAL: Panic recovery for consensus safety
		defer func() {
			if r := recover(); r != nil {
				app.Logger().Error("CRITICAL: Panic recovered in ProcessProposalHandler",
					"height", req.Height,
					"panic", fmt.Sprintf("%v", r),
				)
				// REJECT on panic - safer than accepting potentially invalid proposal
				resp = &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}
				err = nil
			}
		}()

		// Record validator participation/misses from the last commit.
		app.recordLivenessFromLastCommit(ctx, req.ProposedLastCommit)

		app.Logger().Info("ProcessProposal called",
			"height", req.Height,
			"num_txs", len(req.Txs),
		)

		productionMode := !app.allowSimulated(ctx)
		if productionMode {
			if app.consensusHandler == nil {
				app.Logger().Error("SECURITY: consensus handler not configured in production mode")
				return &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}, nil
			}
			if app.voteExtensionCache == nil {
				app.Logger().Error("SECURITY: vote extension cache not configured in production mode")
				return &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}, nil
			}
		}
		consensusThreshold := app.getConsensusThreshold(ctx)
		audit := AuditProposalConsensusEvidence(req.Txs, req.ProposedLastCommit, consensusThreshold)
		if !audit.Passed() {
			app.Logger().Error("Injected consensus evidence audit failed", "error", audit.Error())
			return &abci.ResponseProcessProposal{
				Status: abci.ResponseProcessProposal_REJECT,
			}, nil
		}

		// Validate all transactions in the proposal
		for _, txBytes := range req.Txs {
			// Check if this is an injected vote extension transaction
			if IsInjectedVoteExtensionTx(txBytes) {
				// Prefer keeper-based validation to avoid pipeline divergence.
				if app.consensusHandler != nil {
					if err := app.consensusHandler.ValidateSealTransaction(ctx, txBytes); err != nil {
						app.Logger().Error("Injected tx validation failed", "error", err)
						return &abci.ResponseProcessProposal{
							Status: abci.ResponseProcessProposal_REJECT,
						}, nil
					}
					continue
				}

				tx, err := UnmarshalInjectedVoteExtensionTx(txBytes)
				if err != nil {
					app.Logger().Error("Invalid injected tx in proposal", "error", err)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}

				if err := app.validateInjectedTx(ctx, tx); err != nil {
					app.Logger().Error("Injected tx validation failed", "error", err)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}
			}
		}

		// Enforce computation finality in production: ensure consensus results
		// are reflected in the proposal's injected transactions.
		if productionMode {
			lastHeight := req.Height - 1
			extendedVotes, found := app.voteExtensionCache.BuildExtendedVotes(lastHeight, req.ProposedLastCommit.Votes)
			injectedTxCount := 0
			for _, txBytes := range req.Txs {
				if IsInjectedVoteExtensionTx(txBytes) {
					injectedTxCount++
				}
			}
			if found == 0 && len(req.ProposedLastCommit.Votes) > 0 && injectedTxCount > 0 {
				app.Logger().Error("Missing vote extensions for computation finality check",
					"height", lastHeight,
				)
				return &abci.ResponseProcessProposal{
					Status: abci.ResponseProcessProposal_REJECT,
				}, nil
			}

			if injectedTxCount > 0 {
				evidencePower, totalPower := voteExtensionEvidencePower(extendedVotes)
				requiredEvidencePower := requiredConsensusPower(totalPower, consensusThreshold)
				if totalPower <= 0 || evidencePower < requiredEvidencePower {
					app.Logger().Error("Insufficient vote-extension evidence power for injected consensus txs",
						"evidence_power", evidencePower,
						"total_power", totalPower,
						"required_power", requiredEvidencePower,
						"threshold_pct", consensusThreshold,
					)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}
			}

			if found > 0 {
				results := app.consensusHandler.AggregateVoteExtensions(ctx, extendedVotes)
				if err := app.validateComputationFinality(results, req.Txs, consensusThreshold); err != nil {
					app.Logger().Error("Computation finality check failed", "error", err)
					return &abci.ResponseProcessProposal{
						Status: abci.ResponseProcessProposal_REJECT,
					}, nil
				}
			}
		}

		return &abci.ResponseProcessProposal{
			Status: abci.ResponseProcessProposal_ACCEPT,
		}, nil
	}
}

func voteExtensionEvidencePower(votes []abci.ExtendedVoteInfo) (evidencePower int64, totalPower int64) {
	for _, v := range votes {
		totalPower += v.Validator.Power
		if len(v.VoteExtension) > 0 {
			evidencePower += v.Validator.Power
		}
	}
	return evidencePower, totalPower
}

// executeComputeVerification performs the actual verification of a compute job.
// In production, this executes the model in a TEE and/or generates a zkML proof.
func (app *AethelredApp) executeComputeVerification(ctx sdk.Context, job pouwtypes.ComputeJob) ComputeVerification {
	startTime := time.Now()

	verification := ComputeVerification{
		JobID:           job.Id,
		ModelHash:       job.ModelHash,
		InputHash:       job.InputHash,
		AttestationType: AttestationTypeTEE, // Default to TEE
		Success:         false,
	}

	// Generate nonce for replay protection
	nonce, err := generateNonce()
	if err != nil {
		verification.ErrorCode = ErrorCodeInternalError
		verification.ErrorMessage = "failed to generate nonce"
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}
	verification.Nonce = nonce

	// Check if the model is registered
	if !app.PouwKeeper.IsModelRegistered(ctx, job.ModelHash) {
		verification.ErrorCode = ErrorCodeModelNotFound
		verification.ErrorMessage = "model not registered"
		verification.AttestationType = AttestationTypeNone
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	// Execute in TEE client
	teeResult, err := app.executeTEE(ctx, job, nonce)
	if err != nil {
		verification.ErrorCode = ErrorCodeTEEFailure
		verification.ErrorMessage = err.Error()
		verification.AttestationType = AttestationTypeNone
		verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verification
	}

	verification.OutputHash = teeResult.OutputHash
	verification.TEEAttestation = teeResult.Attestation
	verification.Success = true
	verification.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	// Include zkML proof if available
	if teeResult.ZKProof != nil {
		verification.ZKProof = teeResult.ZKProof
		verification.AttestationType = AttestationTypeHybrid
	}

	app.Logger().Info("Compute verification completed",
		"job_id", job.Id,
		"success", verification.Success,
		"execution_time_ms", verification.ExecutionTimeMs,
		"attestation_type", verification.AttestationType,
	)

	return verification
}

// executeTEE executes a compute job in the TEE client.
// This uses the TEEClient interface, which can be either a real Nitro Enclave
// or a simulated client depending on configuration.
func (app *AethelredApp) executeTEE(ctx sdk.Context, job pouwtypes.ComputeJob, nonce []byte) (*TEEExecutionResult, error) {
	if app.teeClient == nil {
		return nil, fmt.Errorf("TEE client not configured - set aethelred.tee.mode and endpoint")
	}

	request := &TEEExecutionRequest{
		JobID:     job.Id,
		ModelHash: job.ModelHash,
		InputHash: job.InputHash,
		Nonce:     nonce,
		Timeout:   30 * time.Second,
	}

	result, err := app.teeClient.Execute(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("TEE execution failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("TEE execution failed: %s", result.ErrorMessage)
	}

	return result, nil
}

// validateInjectedTx validates an injected vote extension transaction
func (app *AethelredApp) validateInjectedTx(ctx sdk.Context, tx *InjectedVoteExtensionTx) error {
	if err := validateInjectedConsensusTxFormat(tx); err != nil {
		return err
	}

	// Validate job exists
	job, err := app.PouwKeeper.GetJob(ctx, tx.JobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", tx.JobID)
	}

	// Validate that consensus threshold was met
	// Get threshold from on-chain params (BFT-safe, minimum 67%)
	consensusThreshold := app.getConsensusThreshold(ctx)
	if err := validateConsensusEvidenceThreshold(
		tx.ValidatorCount,
		tx.TotalVotes,
		tx.AgreementPower,
		tx.TotalPower,
		consensusThreshold,
		app.allowSimulated(ctx),
	); err != nil {
		return err
	}

	_ = job // used for validation above
	return nil
}

// getConsensusThreshold returns the consensus threshold from on-chain params.
// This ensures the threshold is always read from governance params rather than
// a hardcoded value, while maintaining BFT safety with a minimum of 67%.
func (app *AethelredApp) getConsensusThreshold(ctx sdk.Context) int {
	params, err := app.PouwKeeper.GetParams(ctx)
	if err == nil && params != nil && params.ConsensusThreshold >= 67 {
		return int(params.ConsensusThreshold)
	}
	// Default to BFT-safe 67% if params unavailable or invalid
	return 67
}

func (app *AethelredApp) allowSimulated(ctx sdk.Context) bool {
	params, err := app.PouwKeeper.GetParams(ctx)
	if err != nil || params == nil {
		return false
	}
	return params.AllowSimulated
}

func (app *AethelredApp) verifyAllowSimulated(ctx sdk.Context) bool {
	defer func() {
		if recover() != nil {
			// Fail closed.
		}
	}()

	params, err := app.VerifyKeeper.GetParams(ctx)
	if err != nil || params == nil {
		return false
	}
	return params.AllowSimulated
}

func (app *AethelredApp) voteExtensionValidationMode(ctx sdk.Context) ValidationMode {
	if !app.allowSimulated(ctx) || !app.verifyAllowSimulated(ctx) {
		return ValidationModeStrict
	}
	return ValidationModePermissive
}

func (app *AethelredApp) validateVoteExtensionTEESchemas(ve *VoteExtension) error {
	if ve == nil {
		return fmt.Errorf("vote extension is nil")
	}
	for i := range ve.Verifications {
		ver := ve.Verifications[i]
		if ver.AttestationType != AttestationTypeTEE && ver.AttestationType != AttestationTypeHybrid {
			continue
		}
		if ver.TEEAttestation == nil {
			return fmt.Errorf("verification %d missing TEE attestation", i)
		}
		if err := validateTEEQuoteSchema(ver.TEEAttestation); err != nil {
			return fmt.Errorf("verification %d: %w", i, err)
		}
	}
	return nil
}

// generateNonce creates a cryptographic nonce for replay protection
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := cryptoRand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}
