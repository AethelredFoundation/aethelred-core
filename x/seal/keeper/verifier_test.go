package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"cosmossdk.io/log"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/aethelred/aethelred/x/seal/types"
)

func newVerifierForTest(k *Keeper, cfg VerifierConfig) *SealVerifier {
	return NewSealVerifier(log.NewNopLogger(), k, cfg)
}

func storeSealForTest(t *testing.T, k *Keeper, seal *types.DigitalSeal) {
	t.Helper()
	if err := k.SetSeal(context.Background(), seal); err != nil {
		t.Fatalf("expected set seal success, got %v", err)
	}
}

func findCheck(result *SealVerificationResult, name string) (VerificationCheck, bool) {
	for _, check := range result.Checks {
		if check.Name == name {
			return check, true
		}
	}
	return VerificationCheck{}, false
}

func containsFailedCheck(result *SealVerificationResult, name string) bool {
	for _, failed := range result.FailedChecks {
		if failed == name {
			return true
		}
	}
	return false
}

func makeValidSealForVerifier(seed byte) *types.DigitalSeal {
	seal := newSealForTest(seed)
	seal.Status = types.SealStatusActive
	seal.ValidatorSet = []string{testAccAddress(seed + 10)}
	if len(seal.TeeAttestations) == 0 {
		seal.TeeAttestations = []*types.TEEAttestation{{ValidatorAddress: testAccAddress(seed + 1)}}
	}
	seal.TeeAttestations[0].Quote = []byte{0x01}
	seal.TeeAttestations[0].Measurement = []byte{0x02}
	return seal
}

func computeBundleHashForTest(bundle *types.VerificationBundle) []byte {
	h := sha256.New()
	h.Write([]byte(bundle.VerificationType))
	h.Write(bundle.AggregatedOutputHash)
	for _, tee := range bundle.TEEVerifications {
		h.Write(tee.OutputHash)
		h.Write(tee.AttestationDocument)
	}
	if bundle.ZKMLVerification != nil {
		h.Write(bundle.ZKMLVerification.Proof)
	}
	return h.Sum(nil)
}

func newEnhancedSealForVerifier(seed byte) *types.EnhancedDigitalSeal {
	outputHash := bytes.Repeat([]byte{0x03}, 32)
	consensus := &types.ConsensusInfo{
		Height:                  10,
		Round:                   1,
		TotalValidators:         1,
		ParticipatingValidators: 1,
		AgreementCount:          1,
		ConsensusThreshold:      67,
		VoteExtensionHashes:     [][]byte{bytes.Repeat([]byte{0x01}, 32)},
		Timestamp:               time.Now().UTC(),
	}
	bundle := &types.VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: outputHash,
		TEEVerifications: []types.TEEVerification{
			{
				ValidatorAddress:    testAccAddress(seed + 1),
				OutputHash:          outputHash,
				AttestationDocument: []byte{0x01},
			},
		},
	}
	bundle.BundleHash = computeBundleHashForTest(bundle)
	seal := types.NewEnhancedDigitalSeal(
		"job-test",
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		outputHash,
		consensus,
		bundle,
		testAccAddress(seed),
		"verification",
		"chain-test",
	)
	seal.Status = types.SealStatusActive
	seal.SealHash = seal.ComputeSealHash()
	return seal
}

func TestSealVerifierStatusPending(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(1)
	seal.Status = types.SealStatusPending
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if result.Valid {
		t.Fatalf("expected pending seal to be invalid")
	}
	if !containsFailedCheck(result, "status") {
		t.Fatalf("expected status check to fail")
	}
}

func TestSealVerifierExpirationMissingTimestamp(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(2)
	seal.RegulatoryInfo = &types.RegulatoryInfo{
		RetentionPeriod: durationpb.New(time.Hour),
	}
	seal.Timestamp = nil
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "expiration") {
		t.Fatalf("expected expiration check to fail")
	}
}

func TestSealVerifierConsensusMissingValidators(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(3)
	seal.ValidatorSet = nil
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "consensus") {
		t.Fatalf("expected consensus check to fail")
	}
}

func TestSealVerifierTeeAttestationFailures(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(4)
	seal.ValidatorSet = []string{testAccAddress(12)}
	seal.TeeAttestations = []*types.TEEAttestation{
		nil,
		{ValidatorAddress: testAccAddress(13)},
	}
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "tee_attestations") {
		t.Fatalf("expected tee_attestations check to fail")
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected warnings for invalid attestations")
	}
}

func TestSealVerifierZKMLProofInvalid(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(5)
	seal.ZkProof = &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       []byte{0x01},
		VerifyingKeyHash: bytes.Repeat([]byte{0x02}, 31),
	}
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "zkml_proof") {
		t.Fatalf("expected zkml_proof check to fail")
	}
}

func TestSealVerifierComplianceAuditRequiredNoEvidence(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	cfg := DefaultVerifierConfig()
	cfg.VerifyConsensus = false
	verifier := newVerifierForTest(&k, cfg)

	seal := makeValidSealForVerifier(6)
	seal.TeeAttestations = nil
	seal.ZkProof = nil
	seal.RegulatoryInfo = &types.RegulatoryInfo{
		AuditRequired: true,
	}
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "compliance") {
		t.Fatalf("expected compliance check to fail")
	}
}

func TestSealVerifierExpiredAllowed(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	cfg := DefaultVerifierConfig()
	cfg.AllowExpiredSeals = true
	verifier := newVerifierForTest(&k, cfg)

	seal := makeValidSealForVerifier(7)
	seal.Status = types.SealStatusExpired
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected expired seal to be valid when allowed")
	}
	if check, ok := findCheck(result, "status"); ok && !check.Passed {
		t.Fatalf("expected status check to pass when expired allowed")
	}
}

func TestSealVerifierHashIntegrityFailure(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := makeValidSealForVerifier(8)
	seal.ModelCommitment = []byte{0x01}
	storeSealForTest(t, &k, seal)

	result, err := verifier.VerifySeal(context.Background(), seal.Id)
	if err != nil {
		t.Fatalf("expected verify seal success, got %v", err)
	}
	if !containsFailedCheck(result, "hash_integrity") {
		t.Fatalf("expected hash_integrity check to fail")
	}
}

func TestSealVerifierEnhancedBundleHashMismatch(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := newEnhancedSealForVerifier(9)
	seal.VerificationBundle.BundleHash = bytes.Repeat([]byte{0xFF}, 32)
	seal.SealHash = seal.ComputeSealHash()

	result, err := verifier.VerifyEnhancedSeal(context.Background(), seal)
	if err != nil {
		t.Fatalf("expected verify enhanced seal success, got %v", err)
	}
	if !containsFailedCheck(result, "verification_bundle") {
		t.Fatalf("expected verification_bundle check to fail")
	}
}

func TestSealVerifierEnhancedOutputConsistencyMismatch(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := newEnhancedSealForVerifier(10)
	seal.VerificationBundle.TEEVerifications[0].OutputHash = bytes.Repeat([]byte{0xFF}, 32)
	seal.VerificationBundle.BundleHash = computeBundleHashForTest(seal.VerificationBundle)
	seal.SealHash = seal.ComputeSealHash()

	result, err := verifier.VerifyEnhancedSeal(context.Background(), seal)
	if err != nil {
		t.Fatalf("expected verify enhanced seal success, got %v", err)
	}
	if !containsFailedCheck(result, "output_consistency") {
		t.Fatalf("expected output_consistency check to fail")
	}
}

func TestSealVerifierEnhancedAuditTrailBreak(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := newEnhancedSealForVerifier(11)
	seal.AuditTrail = append(seal.AuditTrail, types.AuditEntry{
		Timestamp:         time.Now().UTC(),
		EventType:         types.AuditEventAccessed,
		Actor:             "auditor",
		PreviousStateHash: []byte{0x01, 0x02},
	})

	result, err := verifier.VerifyEnhancedSeal(context.Background(), seal)
	if err != nil {
		t.Fatalf("expected verify enhanced seal success, got %v", err)
	}
	if !containsFailedCheck(result, "audit_trail") {
		t.Fatalf("expected audit_trail check to fail")
	}
}

func TestSealVerifierEnhancedSealHashMismatch(t *testing.T) {
	k := NewKeeper(nil, nil, "authority")
	verifier := newVerifierForTest(&k, DefaultVerifierConfig())

	seal := newEnhancedSealForVerifier(12)
	seal.SealHash = bytes.Repeat([]byte{0xAA}, len(seal.SealHash))

	result, err := verifier.VerifyEnhancedSeal(context.Background(), seal)
	if err != nil {
		t.Fatalf("expected verify enhanced seal success, got %v", err)
	}
	if !containsFailedCheck(result, "seal_hash") {
		t.Fatalf("expected seal_hash check to fail")
	}
}
