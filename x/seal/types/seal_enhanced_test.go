package types

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnhancedSealValidate(t *testing.T) {
	base := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(3),
		"credit_scoring",
	)

	enh := &EnhancedDigitalSeal{DigitalSeal: *base}
	if err := enh.ValidateEnhanced(); err == nil {
		t.Fatalf("expected error for missing version and fields")
	}

	enh.Version = CurrentSealVersion
	enh.JobID = "job-1"
	enh.ChainID = "aethelred-test-1"
	enh.ConsensusInfo = &ConsensusInfo{TotalValidators: 4, AgreementCount: 3, Timestamp: time.Now().UTC()}
	enh.VerificationBundle = &VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: bytes.Repeat([]byte{0x04}, 32),
		TEEVerifications: []TEEVerification{{
			ValidatorAddress: testAccAddress(4),
			Measurement:      []byte{0x01},
		}},
	}

	enh.Timestamp = timestamppb.Now()
	enh.Id = enh.GenerateID()

	if err := enh.ValidateEnhanced(); err != nil {
		t.Fatalf("expected valid enhanced seal, got %v", err)
	}
}

func TestEnhancedSealVerificationBundleErrors(t *testing.T) {
	base := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(5),
		"credit_scoring",
	)
	enh := &EnhancedDigitalSeal{
		DigitalSeal: *base,
		Version:     CurrentSealVersion,
		JobID:       "job-2",
		ChainID:     "aethelred-test-1",
		ConsensusInfo: &ConsensusInfo{
			TotalValidators: 4,
			AgreementCount:  3,
			Timestamp:       time.Now().UTC(),
		},
		VerificationBundle: &VerificationBundle{
			VerificationType:     "unknown",
			AggregatedOutputHash: bytes.Repeat([]byte{0x04}, 32),
		},
	}
	enh.Timestamp = timestamppb.Now()
	enh.Id = enh.GenerateID()

	if err := enh.ValidateEnhanced(); err == nil {
		t.Fatalf("expected error for unknown verification type")
	}
}

func TestEnhancedSealSummaryAndConsistency(t *testing.T) {
	base := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(6),
		"credit_scoring",
	)

	bundle := &VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: bytes.Repeat([]byte{0x04}, 32),
		TEEVerifications: []TEEVerification{{
			ValidatorAddress: testAccAddress(7),
			OutputHash:       bytes.Repeat([]byte{0x04}, 32),
		}},
	}
	enh := &EnhancedDigitalSeal{
		DigitalSeal: *base,
		Version:     CurrentSealVersion,
		JobID:       "job-3",
		ChainID:     "aethelred-test-1",
		ConsensusInfo: &ConsensusInfo{
			TotalValidators:         4,
			ParticipatingValidators: 4,
			AgreementCount:          3,
			Timestamp:               time.Now().UTC(),
		},
		VerificationBundle: bundle,
	}
	enh.Timestamp = timestamppb.Now()
	enh.Id = enh.GenerateID()
	enh.Status = SealStatusActive

	if !enh.VerifyOutputConsistency() {
		t.Fatalf("expected output consistency")
	}

	summary := enh.GetVerificationSummary()
	if summary.VerificationType != "tee" {
		t.Fatalf("expected tee verification type")
	}
	if !summary.ConsensusReached {
		t.Fatalf("expected consensus reached")
	}
}

func TestEnhancedSealOutputConsistencyMismatch(t *testing.T) {
	base := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(8),
		"credit_scoring",
	)

	bundle := &VerificationBundle{
		VerificationType:     "tee",
		AggregatedOutputHash: bytes.Repeat([]byte{0x04}, 32),
		TEEVerifications: []TEEVerification{{
			ValidatorAddress: testAccAddress(9),
			OutputHash:       bytes.Repeat([]byte{0x05}, 32),
		}},
	}
	enh := &EnhancedDigitalSeal{
		DigitalSeal:        *base,
		Version:            CurrentSealVersion,
		JobID:              "job-4",
		ChainID:            "aethelred-test-1",
		ConsensusInfo:      &ConsensusInfo{TotalValidators: 4, AgreementCount: 3, Timestamp: time.Now().UTC()},
		VerificationBundle: bundle,
	}
	enh.Timestamp = timestamppb.Now()
	enh.Id = enh.GenerateID()

	if enh.VerifyOutputConsistency() {
		t.Fatalf("expected output consistency to fail on mismatch")
	}
}

func TestEnhancedSealJSONRoundTrip(t *testing.T) {
	base := NewDigitalSeal(
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		100,
		testAccAddress(12),
		"credit_scoring",
	)
	enh := &EnhancedDigitalSeal{
		DigitalSeal: *base,
		Version:     CurrentSealVersion,
		JobID:       "job-5",
		ChainID:     "aethelred-test-1",
		ConsensusInfo: &ConsensusInfo{
			TotalValidators: 4,
			AgreementCount:  3,
			Timestamp:       time.Now().UTC(),
		},
		VerificationBundle: &VerificationBundle{
			VerificationType:     "tee",
			AggregatedOutputHash: bytes.Repeat([]byte{0x04}, 32),
			TEEVerifications: []TEEVerification{{
				ValidatorAddress: testAccAddress(13),
				OutputHash:       bytes.Repeat([]byte{0x04}, 32),
			}},
		},
	}
	enh.Timestamp = timestamppb.Now()
	enh.Id = enh.GenerateID()

	payload, err := enh.ToJSON()
	if err != nil {
		t.Fatalf("expected json encode to succeed, got %v", err)
	}

	decoded, err := FromJSON(payload)
	if err != nil {
		t.Fatalf("expected json decode to succeed, got %v", err)
	}
	if decoded.Id != enh.Id {
		t.Fatalf("expected decoded ID to match")
	}
}
