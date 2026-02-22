package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func FuzzVoteExtensionUnmarshal(f *testing.F) {
	f.Add([]byte(`{"version":1,"height":1,"validator_address":"AAEC","verifications":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"height":0,"verifications":[{"job_id":"job-1","success":true,"output_hash":"` + hex.EncodeToString(make([]byte, 32)) + `"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		ve, err := UnmarshalVoteExtension(data)
		if err != nil {
			return
		}

		_ = ve.Validate()
		_ = ve.ValidateStrict()
		_ = ve.ComputeHash()

		roundTrip, err := ve.Marshal()
		if err != nil {
			return
		}
		ve2, err := UnmarshalVoteExtension(roundTrip)
		if err != nil {
			t.Fatalf("round-trip unmarshal failed: %v", err)
		}
		_ = ve2.Validate()
	})
}

func FuzzVoteExtensionSignVerify(f *testing.F) {
	f.Add([]byte("seed-1"))
	f.Add([]byte("seed-2"))
	f.Add([]byte("seed-3"))

	f.Fuzz(func(t *testing.T, data []byte) {
		seed := sha256.Sum256(data)
		priv := ed25519.NewKeyFromSeed(seed[:])
		pub := priv.Public().(ed25519.PublicKey)

		height := int64(binary.BigEndian.Uint64(seed[:8]))
		addr := seed[:20]

		ve := NewVoteExtension(height, addr)
		ve.Timestamp = boundedFuzzTime(seed[8:16])
		ve.AddVerification(buildVerificationFromSeed(seed, data))

		if err := SignVoteExtension(ve, priv); err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		if !VerifyVoteExtensionSignature(ve, pub) {
			t.Fatalf("signature verify failed")
		}

		// Tamper with signature and ensure verify does not panic.
		if len(ve.Signature) > 0 {
			ve.Signature[0] ^= 0xff
		}
		_ = VerifyVoteExtensionSignature(ve, pub)
	})
}

func FuzzAggregateVoteExtensions(f *testing.F) {
	f.Add([]byte("agg-seed-1"))
	f.Add([]byte("agg-seed-2"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		count := int(data[0]%5) + 1
		extensions := make([]*VoteExtension, 0, count)
		for i := 0; i < count; i++ {
			hash := sha256.Sum256(append(data, byte(i)))
			ve := NewVoteExtension(int64(i+1), hash[:20])
			ve.Timestamp = boundedFuzzTime(hash[8:16])
			ver := buildVerificationFromSeed(hash, data)
			ver.Success = (hash[0]%2 == 0)
			ve.Verifications = []ComputeVerification{ver}
			extensions = append(extensions, ve)
		}

		threshold := int(data[0]%100) + 1
		withPower := make([]VoteExtensionWithPower, 0, len(extensions))
		for _, ext := range extensions {
			withPower = append(withPower, VoteExtensionWithPower{
				Extension: ext,
				Power:     1,
			})
		}
		_ = AggregateVoteExtensions(sdk.Context{}, withPower, threshold, true)
	})
}

func boundedFuzzTime(seed []byte) time.Time {
	base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	max := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix() - base.Unix()
	if max <= 0 {
		return base
	}
	span := int64(binary.BigEndian.Uint64(seed) % uint64(max))
	return base.Add(time.Duration(span) * time.Second)
}

func FuzzInjectedVoteExtensionTx(f *testing.F) {
	f.Add([]byte(`{"job_id":"job-1","output_hash":"","validator_count":1,"total_votes":1,"block_height":1,"type":"create_seal_from_consensus"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, err := UnmarshalInjectedVoteExtensionTx(data)
		if err != nil {
			return
		}
		_, _ = tx.Marshal()
		_ = IsInjectedVoteExtensionTx(data)
	})
}

func buildVerificationFromSeed(seed [32]byte, data []byte) ComputeVerification {
	jobID := hex.EncodeToString(seed[:6])
	modelHash := seed[:]
	inputHash := sha256.Sum256(append(seed[:], 0x01))
	outputHash := sha256.Sum256(append(seed[:], 0x02))

	attestation := AttestationTypeNone
	switch seed[0] % 4 {
	case 0:
		attestation = AttestationTypeTEE
	case 1:
		attestation = AttestationTypeZKML
	case 2:
		attestation = AttestationTypeHybrid
	}

	return ComputeVerification{
		JobID:           jobID,
		ModelHash:       modelHash,
		InputHash:       inputHash[:],
		OutputHash:      outputHash[:],
		AttestationType: attestation,
		ExecutionTimeMs: int64(binary.BigEndian.Uint32(seed[0:4])),
		Success:         len(data)%2 == 0,
		Nonce:           seed[10:20],
	}
}
