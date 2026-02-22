package types

import "fmt"

const (
	VerificationTypeUnspecified = VerificationType_VERIFICATION_TYPE_UNSPECIFIED
	VerificationTypeTEE         = VerificationType_VERIFICATION_TYPE_TEE
	VerificationTypeZKML        = VerificationType_VERIFICATION_TYPE_ZKML
	VerificationTypeHybrid      = VerificationType_VERIFICATION_TYPE_HYBRID
)

const (
	TEEPlatformUnspecified = TEEPlatform_TEE_PLATFORM_UNSPECIFIED
	TEEPlatformAWSNitro    = TEEPlatform_TEE_PLATFORM_AWS_NITRO
	TEEPlatformIntelSGX    = TEEPlatform_TEE_PLATFORM_INTEL_SGX
	TEEPlatformIntelTDX    = TEEPlatform_TEE_PLATFORM_INTEL_TDX
	TEEPlatformAMDSEV      = TEEPlatform_TEE_PLATFORM_AMD_SEV
	TEEPlatformARMTrustZone = TEEPlatform_TEE_PLATFORM_ARM_TRUSTZONE
)

// Validate validates a ZKMLProof
func (p *ZKMLProof) Validate() error {
	if len(p.ProofSystem) == 0 {
		return fmt.Errorf("proof system cannot be empty")
	}
	if len(p.ProofBytes) == 0 {
		return fmt.Errorf("proof bytes cannot be empty")
	}
	if len(p.VerifyingKeyHash) != 32 {
		return fmt.Errorf("verifying key hash must be 32 bytes")
	}
	return nil
}

// Validate validates a TEEAttestation
func (a *TEEAttestation) Validate() error {
	if a.Platform == TEEPlatformUnspecified {
		return fmt.Errorf("platform cannot be unspecified")
	}
	if len(a.Measurement) == 0 {
		return fmt.Errorf("measurement cannot be empty")
	}
	if len(a.Quote) == 0 {
		return fmt.Errorf("quote cannot be empty")
	}
	return nil
}

// IsPlatformSupported checks if a TEE platform is supported
func IsPlatformSupported(platform TEEPlatform) bool {
	switch platform {
	case TEEPlatformAWSNitro, TEEPlatformIntelSGX, TEEPlatformIntelTDX, TEEPlatformAMDSEV, TEEPlatformARMTrustZone:
		return true
	default:
		return false
	}
}

// IsProofSystemSupported checks if a proof system is supported
func IsProofSystemSupported(system string) bool {
	supported := map[string]bool{
		"ezkl":    true,
		"risc0":   true,
		"plonky2": true,
		"halo2":   true,
	}
	return supported[system]
}
