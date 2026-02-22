package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NewHardwareCapability creates a new HardwareCapability
func NewHardwareCapability(validatorAddr, operatorAddr string) *HardwareCapability {
	now := timestamppb.Now()
	return &HardwareCapability{
		ValidatorAddress: validatorAddr,
		OperatorAddress:  operatorAddr,
		Tee: &TEECapabilities{
			Platforms:  make([]*TEEPlatform, 0),
			EnclaveInfo: make([]*EnclaveInfo, 0),
			Active:     false,
		},
		Zkml: &ZKMLCapabilities{
			ProofSystems:  make([]*ProofSystem, 0),
			Active:        false,
			GpuAccelerated: false,
		},
		Compute: &ComputeResources{
			Gpus: make([]*GPUInfo, 0),
		},
		Status: &CapabilityStatus{
			Online:          false,
			ReputationScore: 50, // Start at 50%
		},
		RegisteredAt: now,
		UpdatedAt:    now,
		Version:      "1.0",
	}
}

// Validate validates the hardware capability
func (hc *HardwareCapability) Validate() error {
	if hc == nil {
		return fmt.Errorf("hardware capability cannot be nil")
	}
	if _, err := sdk.ValAddressFromBech32(hc.ValidatorAddress); err != nil {
		if len(hc.ValidatorAddress) == 0 {
			return fmt.Errorf("validator address cannot be empty")
		}
	}

	if hc.Compute != nil && hc.Compute.MaxConcurrentJobs < 0 {
		return fmt.Errorf("max concurrent jobs cannot be negative")
	}

	return nil
}

// CanHandleTEE checks if the validator can handle TEE-based verification
func (hc *HardwareCapability) CanHandleTEE() bool {
	return hc != nil && hc.Tee != nil && hc.Tee.Active && len(hc.Tee.Platforms) > 0
}

// CanHandleZKML checks if the validator can handle zkML-based verification
func (hc *HardwareCapability) CanHandleZKML() bool {
	return hc != nil && hc.Zkml != nil && hc.Zkml.Active && len(hc.Zkml.ProofSystems) > 0
}

// CanHandleHybrid checks if the validator can handle hybrid verification
func (hc *HardwareCapability) CanHandleHybrid() bool {
	return hc.CanHandleTEE() && hc.CanHandleZKML()
}

// HasTEEPlatform checks if a specific TEE platform is supported
func (hc *HardwareCapability) HasTEEPlatform(platform string) bool {
	if hc == nil || hc.Tee == nil {
		return false
	}
	for _, p := range hc.Tee.Platforms {
		if p != nil && p.Name == platform {
			return true
		}
	}
	return false
}

// HasProofSystem checks if a specific proof system is supported
func (hc *HardwareCapability) HasProofSystem(system string) bool {
	if hc == nil || hc.Zkml == nil {
		return false
	}
	for _, ps := range hc.Zkml.ProofSystems {
		if ps != nil && ps.Name == system {
			return true
		}
	}
	return false
}

// AddTEEPlatform adds a TEE platform to capabilities
func (hc *HardwareCapability) AddTEEPlatform(platform *TEEPlatform) {
	if hc == nil || platform == nil {
		return
	}
	if hc.Tee == nil {
		hc.Tee = &TEECapabilities{}
	}
	// Check if already exists
	for i, p := range hc.Tee.Platforms {
		if p != nil && p.Name == platform.Name {
			hc.Tee.Platforms[i] = platform
			hc.UpdatedAt = timestamppb.Now()
			return
		}
	}
	hc.Tee.Platforms = append(hc.Tee.Platforms, platform)
	hc.Tee.Active = true
	hc.UpdatedAt = timestamppb.Now()
}

// AddProofSystem adds a proof system to capabilities
func (hc *HardwareCapability) AddProofSystem(system *ProofSystem) {
	if hc == nil || system == nil {
		return
	}
	if hc.Zkml == nil {
		hc.Zkml = &ZKMLCapabilities{}
	}
	// Check if already exists
	for i, ps := range hc.Zkml.ProofSystems {
		if ps != nil && ps.Name == system.Name {
			hc.Zkml.ProofSystems[i] = system
			hc.UpdatedAt = timestamppb.Now()
			return
		}
	}
	hc.Zkml.ProofSystems = append(hc.Zkml.ProofSystems, system)
	hc.Zkml.Active = true
	hc.UpdatedAt = timestamppb.Now()
}

// UpdateStatus updates the validator's status
func (hc *HardwareCapability) UpdateStatus(online bool, currentJobs int) {
	if hc == nil {
		return
	}
	if hc.Status == nil {
		hc.Status = &CapabilityStatus{}
	}
	hc.Status.Online = online
	hc.Status.CurrentJobs = int32(currentJobs)
	hc.Status.LastHeartbeat = timestamppb.Now()
	hc.UpdatedAt = timestamppb.Now()
}

// RecordJobCompletion updates stats after a job completion
func (hc *HardwareCapability) RecordJobCompletion(success bool, latencyMs int64) {
	if hc == nil {
		return
	}
	if hc.Status == nil {
		hc.Status = &CapabilityStatus{}
	}
	hc.Status.TotalJobsProcessed++
	if hc.Status.CurrentJobs > 0 {
		hc.Status.CurrentJobs--
	}

	// Update average latency (exponential moving average)
	if hc.Status.AverageLatencyMs == 0 {
		hc.Status.AverageLatencyMs = latencyMs
	} else {
		hc.Status.AverageLatencyMs = (hc.Status.AverageLatencyMs*9 + latencyMs) / 10
	}

	// Update reputation
	if success {
		if hc.Status.ReputationScore < 100 {
			hc.Status.ReputationScore++
		}
	} else {
		if hc.Status.ReputationScore > 0 {
			hc.Status.ReputationScore -= 5
		}
	}

	hc.UpdatedAt = timestamppb.Now()
}

// IsAvailable checks if the validator can accept new jobs
func (hc *HardwareCapability) IsAvailable() bool {
	if hc == nil || hc.Status == nil || hc.Compute == nil {
		return false
	}
	return hc.Status.Online &&
		hc.Status.CurrentJobs < hc.Compute.MaxConcurrentJobs &&
		hc.Status.ReputationScore > 10 // Minimum reputation to accept jobs
}

// GetCapabilityScore returns a score representing overall capability
func (hc *HardwareCapability) GetCapabilityScore() int64 {
	if hc == nil {
		return 0
	}

	var score int64

	// TEE capabilities (max 30 points)
	if hc.CanHandleTEE() {
		score += 10
		for _, p := range hc.Tee.Platforms {
			if p != nil {
				score += int64(p.SecurityLevel * 2)
			}
		}
	}

	// zkML capabilities (max 30 points)
	if hc.CanHandleZKML() {
		score += 10
		score += int64(len(hc.Zkml.ProofSystems) * 5)
		if hc.Zkml.GpuAccelerated {
			score += 10
		}
	}

	// Compute resources (max 20 points)
	if hc.Compute != nil {
		score += int64(hc.Compute.CpuCores / 4)
		score += int64(hc.Compute.MemoryGb / 8)
		score += int64(len(hc.Compute.Gpus) * 5)
	}

	// Reputation (max 20 points)
	if hc.Status != nil {
		score += hc.Status.ReputationScore / 5
	}

	return score
}
