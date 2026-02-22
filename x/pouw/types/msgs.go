package types

import (
	"encoding/hex"
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	TypeMsgSubmitJob                   = "submit_job"
	TypeMsgRegisterModel               = "register_model"
	TypeMsgCancelJob                   = "cancel_job"
	TypeMsgSubmitResult                = "submit_result"
	TypeMsgRegisterValidatorCapability = "register_validator_capability"
	TypeMsgRegisterValidatorPCR0       = "register_validator_pcr0"
)

var (
	_ sdk.Msg = &MsgSubmitJob{}
	_ sdk.Msg = &MsgRegisterModel{}
	_ sdk.Msg = &MsgCancelJob{}
	_ sdk.Msg = &MsgRegisterValidatorCapability{}
	_ sdk.Msg = &MsgRegisterValidatorPCR0{}
)

// NewMsgSubmitJob creates a new MsgSubmitJob
func NewMsgSubmitJob(
	creator string,
	modelHash, inputHash []byte,
	proofType ProofType,
	purpose string,
) *MsgSubmitJob {
	return &MsgSubmitJob{
		Creator:   creator,
		ModelHash: modelHash,
		InputHash: inputHash,
		ProofType: proofType,
		Purpose:   purpose,
		Metadata:  make(map[string]string),
	}
}

// Route implements sdk.Msg
func (msg *MsgSubmitJob) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgSubmitJob) Type() string { return TypeMsgSubmitJob }

// GetSigners implements sdk.Msg
// Note: In production, GetSigners should not panic. If the address is invalid,
// the transaction will fail validation in ValidateBasic before reaching this point.
// However, we still handle the error gracefully by returning an empty slice.
func (msg *MsgSubmitJob) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		// SECURITY FIX: Return empty slice instead of panicking
		// Invalid addresses will be caught by ValidateBasic()
		return []sdk.AccAddress{}
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgSubmitJob) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgSubmitJob) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if len(msg.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes")
	}
	if len(msg.InputHash) != 32 {
		return fmt.Errorf("input hash must be 32 bytes")
	}
	if msg.ProofType != ProofTypeTEE && msg.ProofType != ProofTypeZKML && msg.ProofType != ProofTypeHybrid {
		return fmt.Errorf("invalid proof type: %s", msg.ProofType.String())
	}
	if len(msg.Purpose) == 0 {
		return fmt.Errorf("purpose cannot be empty")
	}
	return nil
}

// NewMsgRegisterModel creates a new MsgRegisterModel
func NewMsgRegisterModel(
	owner string,
	modelHash []byte,
	modelID, name, description, version, architecture string,
) *MsgRegisterModel {
	return &MsgRegisterModel{
		Owner:        owner,
		ModelHash:    modelHash,
		ModelId:      modelID,
		Name:         name,
		Description:  description,
		Version:      version,
		Architecture: architecture,
	}
}

// Route implements sdk.Msg
func (msg *MsgRegisterModel) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRegisterModel) Type() string { return TypeMsgRegisterModel }

// GetSigners implements sdk.Msg
func (msg *MsgRegisterModel) GetSigners() []sdk.AccAddress {
	owner, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		// SECURITY FIX: Return empty slice instead of panicking
		return []sdk.AccAddress{}
	}
	return []sdk.AccAddress{owner}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRegisterModel) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRegisterModel) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Owner)
	if err != nil {
		return fmt.Errorf("invalid owner address: %w", err)
	}
	if len(msg.ModelHash) != 32 {
		return fmt.Errorf("model hash must be 32 bytes")
	}
	if len(msg.ModelId) == 0 {
		return fmt.Errorf("model ID cannot be empty")
	}
	if len(msg.Name) == 0 {
		return fmt.Errorf("model name cannot be empty")
	}
	return nil
}

// NewMsgCancelJob creates a new MsgCancelJob
func NewMsgCancelJob(creator, jobID string) *MsgCancelJob {
	return &MsgCancelJob{
		Creator: creator,
		JobId:   jobID,
	}
}

// Route implements sdk.Msg
func (msg *MsgCancelJob) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgCancelJob) Type() string { return TypeMsgCancelJob }

// GetSigners implements sdk.Msg
func (msg *MsgCancelJob) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		// SECURITY FIX: Return empty slice instead of panicking
		return []sdk.AccAddress{}
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgCancelJob) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgCancelJob) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if len(msg.JobId) == 0 {
		return fmt.Errorf("job ID cannot be empty")
	}
	return nil
}

// Route implements sdk.Msg
func (msg *MsgRegisterValidatorCapability) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRegisterValidatorCapability) Type() string { return TypeMsgRegisterValidatorCapability }

// GetSigners implements sdk.Msg
func (msg *MsgRegisterValidatorCapability) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		// SECURITY FIX: Return empty slice instead of panicking
		return []sdk.AccAddress{}
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRegisterValidatorCapability) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRegisterValidatorCapability) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Creator); err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if msg.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max_concurrent_jobs must be positive")
	}
	return nil
}

// Route implements sdk.Msg
func (msg *MsgRegisterValidatorPCR0) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRegisterValidatorPCR0) Type() string { return TypeMsgRegisterValidatorPCR0 }

// GetSigners implements sdk.Msg
func (msg *MsgRegisterValidatorPCR0) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return []sdk.AccAddress{}
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRegisterValidatorPCR0) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRegisterValidatorPCR0) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(msg.Creator); err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if _, err := sdk.AccAddressFromBech32(msg.ValidatorAddress); err != nil {
		return fmt.Errorf("invalid validator address: %w", err)
	}
	if msg.Creator != msg.ValidatorAddress {
		return fmt.Errorf("creator must match validator_address")
	}
	normalized := strings.TrimSpace(strings.ToLower(msg.Pcr0Hex))
	if len(normalized) != 64 {
		return fmt.Errorf("invalid pcr0 hex length: got %d, need %d", len(normalized), 64)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return fmt.Errorf("invalid pcr0 hex: %w", err)
	}
	return nil
}
