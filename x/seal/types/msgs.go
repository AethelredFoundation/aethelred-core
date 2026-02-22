package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	TypeMsgCreateSeal   = "create_seal"
	TypeMsgRevokeSeal   = "revoke_seal"
	TypeMsgQuerySeal    = "query_seal"
	TypeMsgExportAudit  = "export_audit"
)

var (
	_ sdk.Msg = &MsgCreateSeal{}
	_ sdk.Msg = &MsgRevokeSeal{}
)

// NewMsgCreateSeal creates a new MsgCreateSeal
func NewMsgCreateSeal(
	creator string,
	jobID string,
	modelCommitment, inputCommitment, outputCommitment []byte,
	purpose string,
) *MsgCreateSeal {
	return &MsgCreateSeal{
		Creator:          creator,
		JobId:            jobID,
		ModelCommitment:  modelCommitment,
		InputCommitment:  inputCommitment,
		OutputCommitment: outputCommitment,
		Purpose:          purpose,
		TeeAttestations:  make([]*TEEAttestation, 0),
	}
}

// Route implements sdk.Msg
func (msg *MsgCreateSeal) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgCreateSeal) Type() string { return TypeMsgCreateSeal }

// GetSigners implements sdk.Msg
func (msg *MsgCreateSeal) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgCreateSeal) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgCreateSeal) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if len(msg.JobId) == 0 {
		return fmt.Errorf("job ID cannot be empty")
	}
	if len(msg.ModelCommitment) != 32 {
		return fmt.Errorf("model commitment must be 32 bytes")
	}
	if len(msg.InputCommitment) != 32 {
		return fmt.Errorf("input commitment must be 32 bytes")
	}
	if len(msg.OutputCommitment) != 32 {
		return fmt.Errorf("output commitment must be 32 bytes")
	}
	if len(msg.Purpose) == 0 {
		return fmt.Errorf("purpose cannot be empty")
	}
	return nil
}

// NewMsgRevokeSeal creates a new MsgRevokeSeal
func NewMsgRevokeSeal(authority, sealID, reason string) *MsgRevokeSeal {
	return &MsgRevokeSeal{
		Authority: authority,
		SealId:    sealID,
		Reason:    reason,
	}
}

// Route implements sdk.Msg
func (msg *MsgRevokeSeal) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRevokeSeal) Type() string { return TypeMsgRevokeSeal }

// GetSigners implements sdk.Msg
func (msg *MsgRevokeSeal) GetSigners() []sdk.AccAddress {
	authority, err := sdk.AccAddressFromBech32(msg.Authority)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{authority}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRevokeSeal) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRevokeSeal) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Authority)
	if err != nil {
		return fmt.Errorf("invalid authority address: %w", err)
	}
	if len(msg.SealId) == 0 {
		return fmt.Errorf("seal ID cannot be empty")
	}
	if len(msg.Reason) == 0 {
		return fmt.Errorf("reason cannot be empty")
	}
	return nil
}
