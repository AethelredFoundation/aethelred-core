package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	TypeMsgRegisterVerifyingKey = "register_verifying_key"
	TypeMsgRegisterCircuit      = "register_circuit"
	TypeMsgConfigureTEE         = "configure_tee"
	TypeMsgVerifyZKProof        = "verify_zk_proof"
	TypeMsgVerifyTEEAttestation = "verify_tee_attestation"
)

var (
	_ sdk.Msg = &MsgRegisterVerifyingKey{}
	_ sdk.Msg = &MsgRegisterCircuit{}
	_ sdk.Msg = &MsgVerifyZKProof{}
)

// NewMsgRegisterVerifyingKey creates a new MsgRegisterVerifyingKey
func NewMsgRegisterVerifyingKey(
	creator string,
	keyBytes []byte,
	proofSystem string,
	circuitHash, modelHash []byte,
) *MsgRegisterVerifyingKey {
	return &MsgRegisterVerifyingKey{
		Creator:     creator,
		KeyBytes:    keyBytes,
		ProofSystem: proofSystem,
		CircuitHash: circuitHash,
		ModelHash:   modelHash,
	}
}

// Route implements sdk.Msg
func (msg *MsgRegisterVerifyingKey) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRegisterVerifyingKey) Type() string { return TypeMsgRegisterVerifyingKey }

// GetSigners implements sdk.Msg
func (msg *MsgRegisterVerifyingKey) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRegisterVerifyingKey) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRegisterVerifyingKey) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if len(msg.KeyBytes) == 0 {
		return fmt.Errorf("key bytes cannot be empty")
	}
	if len(msg.ProofSystem) == 0 {
		return fmt.Errorf("proof system cannot be empty")
	}
	if !IsProofSystemSupported(msg.ProofSystem) {
		return fmt.Errorf("unsupported proof system: %s", msg.ProofSystem)
	}
	return nil
}

// Route implements sdk.Msg
func (msg *MsgRegisterCircuit) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgRegisterCircuit) Type() string { return TypeMsgRegisterCircuit }

// GetSigners implements sdk.Msg
func (msg *MsgRegisterCircuit) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgRegisterCircuit) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgRegisterCircuit) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return fmt.Errorf("invalid creator address: %w", err)
	}
	if len(msg.CircuitBytes) == 0 {
		return fmt.Errorf("circuit bytes cannot be empty")
	}
	if len(msg.ProofSystem) == 0 {
		return fmt.Errorf("proof system cannot be empty")
	}
	return nil
}

// Route implements sdk.Msg
func (msg *MsgVerifyZKProof) Route() string { return RouterKey }

// Type implements sdk.Msg
func (msg *MsgVerifyZKProof) Type() string { return TypeMsgVerifyZKProof }

// GetSigners implements sdk.Msg
func (msg *MsgVerifyZKProof) GetSigners() []sdk.AccAddress {
	verifier, err := sdk.AccAddressFromBech32(msg.Verifier)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{verifier}
}

// GetSignBytes implements sdk.Msg
func (msg *MsgVerifyZKProof) GetSignBytes() []byte {
	bz := ModuleCdc.MustMarshalJSON(msg)
	return sdk.MustSortJSON(bz)
}

// ValidateBasic implements sdk.Msg
func (msg *MsgVerifyZKProof) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Verifier)
	if err != nil {
		return fmt.Errorf("invalid verifier address: %w", err)
	}
	if msg.Proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if err := msg.Proof.Validate(); err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}
	return nil
}
