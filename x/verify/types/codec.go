package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	"github.com/cosmos/cosmos-sdk/types/tx"
)

// ModuleCdc is the codec for the module
var ModuleCdc = codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())

// RegisterLegacyAminoCodec registers the necessary interfaces and concrete types
// for amino serialization.
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgRegisterVerifyingKey{}, "aethelred/verify/MsgRegisterVerifyingKey", nil)
	cdc.RegisterConcrete(&MsgRegisterCircuit{}, "aethelred/verify/MsgRegisterCircuit", nil)
	cdc.RegisterConcrete(&MsgVerifyZKProof{}, "aethelred/verify/MsgVerifyZKProof", nil)
}

// RegisterInterfaces registers the interfaces types with the interface registry.
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRegisterVerifyingKey{},
		&MsgRegisterCircuit{},
		&MsgVerifyZKProof{},
	)

	registry.RegisterImplementations((*tx.MsgResponse)(nil),
		&MsgRegisterVerifyingKeyResponse{},
		&MsgRegisterCircuitResponse{},
		&MsgVerifyZKProofResponse{},
	)

	// Best-effort registration: avoid panic when proto descriptors are not
	// registered via gogoproto in certain builds/tests.
	func() {
		defer func() {
			_ = recover()
		}()
		msgservice.RegisterMsgServiceDesc(registry, &Msg_ServiceDesc)
	}()
}
