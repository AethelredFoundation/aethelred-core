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
	cdc.RegisterConcrete(&MsgSubmitJob{}, "aethelred/pouw/MsgSubmitJob", nil)
	cdc.RegisterConcrete(&MsgRegisterModel{}, "aethelred/pouw/MsgRegisterModel", nil)
	cdc.RegisterConcrete(&MsgCancelJob{}, "aethelred/pouw/MsgCancelJob", nil)
	cdc.RegisterConcrete(&MsgRegisterValidatorCapability{}, "aethelred/pouw/MsgRegisterValidatorCapability", nil)
	cdc.RegisterConcrete(&MsgRegisterValidatorPCR0{}, "aethelred/pouw/MsgRegisterValidatorPCR0", nil)
}

// RegisterInterfaces registers the interfaces types with the interface registry.
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSubmitJob{},
		&MsgRegisterModel{},
		&MsgCancelJob{},
		&MsgRegisterValidatorCapability{},
		&MsgRegisterValidatorPCR0{},
	)

	registry.RegisterImplementations((*tx.MsgResponse)(nil),
		&MsgSubmitJobResponse{},
		&MsgRegisterModelResponse{},
		&MsgCancelJobResponse{},
		&MsgRegisterValidatorCapabilityResponse{},
		&MsgRegisterValidatorPCR0Response{},
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
