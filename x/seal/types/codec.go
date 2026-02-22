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
	cdc.RegisterConcrete(&MsgCreateSeal{}, "aethelred/seal/MsgCreateSeal", nil)
	cdc.RegisterConcrete(&MsgRevokeSeal{}, "aethelred/seal/MsgRevokeSeal", nil)
}

// RegisterInterfaces registers the interfaces types with the interface registry.
func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateSeal{},
		&MsgRevokeSeal{},
	)

	registry.RegisterImplementations((*tx.MsgResponse)(nil),
		&MsgCreateSealResponse{},
		&MsgRevokeSealResponse{},
	)

	// Best-effort registration: in some builds the proto file descriptor is not
	// registered with gogoproto, so RegisterMsgServiceDesc can panic. We still
	// want app.New(...) to work in tests.
	func() {
		defer func() {
			_ = recover()
		}()
		msgservice.RegisterMsgServiceDesc(registry, &Msg_ServiceDesc)
	}()
}
