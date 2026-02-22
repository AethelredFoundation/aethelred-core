package app

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"

	// Aethelred custom modules
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
	verifytypes "github.com/aethelred/aethelred/x/verify/types"
)

// EncodingConfig specifies the concrete encoding types to use for the Aethelred app
type EncodingConfig struct {
	InterfaceRegistry types.InterfaceRegistry
	Codec             codec.Codec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}

// MakeEncodingConfig creates an EncodingConfig for the Aethelred app
func MakeEncodingConfig() EncodingConfig {
	amino := codec.NewLegacyAmino()
	interfaceRegistry := types.NewInterfaceRegistry()

	// Register standard Cosmos SDK types
	std.RegisterLegacyAminoCodec(amino)
	std.RegisterInterfaces(interfaceRegistry)

	// Register all module interfaces (including Msg services) to avoid
	// MsgServiceRouter panics when app.New() registers services.
	ModuleBasics.RegisterInterfaces(interfaceRegistry)

	// Register Aethelred custom module types
	sealtypes.RegisterInterfaces(interfaceRegistry)
	pouwtypes.RegisterInterfaces(interfaceRegistry)
	verifytypes.RegisterInterfaces(interfaceRegistry)

	// Register legacy amino codecs for custom modules
	sealtypes.RegisterLegacyAminoCodec(amino)
	pouwtypes.RegisterLegacyAminoCodec(amino)
	verifytypes.RegisterLegacyAminoCodec(amino)

	// Create the codec
	cdc := codec.NewProtoCodec(interfaceRegistry)

	// Create tx config
	txConfig := tx.NewTxConfig(cdc, tx.DefaultSignModes)

	return EncodingConfig{
		InterfaceRegistry: interfaceRegistry,
		Codec:             cdc,
		TxConfig:          txConfig,
		Amino:             amino,
	}
}
