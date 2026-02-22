package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ValidateVerificationWireForTest exposes validateVerificationWire for
// negative-case testing. This method is part of the production binary but
// only called from test code.
//
// NOTE: This follows the standard Go pattern of adding exported test helpers
// directly on the type rather than using export_test.go (which would require
// the _test package), because our tests are in keeper_test and need to call
// through the public API.
func (ch *ConsensusHandler) ValidateVerificationWireForTest(v *VerificationWire) error {
	return ch.validateVerificationWire(v)
}

// ValidateVerificationWireWithCtxForTest exposes deterministic validation that
// uses block context (e.g. block time) for freshness checks.
func (ch *ConsensusHandler) ValidateVerificationWireWithCtxForTest(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateVerificationWireWithCtx(&ctx, v)
}

// ValidateTEEAttestationWireStrictForTest exposes the production-mode TEE
// attestation validation for testing. This checks AllowSimulated on the
// keeper's params and rejects simulated TEE when false.
func (ch *ConsensusHandler) ValidateTEEAttestationWireStrictForTest(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateTEEAttestationWireStrict(ctx, v)
}
