package keeper

import (
	"cosmossdk.io/collections"
	"cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/x/verify/types"
)

// Keeper manages the verify module state.
type Keeper struct {
	cdc          codec.Codec
	storeService store.KVStoreService
	authority    string

	// Circuit breakers for external verifiers.
	zkVerifierBreaker          *circuitbreaker.Breaker
	attestationVerifierBreaker *circuitbreaker.Breaker

	// State collections.
	VerifyingKeys   collections.Map[string, types.VerifyingKey]
	Circuits        collections.Map[string, types.Circuit]
	TEEConfigs      collections.Map[string, types.TEEConfig]
	TEEReplayQuotes collections.Map[string, string]
	TEEReplayNonces collections.Map[string, string]
	Params          collections.Item[types.Params]
}

// NewKeeper creates a new Keeper instance.
func NewKeeper(
	cdc codec.Codec,
	storeService store.KVStoreService,
	authority string,
) Keeper {
	if storeService == nil {
		// Testing mode — return keeper with circuit breakers only;
		// collections stay zero-valued (unused without a store).
		return Keeper{
			cdc:                        cdc,
			authority:                  authority,
			zkVerifierBreaker:          circuitbreaker.NewDefault("zk_verifier_remote"),
			attestationVerifierBreaker: circuitbreaker.NewDefault("tee_attestation_remote"),
		}
	}

	sb := collections.NewSchemaBuilder(storeService)

	return Keeper{
		cdc:                        cdc,
		storeService:               storeService,
		authority:                  authority,
		zkVerifierBreaker:          circuitbreaker.NewDefault("zk_verifier_remote"),
		attestationVerifierBreaker: circuitbreaker.NewDefault("tee_attestation_remote"),
		VerifyingKeys: collections.NewMap(
			sb,
			collections.NewPrefix(types.VerifyingKeyPrefix),
			"verifying_keys",
			collections.StringKey,
			codec.CollValue[types.VerifyingKey](cdc),
		),
		Circuits: collections.NewMap(
			sb,
			collections.NewPrefix(types.CircuitPrefix),
			"circuits",
			collections.StringKey,
			codec.CollValue[types.Circuit](cdc),
		),
		TEEConfigs: collections.NewMap(
			sb,
			collections.NewPrefix(types.TEEConfigPrefix),
			"tee_configs",
			collections.StringKey,
			codec.CollValue[types.TEEConfig](cdc),
		),
		TEEReplayQuotes: collections.NewMap(
			sb,
			collections.NewPrefix(types.TEEReplayQuotePrefix),
			"tee_replay_quotes",
			collections.StringKey,
			collections.StringValue,
		),
		TEEReplayNonces: collections.NewMap(
			sb,
			collections.NewPrefix(types.TEEReplayNoncePrefix),
			"tee_replay_nonces",
			collections.StringKey,
			collections.StringValue,
		),
		Params: collections.NewItem(
			sb,
			collections.NewPrefix(types.ParamsKey),
			"params",
			codec.CollValue[types.Params](cdc),
		),
	}
}

// GetAuthority returns the module's governance authority address.
func (k Keeper) GetAuthority() string {
	return k.authority
}

// CircuitBreakers returns any configured breakers for external services.
func (k Keeper) CircuitBreakers() []*circuitbreaker.Breaker {
	breakers := make([]*circuitbreaker.Breaker, 0, 2)
	if k.zkVerifierBreaker != nil {
		breakers = append(breakers, k.zkVerifierBreaker)
	}
	if k.attestationVerifierBreaker != nil {
		breakers = append(breakers, k.attestationVerifierBreaker)
	}
	return breakers
}
