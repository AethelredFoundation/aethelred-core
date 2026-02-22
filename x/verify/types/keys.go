package types

const (
	// ModuleName defines the module name
	ModuleName = "verify"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing key
	QuerierRoute = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_verify"
)

var (
	// VerifyingKeyPrefix is the prefix for storing verifying keys
	VerifyingKeyPrefix = []byte{0x01}

	// CircuitPrefix is the prefix for storing circuit definitions
	CircuitPrefix = []byte{0x02}

	// TEEConfigPrefix is the prefix for TEE configurations
	TEEConfigPrefix = []byte{0x03}

	// VerificationResultPrefix is the prefix for verification results
	VerificationResultPrefix = []byte{0x04}

	// ParamsKey is the key for storing module params
	ParamsKey = []byte{0x05}

	// TEEReplayQuotePrefix stores quote-hash replay registry entries.
	TEEReplayQuotePrefix = []byte{0x06}

	// TEEReplayNoncePrefix stores nonce replay registry entries.
	TEEReplayNoncePrefix = []byte{0x07}
)

// VerifyingKeyKey returns the store key for a verifying key
func VerifyingKeyKey(hash []byte) []byte {
	return append(VerifyingKeyPrefix, hash...)
}

// CircuitKey returns the store key for a circuit definition
func CircuitKey(hash []byte) []byte {
	return append(CircuitPrefix, hash...)
}

// TEEConfigKey returns the store key for a TEE configuration
func TEEConfigKey(platform string) []byte {
	return append(TEEConfigPrefix, []byte(platform)...)
}
