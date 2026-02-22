package types

const (
	// ModuleName is the name of the validator module
	ModuleName = "aethelred_validator"

	// StoreKey is the store key for the validator module
	StoreKey = ModuleName

	// RouterKey is the router key for the validator module
	RouterKey = ModuleName

	// QuerierRoute is the querier route for the validator module
	QuerierRoute = ModuleName
)

// Store key prefixes
var (
	// HardwareCapabilityKeyPrefix is the prefix for hardware capability storage
	HardwareCapabilityKeyPrefix = []byte{0x01}

	// HeartbeatKeyPrefix is the prefix for heartbeat storage
	HeartbeatKeyPrefix = []byte{0x02}

	// SlashingRecordKeyPrefix is the prefix for slashing records
	SlashingRecordKeyPrefix = []byte{0x03}

	// ParamsKey is the key for module parameters
	ParamsKey = []byte{0x04}

	// TombstonedValidatorKeyPrefix tracks permanently banned validators.
	TombstonedValidatorKeyPrefix = []byte{0x05}

	// ValidatorJailUntilKeyPrefix tracks temporary jail windows.
	ValidatorJailUntilKeyPrefix = []byte{0x06}
)

// GetHardwareCapabilityKey returns the key for a validator's hardware capability
func GetHardwareCapabilityKey(validatorAddr string) []byte {
	return append(HardwareCapabilityKeyPrefix, []byte(validatorAddr)...)
}

// GetHeartbeatKey returns the key for a validator's heartbeat
func GetHeartbeatKey(validatorAddr string) []byte {
	return append(HeartbeatKeyPrefix, []byte(validatorAddr)...)
}

// GetSlashingRecordKey returns the key for a slashing record
func GetSlashingRecordKey(validatorAddr string, height int64) []byte {
	key := append(SlashingRecordKeyPrefix, []byte(validatorAddr)...)
	// Append height as big-endian bytes
	heightBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		heightBytes[i] = byte(height & 0xff)
		height >>= 8
	}
	return append(key, heightBytes...)
}
