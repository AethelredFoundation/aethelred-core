package types

const (
	// ModuleName defines the module name
	ModuleName = "seal"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing key
	QuerierRoute = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_seal"
)

var (
	// SealKeyPrefix is the prefix for storing seals
	SealKeyPrefix = []byte{0x01}

	// SealCountKey is the key for storing the seal count
	SealCountKey = []byte{0x02}

	// SealByModelKeyPrefix is the prefix for indexing seals by model hash
	SealByModelKeyPrefix = []byte{0x03}

	// SealByRequesterKeyPrefix is the prefix for indexing seals by requester
	SealByRequesterKeyPrefix = []byte{0x04}

	// ParamsKey is the key for storing module params
	ParamsKey = []byte{0x05}
)

// SealKey returns the store key for a seal with the given ID
func SealKey(id string) []byte {
	return append(SealKeyPrefix, []byte(id)...)
}

// SealByModelKey returns the index key for seals by model hash
func SealByModelKey(modelHash []byte, sealID string) []byte {
	return append(append(SealByModelKeyPrefix, modelHash...), []byte(sealID)...)
}

// SealByRequesterKey returns the index key for seals by requester address
func SealByRequesterKey(requester string, sealID string) []byte {
	return append(append(SealByRequesterKeyPrefix, []byte(requester)...), []byte(sealID)...)
}
