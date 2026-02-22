package types

const (
	// ModuleName is the sovereign emergency-response module namespace.
	ModuleName = "sovereign_crisis"

	// StoreKey is the module KV store key.
	StoreKey = ModuleName
)

var (
	// HaltStateKey stores the active halt state.
	HaltStateKey = []byte{0x01}

	// SecurityCouncilConfigKey stores council membership and threshold.
	SecurityCouncilConfigKey = []byte{0x02}
)
