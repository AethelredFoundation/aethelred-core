package types

const (
	// ModuleName is the insurance module namespace.
	ModuleName = "insurance"

	// StoreKey is the module KV store key.
	StoreKey = ModuleName
)

var (
	// EscrowKeyPrefix stores escrowed slashing cases.
	EscrowKeyPrefix = []byte{0x01}

	// AppealKeyPrefix stores validator appeal cases.
	AppealKeyPrefix = []byte{0x02}

	// AppealVoteKeyPrefix stores tribunal votes for each appeal.
	AppealVoteKeyPrefix = []byte{0x03}

	// EscrowCountKey stores the next escrow sequence.
	EscrowCountKey = []byte{0x04}

	// AppealCountKey stores the next appeal sequence.
	AppealCountKey = []byte{0x05}
)
