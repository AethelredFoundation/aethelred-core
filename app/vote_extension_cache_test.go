package app

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func TestVoteExtensionCache_StoresEmptyExtensions(t *testing.T) {
	cache := NewVoteExtensionCache(4)
	height := int64(10)
	addr1 := []byte("validator-1")
	addr2 := []byte("validator-2")

	cache.Store(height, addr1, []byte{})
	cache.Store(height, addr2, []byte{0xAA, 0xBB})

	votes := []abci.VoteInfo{
		{Validator: abci.Validator{Address: addr1, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
		{Validator: abci.Validator{Address: addr2, Power: 1}, BlockIdFlag: cmtproto.BlockIDFlagCommit},
	}

	extended, found := cache.BuildExtendedVotes(height, votes)
	if found != 2 {
		t.Fatalf("expected 2 cached vote extensions, got %d", found)
	}
	if len(extended) != 2 {
		t.Fatalf("expected 2 extended votes, got %d", len(extended))
	}
	if len(extended[0].VoteExtension) != 0 {
		t.Fatalf("expected first vote extension to be empty, got %d bytes", len(extended[0].VoteExtension))
	}
	if len(extended[1].VoteExtension) != 2 {
		t.Fatalf("expected second vote extension to be 2 bytes, got %d", len(extended[1].VoteExtension))
	}
}
