package app

import (
	"encoding/hex"
	"sort"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

// VoteExtensionCache stores verified vote extensions by height and validator address.
// It is an in-memory cache used to enforce computation finality in ProcessProposal.
type VoteExtensionCache struct {
	mu         sync.RWMutex
	byHeight   map[int64]map[string][]byte
	maxHeights int
}

// NewVoteExtensionCache creates a cache that retains at most maxHeights entries.
func NewVoteExtensionCache(maxHeights int) *VoteExtensionCache {
	if maxHeights <= 0 {
		maxHeights = 2
	}
	return &VoteExtensionCache{
		byHeight:   make(map[int64]map[string][]byte),
		maxHeights: maxHeights,
	}
}

// Store records a verified vote extension for a validator at a given height.
func (c *VoteExtensionCache) Store(height int64, validatorAddr []byte, extension []byte) {
	if c == nil || height <= 0 || len(validatorAddr) == 0 {
		return
	}

	key := hex.EncodeToString(validatorAddr)
	extCopy := make([]byte, len(extension))
	copy(extCopy, extension)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.byHeight[height] == nil {
		c.byHeight[height] = make(map[string][]byte)
	}
	c.byHeight[height][key] = extCopy

	c.prune()
}

// BuildExtendedVotes constructs ExtendedVoteInfo entries by combining commit votes
// with cached vote extensions for the given height. Returns count of found extensions.
func (c *VoteExtensionCache) BuildExtendedVotes(height int64, votes []abci.VoteInfo) ([]abci.ExtendedVoteInfo, int) {
	extended := make([]abci.ExtendedVoteInfo, 0, len(votes))
	if c == nil {
		for _, vote := range votes {
			extended = append(extended, abci.ExtendedVoteInfo{
				Validator:   vote.Validator,
				BlockIdFlag: vote.BlockIdFlag,
			})
		}
		return extended, 0
	}

	c.mu.RLock()
	byValidator := c.byHeight[height]
	c.mu.RUnlock()

	found := 0
	for _, vote := range votes {
		ext := []byte(nil)
		if byValidator != nil && len(vote.Validator.Address) > 0 {
			key := hex.EncodeToString(vote.Validator.Address)
			if cached, ok := byValidator[key]; ok {
				ext = cached
				found++
			}
		}
		extended = append(extended, abci.ExtendedVoteInfo{
			Validator:     vote.Validator,
			VoteExtension: ext,
			BlockIdFlag:   vote.BlockIdFlag,
		})
	}

	return extended, found
}

func (c *VoteExtensionCache) prune() {
	if len(c.byHeight) <= c.maxHeights {
		return
	}

	heights := make([]int64, 0, len(c.byHeight))
	for h := range c.byHeight {
		heights = append(heights, h)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })

	for len(heights) > c.maxHeights {
		oldest := heights[0]
		delete(c.byHeight, oldest)
		heights = heights[1:]
	}
}
