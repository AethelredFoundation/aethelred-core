package types

import (
	"fmt"
	"strings"
)

const (
	// EscrowDurationDays is the mandatory escrow hold period for fraud slashes.
	EscrowDurationDays = 14

	// TribunalSize is the required number of reviewers.
	TribunalSize = 5

	// TribunalMajority is the vote threshold required to resolve an appeal.
	TribunalMajority = 3
)

type EscrowStatus string

const (
	EscrowStatusHeld       EscrowStatus = "held"
	EscrowStatusReimbursed EscrowStatus = "reimbursed"
	EscrowStatusForfeited  EscrowStatus = "forfeited"
)

type AppealStatus string

const (
	AppealStatusPending  AppealStatus = "pending"
	AppealStatusApproved AppealStatus = "approved"
	AppealStatusRejected AppealStatus = "rejected"
)

// EscrowRecord tracks a slashed stake under insurance review.
type EscrowRecord struct {
	ID               string       `json:"id"`
	ValidatorAddress string       `json:"validator_address"`
	Amount           string       `json:"amount"`
	Reason           string       `json:"reason"`
	EvidenceHash     string       `json:"evidence_hash"`
	CreatedAtUnix    int64        `json:"created_at_unix"`
	ReleaseAtUnix    int64        `json:"release_at_unix"`
	AppealID         string       `json:"appeal_id,omitempty"`
	Status           EscrowStatus `json:"status"`
}

// AppealRecord tracks a validator appeal and assigned tribunal.
type AppealRecord struct {
	ID               string       `json:"id"`
	EscrowID         string       `json:"escrow_id"`
	ValidatorAddress string       `json:"validator_address"`
	TeeLogURI        string       `json:"tee_log_uri"`
	EvidenceHash     string       `json:"evidence_hash"`
	Tribunal         []string     `json:"tribunal"`
	VotesFor         int          `json:"votes_for"`
	VotesAgainst     int          `json:"votes_against"`
	SubmittedAtUnix  int64        `json:"submitted_at_unix"`
	ResolvedAtUnix   int64        `json:"resolved_at_unix,omitempty"`
	Status           AppealStatus `json:"status"`
}

// TribunalVote is a single reviewer vote.
type TribunalVote struct {
	AppealID        string `json:"appeal_id"`
	Voter           string `json:"voter"`
	NonMalicious    bool   `json:"non_malicious"`
	Notes           string `json:"notes,omitempty"`
	SubmittedAtUnix int64  `json:"submitted_at_unix"`
}

// MsgSubmitAppeal opens an appeal against an escrowed fraud slash.
type MsgSubmitAppeal struct {
	ValidatorAddress string `json:"validator_address"`
	EscrowID         string `json:"escrow_id"`
	TeeLogURI        string `json:"tee_log_uri"`
	EvidenceHash     string `json:"evidence_hash"`
}

func (m MsgSubmitAppeal) ValidateBasic() error {
	if strings.TrimSpace(m.ValidatorAddress) == "" {
		return fmt.Errorf("validator address cannot be empty")
	}
	if strings.TrimSpace(m.EscrowID) == "" {
		return fmt.Errorf("escrow id cannot be empty")
	}
	if strings.TrimSpace(m.TeeLogURI) == "" {
		return fmt.Errorf("TEE log URI cannot be empty")
	}
	if strings.TrimSpace(m.EvidenceHash) == "" {
		return fmt.Errorf("evidence hash cannot be empty")
	}
	return nil
}
