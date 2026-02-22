package types

import (
	"fmt"
	"strings"
)

const (
	// SecurityCouncilThreshold is the mandatory emergency quorum.
	SecurityCouncilThreshold = 5

	// SecurityCouncilSize is the mandatory number of council keys.
	SecurityCouncilSize = 7
)

const (
	RoleValidator  = "validator"
	RoleFoundation = "foundation"
	RoleAuditor    = "auditor"
)

// SecurityCouncilMember stores a council key and role.
type SecurityCouncilMember struct {
	Address string `json:"address"`
	Role    string `json:"role"`
}

// SecurityCouncilConfig defines emergency halt authorization.
type SecurityCouncilConfig struct {
	Threshold int                     `json:"threshold"`
	Members   []SecurityCouncilMember `json:"members"`
}

func (c SecurityCouncilConfig) Validate() error {
	if c.Threshold != SecurityCouncilThreshold {
		return fmt.Errorf("security council threshold must be %d-of-%d", SecurityCouncilThreshold, SecurityCouncilSize)
	}
	if len(c.Members) != SecurityCouncilSize {
		return fmt.Errorf("security council must contain exactly %d members", SecurityCouncilSize)
	}

	seen := make(map[string]struct{}, len(c.Members))
	roleCount := map[string]int{
		RoleValidator:  0,
		RoleFoundation: 0,
		RoleAuditor:    0,
	}
	for _, member := range c.Members {
		addr := strings.TrimSpace(member.Address)
		role := strings.TrimSpace(strings.ToLower(member.Role))
		if addr == "" {
			return fmt.Errorf("security council member address cannot be empty")
		}
		if _, exists := seen[addr]; exists {
			return fmt.Errorf("duplicate council member address: %s", addr)
		}
		seen[addr] = struct{}{}

		if _, ok := roleCount[role]; !ok {
			return fmt.Errorf("unsupported council role: %s", member.Role)
		}
		roleCount[role]++
	}

	if roleCount[RoleValidator] < 3 {
		return fmt.Errorf("security council requires at least 3 validator members")
	}
	if roleCount[RoleFoundation] < 2 {
		return fmt.Errorf("security council requires at least 2 foundation members")
	}
	if roleCount[RoleAuditor] < 2 {
		return fmt.Errorf("security council requires at least 2 auditor members")
	}

	return nil
}

// MsgHaltNetwork is the emergency command to freeze bridge and PoUW flows.
type MsgHaltNetwork struct {
	Requester string   `json:"requester"`
	Reason    string   `json:"reason"`
	Signers   []string `json:"signers"`
}

func (m MsgHaltNetwork) ValidateBasic() error {
	if strings.TrimSpace(m.Requester) == "" {
		return fmt.Errorf("requester cannot be empty")
	}
	if strings.TrimSpace(m.Reason) == "" {
		return fmt.Errorf("halt reason cannot be empty")
	}
	if len(m.Signers) == 0 {
		return fmt.Errorf("halt request requires signers")
	}
	return nil
}

// HaltState tracks emergency freeze state.
type HaltState struct {
	Active                bool     `json:"active"`
	Reason                string   `json:"reason"`
	TriggeredBy           []string `json:"triggered_by"`
	TriggeredByRequester  string   `json:"triggered_by_requester"`
	TriggeredAtHeight     int64    `json:"triggered_at_height"`
	TriggeredAtUnix       int64    `json:"triggered_at_unix"`
	BridgeTransfersHalted bool     `json:"bridge_transfers_halted"`
	PoUWAllocationsHalted bool     `json:"pouw_allocations_halted"`
	GovernanceAllowed     bool     `json:"governance_allowed"`
}
