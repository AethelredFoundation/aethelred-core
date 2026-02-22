package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	sgxQuoteHeaderLen = 48
)

func validateTEEQuoteSchema(att *TEEAttestationData) error {
	if att == nil {
		return fmt.Errorf("attestation is nil")
	}
	switch att.Platform {
	case "aws-nitro":
		return validateNitroQuoteSchema(att.Quote, att.UserData, att.Nonce)
	case "intel-sgx", "intel-tdx":
		return validateDCAPQuoteHeader(att.Quote)
	default:
		return nil
	}
}

type nitroQuoteSchema struct {
	ModuleID    string          `json:"module_id"`
	Timestamp   int64           `json:"timestamp_unix"`
	Digest      string          `json:"digest"`
	PCRs        []nitroQuotePCR `json:"pcrs"`
	Certificate []byte          `json:"certificate,omitempty"`
	CABundle    []byte          `json:"cabundle,omitempty"`
	PublicKey   []byte          `json:"public_key,omitempty"`
	UserData    []byte          `json:"user_data,omitempty"`
	Nonce       []byte          `json:"nonce,omitempty"`
}

func validateNitroQuoteSchema(quote []byte, userData []byte, nonce []byte) error {
	if len(quote) == 0 {
		return fmt.Errorf("empty nitro quote")
	}
	var parsed nitroQuoteSchema
	if err := json.Unmarshal(quote, &parsed); err != nil {
		return fmt.Errorf("invalid nitro quote json: %w", err)
	}
	if parsed.ModuleID == "" {
		return fmt.Errorf("nitro quote missing module_id")
	}
	if parsed.Timestamp <= 0 {
		return fmt.Errorf("nitro quote missing timestamp")
	}
	if parsed.Digest == "" {
		return fmt.Errorf("nitro quote missing digest")
	}
	if len(parsed.PCRs) == 0 {
		return fmt.Errorf("nitro quote missing PCRs")
	}
	for _, pcr := range parsed.PCRs {
		if len(pcr.Value) == 0 {
			return fmt.Errorf("nitro quote PCR value missing")
		}
	}
	if len(parsed.UserData) == 0 {
		return fmt.Errorf("nitro quote missing user_data")
	}
	if len(parsed.Nonce) == 0 {
		return fmt.Errorf("nitro quote missing nonce")
	}
	if len(userData) > 0 && !bytes.Equal(parsed.UserData, userData) {
		return fmt.Errorf("nitro quote user_data mismatch")
	}
	if len(nonce) > 0 && !bytes.Equal(parsed.Nonce, nonce) {
		return fmt.Errorf("nitro quote nonce mismatch")
	}
	return nil
}

func validateDCAPQuoteHeader(quote []byte) error {
	if len(quote) < sgxQuoteHeaderLen {
		return fmt.Errorf("sgx/tdx quote too short: %d bytes", len(quote))
	}
	version := binary.LittleEndian.Uint16(quote[0:2])
	if version != 3 && version != 4 {
		return fmt.Errorf("unsupported sgx/tdx quote version: %d", version)
	}
	return nil
}
