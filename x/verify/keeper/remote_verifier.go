package keeper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aethelred/aethelred/x/verify/types"
)

// callRemoteZKVerifier calls an external zkML verifier service.
// SECURITY: Uses secure HTTP client with timeouts and size limits.
func (k Keeper) callRemoteZKVerifier(ctx context.Context, endpoint string, proof *types.ZKMLProof, vk *types.VerifyingKey) (bool, error) {
	if k.zkVerifierBreaker != nil && !k.zkVerifierBreaker.Allow() {
		return false, fmt.Errorf("zk verifier circuit open")
	}

	// SECURITY: Validate endpoint URL to prevent SSRF.
	if err := validateEndpointURL(endpoint); err != nil {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("invalid verifier endpoint: %w", err)
	}

	verifyURL := strings.TrimRight(endpoint, "/") + "/verify"
	payload := struct {
		Proof        *types.ZKMLProof    `json:"proof"`
		VerifyingKey *types.VerifyingKey `json:"verifying_key"`
	}{
		Proof:        proof,
		VerifyingKey: vk,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to marshal verifier payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, bytes.NewReader(body))
	if err != nil {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to create verifier request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Aethelred-Verifier/1.0")

	client := secureHTTPClientProvider()
	resp, err := client.Do(req)
	if err != nil {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		limitedBody := limitedReader(resp.Body, 4096)
		errorPayload, _ := io.ReadAll(limitedBody)
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verifier returned status %d: %s", resp.StatusCode, string(errorPayload))
	}

	limitedBody := limitedReader(resp.Body, maxResponseSize)
	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(limitedBody).Decode(&result); err != nil {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to decode verifier response: %w", err)
	}
	if result.Error != "" && !result.Verified {
		if k.zkVerifierBreaker != nil {
			k.zkVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("verification failed: %s", result.Error)
	}
	if k.zkVerifierBreaker != nil {
		k.zkVerifierBreaker.RecordSuccess()
	}
	return result.Verified, nil
}

// callRemoteAttestationVerifier calls an external TEE attestation verifier service.
// SECURITY: Uses secure HTTP client with timeouts and size limits.
func (k Keeper) callRemoteAttestationVerifier(ctx context.Context, endpoint string, attestation *types.TEEAttestation) (bool, error) {
	if k.attestationVerifierBreaker != nil && !k.attestationVerifierBreaker.Allow() {
		return false, fmt.Errorf("attestation verifier circuit open")
	}

	// SECURITY: Validate endpoint URL to prevent SSRF.
	if err := validateEndpointURL(endpoint); err != nil {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("invalid attestation endpoint: %w", err)
	}

	verifyURL := strings.TrimRight(endpoint, "/") + "/verify"
	body, err := json.Marshal(attestation)
	if err != nil {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to marshal attestation: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, bytes.NewReader(body))
	if err != nil {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to create attestation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Aethelred-Verifier/1.0")

	client := secureHTTPClientProvider()
	resp, err := client.Do(req)
	if err != nil {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("attestation verifier request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		limitedBody := limitedReader(resp.Body, 4096)
		errorPayload, _ := io.ReadAll(limitedBody)
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("attestation verifier returned status %d: %s", resp.StatusCode, string(errorPayload))
	}

	limitedBody := limitedReader(resp.Body, maxResponseSize)
	var result struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(limitedBody).Decode(&result); err != nil {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("failed to decode attestation verifier response: %w", err)
	}
	if result.Error != "" && !result.Verified {
		if k.attestationVerifierBreaker != nil {
			k.attestationVerifierBreaker.RecordFailure()
		}
		return false, fmt.Errorf("attestation verification failed: %s", result.Error)
	}
	if k.attestationVerifierBreaker != nil {
		k.attestationVerifierBreaker.RecordSuccess()
	}
	return result.Verified, nil
}
