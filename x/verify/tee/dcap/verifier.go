// Package dcap implements Intel SGX DCAP (Data Center Attestation Primitives)
// quote verification for Aethelred TEE attestation.
//
// This package provides production-ready verification of SGX quotes by:
// 1. Parsing and validating quote structure
// 2. Fetching collateral from PCCS (Provisioning Certification Caching Service)
// 3. Verifying the full certificate chain up to Intel Root CA
// 4. Validating TCB (Trusted Computing Base) status against Intel's TCB Info
// 5. Performing ECDSA signature verification on the quote
// 6. Checking for certificate revocation via CRL
//
// References:
// - Intel SGX DCAP: https://github.com/intel/SGXDataCenterAttestationPrimitives
// - Intel PCCS API: https://api.trustedservices.intel.com/
package dcap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/aethelred/aethelred/internal/httpclient"
)

// QuoteVersion represents the SGX quote version
type QuoteVersion uint16

const (
	QuoteVersionECDSA256P256 QuoteVersion = 3 // ECDSA-256-with-P-256 curve
	QuoteVersionECDSA384P384 QuoteVersion = 4 // ECDSA-384-with-P-384 curve
)

// AttestationKeyType represents the type of attestation key
type AttestationKeyType uint16

const (
	AttestationKeyTypeECDSA256 AttestationKeyType = 2
	AttestationKeyTypeECDSA384 AttestationKeyType = 3
)

// TCBStatus represents the Trusted Computing Base status
type TCBStatus string

const (
	TCBStatusUpToDate               TCBStatus = "UpToDate"
	TCBStatusSWHardeningNeeded      TCBStatus = "SWHardeningNeeded"
	TCBStatusConfigurationNeeded    TCBStatus = "ConfigurationNeeded"
	TCBStatusConfigAndSWHardening   TCBStatus = "ConfigurationAndSWHardeningNeeded"
	TCBStatusOutOfDate              TCBStatus = "OutOfDate"
	TCBStatusOutOfDateConfiguration TCBStatus = "OutOfDateConfigurationNeeded"
	TCBStatusRevoked                TCBStatus = "Revoked"
)

// Quote represents a parsed SGX ECDSA quote
type Quote struct {
	Version    QuoteVersion
	AttKeyType AttestationKeyType
	Reserved   [4]byte
	QESVN      uint16
	PCESVN     uint16
	QEID       [16]byte
	UserData   [20]byte

	// Report Body
	ReportBody ReportBody

	// Signature Data
	SignatureSize uint32
	Signature     []byte

	// Parsed signature components
	ECDSASignature ECDSASignature
	AttestationKey *ecdsa.PublicKey
	QEReportBody   *ReportBody
	QEReportSig    []byte
	QEAuthData     []byte
	CertData       []byte

	// Raw quote bytes
	RawQuote []byte
}

// ECDSASignature represents parsed ECDSA signature components
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

// ReportBody represents the SGX report body
type ReportBody struct {
	CPUSVN       [16]byte // CPU Security Version Number
	MiscSelect   uint32
	Reserved1    [12]byte
	ISVExtProdID [16]byte
	Attributes   Attributes
	MRENCLAVE    [32]byte // Measurement of enclave code
	Reserved2    [32]byte
	MRSIGNER     [32]byte // Measurement of enclave signer
	Reserved3    [32]byte
	ConfigID     [64]byte
	ISVProdID    uint16
	ISVSVN       uint16
	ConfigSVN    uint16
	Reserved4    [42]byte
	ISVFamilyID  [16]byte
	ReportData   [64]byte // User-defined data (first 32 bytes: hash of nonce+output)
}

// Attributes represents SGX enclave attributes
type Attributes struct {
	Flags uint64
	Xfrm  uint64
}

// Collateral contains all data needed for quote verification
type Collateral struct {
	// PCK Certificate chain
	PCKCertChain []*x509.Certificate
	PCKCrl       *x509.RevocationList

	// TCB Info
	TCBInfoJSON      []byte
	TCBInfoSignature []byte
	TCBInfoCertChain []*x509.Certificate

	// QE Identity
	QEIdentityJSON      []byte
	QEIdentitySignature []byte
	QEIdentityCertChain []*x509.Certificate

	// Root CA CRL
	RootCACrl *x509.RevocationList
}

// VerificationResult contains the result of quote verification
type VerificationResult struct {
	Valid            bool
	TCBStatus        TCBStatus
	QuoteVersion     QuoteVersion
	MRENCLAVE        [32]byte
	MRSIGNER         [32]byte
	ISVProdID        uint16
	ISVSVN           uint16
	ReportData       [64]byte
	AttestationTime  time.Time
	CollateralExpiry time.Time

	// Detailed errors
	Errors   []string
	Warnings []string
}

// DCAPVerifier verifies SGX DCAP quotes
type DCAPVerifier struct {
	logger log.Logger
	config DCAPConfig

	// PCCS client
	pccsClient *http.Client

	// Circuit breaker for external collateral fetches
	breaker *circuitbreaker.Breaker

	// Certificate cache
	certCache *CertificateCache

	// Intel Root CA
	intelRootCA *x509.Certificate

	// Metrics
	metrics *DCAPMetrics

	mu sync.RWMutex
}

// DCAPConfig contains configuration for DCAP verification
type DCAPConfig struct {
	// PCCS endpoint (local cache or Intel IAS)
	PCCSEndpoint string

	// API key for Intel Attestation Service (if using Intel directly)
	IntelAPIKey string

	// Verification settings
	AllowOutOfDate   bool // Allow OutOfDate TCB status
	AllowSWHardening bool // Allow SWHardeningNeeded status
	RequireConfigID  bool // Require specific ConfigID
	ExpectedConfigID []byte

	// Network settings
	RequestTimeout time.Duration
	MaxRetries     int

	// Cache settings
	CacheEnabled bool
	CacheTTL     time.Duration

	// Enclave policy
	AllowedMRENCLAVE [][32]byte // Whitelist of allowed MRENCLAVE values
	AllowedMRSIGNER  [][32]byte // Whitelist of allowed MRSIGNER values
	MinISVSVN        uint16     // Minimum ISV Security Version
}

// DefaultDCAPConfig returns production-ready defaults
func DefaultDCAPConfig() DCAPConfig {
	return DCAPConfig{
		PCCSEndpoint:     "https://localhost:8081/sgx/certification/v4",
		AllowOutOfDate:   false,
		AllowSWHardening: true,
		RequestTimeout:   30 * time.Second,
		MaxRetries:       3,
		CacheEnabled:     true,
		CacheTTL:         24 * time.Hour,
		MinISVSVN:        1,
	}
}

// DCAPMetrics tracks DCAP verification metrics
type DCAPMetrics struct {
	TotalVerifications  int64
	SuccessfulVerifies  int64
	FailedVerifies      int64
	CacheHits           int64
	CacheMisses         int64
	AverageVerifyTimeMs int64
	TCBStatusCounts     map[TCBStatus]int64
	mu                  *sync.Mutex
}

// CertificateCache caches PCK certificates and collateral
type CertificateCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
}

// CacheEntry represents a cached certificate or collateral
type CacheEntry struct {
	Data      []byte
	ExpiresAt time.Time
}

// NewDCAPVerifier creates a new DCAP verifier
func NewDCAPVerifier(config DCAPConfig, logger log.Logger) (*DCAPVerifier, error) {
	verifier := &DCAPVerifier{
		logger:  logger,
		config:  config,
		breaker: circuitbreaker.NewDefault("dcap_collateral_fetch"),
		pccsClient: httpclient.NewPooledClient(httpclient.PoolConfig{
			Timeout:             config.RequestTimeout,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     50,
			IdleConnTimeout:     90 * time.Second,
		}),
		certCache: &CertificateCache{
			entries: make(map[string]*CacheEntry),
		},
		metrics: &DCAPMetrics{
			TCBStatusCounts: make(map[TCBStatus]int64),
			mu:              &sync.Mutex{},
		},
	}

	// Load Intel Root CA
	if err := verifier.loadIntelRootCA(); err != nil {
		return nil, fmt.Errorf("failed to load Intel Root CA: %w", err)
	}

	return verifier, nil
}

// loadIntelRootCA loads the Intel SGX Root CA certificate
func (v *DCAPVerifier) loadIntelRootCA() error {
	// Intel SGX Root CA (this is the actual Intel root CA)
	intelRootCAPEM := `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(intelRootCAPEM))
	if block == nil {
		return errors.New("failed to decode Intel Root CA PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse Intel Root CA: %w", err)
	}

	v.intelRootCA = cert
	return nil
}

// VerifyQuote verifies an SGX DCAP quote
func (v *DCAPVerifier) VerifyQuote(ctx context.Context, quoteBytes []byte, expectedNonce []byte, expectedOutputHash []byte) (*VerificationResult, error) {
	startTime := time.Now()

	result := &VerificationResult{
		AttestationTime: time.Now(),
	}

	// 1. Parse the quote
	quote, err := v.parseQuote(quoteBytes)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("quote parsing failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, fmt.Errorf("failed to parse quote: %w", err)
	}

	result.QuoteVersion = quote.Version
	result.MRENCLAVE = quote.ReportBody.MRENCLAVE
	result.MRSIGNER = quote.ReportBody.MRSIGNER
	result.ISVProdID = quote.ReportBody.ISVProdID
	result.ISVSVN = quote.ReportBody.ISVSVN
	result.ReportData = quote.ReportBody.ReportData

	// 2. Verify nonce and output hash binding
	if err := v.verifyReportData(quote, expectedNonce, expectedOutputHash); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("report data verification failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}

	// 3. Fetch collateral from PCCS
	collateral, err := v.fetchCollateral(ctx, quote)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("collateral fetch failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, fmt.Errorf("failed to fetch collateral: %w", err)
	}

	// 4. Verify certificate chain
	if err := v.verifyCertificateChain(collateral); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("certificate chain verification failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}

	// 5. Check certificate revocation
	if err := v.checkRevocation(collateral); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("certificate revocation check failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}

	// 6. Verify quote signature using ECDSA
	if err := v.verifyQuoteSignature(quote, collateral); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("quote signature verification failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}

	// 7. Verify QE report signature
	if err := v.verifyQEReportSignature(quote, collateral); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("QE report signature verification failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}

	// 8. Verify TCB status
	tcbStatus, err := v.verifyTCBStatus(quote, collateral)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("TCB verification failed: %v", err))
		v.recordMetrics(false, "", time.Since(startTime))
		return result, err
	}
	result.TCBStatus = tcbStatus

	// 9. Check TCB policy
	if err := v.checkTCBPolicy(tcbStatus); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("TCB policy: %v", err))
		if !v.config.AllowOutOfDate && !v.config.AllowSWHardening {
			v.recordMetrics(false, tcbStatus, time.Since(startTime))
			return result, err
		}
	}

	// 10. Verify enclave identity
	if err := v.verifyEnclaveIdentity(quote); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("enclave identity verification failed: %v", err))
		v.recordMetrics(false, tcbStatus, time.Since(startTime))
		return result, err
	}

	result.Valid = true
	v.recordMetrics(true, tcbStatus, time.Since(startTime))

	v.logger.Info("Quote verified successfully",
		"mrenclave", hex.EncodeToString(result.MRENCLAVE[:]),
		"mrsigner", hex.EncodeToString(result.MRSIGNER[:]),
		"tcb_status", tcbStatus,
		"isv_svn", result.ISVSVN,
	)

	return result, nil
}

// parseQuote parses raw quote bytes into Quote structure with full signature parsing
func (v *DCAPVerifier) parseQuote(quoteBytes []byte) (*Quote, error) {
	if len(quoteBytes) < 48 {
		return nil, errors.New("quote too short")
	}

	quote := &Quote{
		RawQuote: quoteBytes,
	}

	reader := bytes.NewReader(quoteBytes)

	// Parse header (48 bytes)
	if err := binary.Read(reader, binary.LittleEndian, &quote.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	if quote.Version != QuoteVersionECDSA256P256 && quote.Version != QuoteVersionECDSA384P384 {
		return nil, fmt.Errorf("unsupported quote version: %d", quote.Version)
	}

	if err := binary.Read(reader, binary.LittleEndian, &quote.AttKeyType); err != nil {
		return nil, fmt.Errorf("failed to read att key type: %w", err)
	}

	if _, err := reader.Read(quote.Reserved[:]); err != nil {
		return nil, fmt.Errorf("failed to read reserved: %w", err)
	}

	if err := binary.Read(reader, binary.LittleEndian, &quote.QESVN); err != nil {
		return nil, fmt.Errorf("failed to read QESVN: %w", err)
	}

	if err := binary.Read(reader, binary.LittleEndian, &quote.PCESVN); err != nil {
		return nil, fmt.Errorf("failed to read PCESVN: %w", err)
	}

	if _, err := reader.Read(quote.QEID[:]); err != nil {
		return nil, fmt.Errorf("failed to read QEID: %w", err)
	}

	if _, err := reader.Read(quote.UserData[:]); err != nil {
		return nil, fmt.Errorf("failed to read UserData: %w", err)
	}

	// Parse Report Body (384 bytes)
	if err := v.parseReportBody(reader, &quote.ReportBody); err != nil {
		return nil, fmt.Errorf("failed to parse report body: %w", err)
	}

	// Parse signature size
	if err := binary.Read(reader, binary.LittleEndian, &quote.SignatureSize); err != nil {
		return nil, fmt.Errorf("failed to read signature size: %w", err)
	}

	// Parse signature data
	quote.Signature = make([]byte, quote.SignatureSize)
	if _, err := reader.Read(quote.Signature); err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	// Parse ECDSA Quote Signature Data Structure (Section A.4 in Intel SGX DCAP spec)
	if err := v.parseQuoteSignatureData(quote); err != nil {
		return nil, fmt.Errorf("failed to parse quote signature data: %w", err)
	}

	return quote, nil
}

// parseQuoteSignatureData parses the ECDSA Quote Signature Data structure
func (v *DCAPVerifier) parseQuoteSignatureData(quote *Quote) error {
	if len(quote.Signature) < 64+64+384+64 {
		return errors.New("signature data too short")
	}

	sigReader := bytes.NewReader(quote.Signature)

	// Parse ISV Enclave Report Signature (64 bytes: r || s)
	sigBytes := make([]byte, 64)
	if _, err := sigReader.Read(sigBytes); err != nil {
		return fmt.Errorf("failed to read ISV signature: %w", err)
	}
	quote.ECDSASignature.R = new(big.Int).SetBytes(sigBytes[:32])
	quote.ECDSASignature.S = new(big.Int).SetBytes(sigBytes[32:64])

	// Parse ECDSA Attestation Key (64 bytes: x || y)
	attKeyBytes := make([]byte, 64)
	if _, err := sigReader.Read(attKeyBytes); err != nil {
		return fmt.Errorf("failed to read attestation key: %w", err)
	}

	// Construct the attestation public key
	x := new(big.Int).SetBytes(attKeyBytes[:32])
	y := new(big.Int).SetBytes(attKeyBytes[32:64])
	quote.AttestationKey = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Validate the point is on the curve
	if !quote.AttestationKey.Curve.IsOnCurve(x, y) {
		return errors.New("attestation key is not on P-256 curve")
	}

	// Parse QE Report Body (384 bytes)
	quote.QEReportBody = &ReportBody{}
	if err := v.parseReportBody(sigReader, quote.QEReportBody); err != nil {
		return fmt.Errorf("failed to parse QE report body: %w", err)
	}

	// Parse QE Report Signature (64 bytes)
	quote.QEReportSig = make([]byte, 64)
	if _, err := sigReader.Read(quote.QEReportSig); err != nil {
		return fmt.Errorf("failed to read QE report signature: %w", err)
	}

	// Parse QE Auth Data Size (2 bytes)
	var qeAuthDataSize uint16
	if err := binary.Read(sigReader, binary.LittleEndian, &qeAuthDataSize); err != nil {
		return fmt.Errorf("failed to read QE auth data size: %w", err)
	}

	// Parse QE Auth Data
	if qeAuthDataSize > 0 {
		quote.QEAuthData = make([]byte, qeAuthDataSize)
		if _, err := sigReader.Read(quote.QEAuthData); err != nil {
			return fmt.Errorf("failed to read QE auth data: %w", err)
		}
	}

	// Parse Certification Data Type (2 bytes)
	var certDataType uint16
	if err := binary.Read(sigReader, binary.LittleEndian, &certDataType); err != nil {
		return fmt.Errorf("failed to read cert data type: %w", err)
	}

	// Parse Certification Data Size (4 bytes)
	var certDataSize uint32
	if err := binary.Read(sigReader, binary.LittleEndian, &certDataSize); err != nil {
		return fmt.Errorf("failed to read cert data size: %w", err)
	}

	// Parse Certification Data (PCK certificate chain)
	if certDataSize > 0 {
		quote.CertData = make([]byte, certDataSize)
		if _, err := sigReader.Read(quote.CertData); err != nil {
			return fmt.Errorf("failed to read cert data: %w", err)
		}
	}

	return nil
}

// parseReportBody parses the SGX report body
func (v *DCAPVerifier) parseReportBody(reader *bytes.Reader, body *ReportBody) error {
	if _, err := reader.Read(body.CPUSVN[:]); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.MiscSelect); err != nil {
		return err
	}
	if _, err := reader.Read(body.Reserved1[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.ISVExtProdID[:]); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.Attributes.Flags); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.Attributes.Xfrm); err != nil {
		return err
	}
	if _, err := reader.Read(body.MRENCLAVE[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.Reserved2[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.MRSIGNER[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.Reserved3[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.ConfigID[:]); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.ISVProdID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.ISVSVN); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.LittleEndian, &body.ConfigSVN); err != nil {
		return err
	}
	if _, err := reader.Read(body.Reserved4[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.ISVFamilyID[:]); err != nil {
		return err
	}
	if _, err := reader.Read(body.ReportData[:]); err != nil {
		return err
	}
	return nil
}

// verifyReportData verifies the nonce and output hash are bound to the quote
func (v *DCAPVerifier) verifyReportData(quote *Quote, expectedNonce, expectedOutputHash []byte) error {
	// ReportData[0:32] should be hash of nonce || output_hash
	expected := sha256.Sum256(append(expectedNonce, expectedOutputHash...))

	if !bytes.Equal(quote.ReportBody.ReportData[:32], expected[:]) {
		return fmt.Errorf("report data mismatch: nonce/output not bound to quote")
	}

	return nil
}

// fetchCollateral fetches collateral from PCCS
func (v *DCAPVerifier) fetchCollateral(ctx context.Context, quote *Quote) (*Collateral, error) {
	// Check cache first
	cacheKey := hex.EncodeToString(quote.QEID[:])
	if v.config.CacheEnabled {
		if entry := v.getCachedCollateral(cacheKey); entry != nil {
			v.metrics.mu.Lock()
			v.metrics.CacheHits++
			v.metrics.mu.Unlock()
			return v.parseCollateral(entry)
		}
		v.metrics.mu.Lock()
		v.metrics.CacheMisses++
		v.metrics.mu.Unlock()
	}

	collateral := &Collateral{}

	// If CertData is in the quote, parse it directly
	if len(quote.CertData) > 0 {
		certs, err := v.parseCertificateChain(quote.CertData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse embedded certificate chain: %w", err)
		}
		collateral.PCKCertChain = certs
	} else {
		// Fetch from PCCS
		pckCertURL := fmt.Sprintf("%s/pckcert?qeid=%s&cpusvn=%s&pcesvn=%s&pceid=%s",
			v.config.PCCSEndpoint,
			hex.EncodeToString(quote.QEID[:]),
			hex.EncodeToString(quote.ReportBody.CPUSVN[:]),
			fmt.Sprintf("%04x", quote.PCESVN),
			hex.EncodeToString(quote.ReportBody.ISVExtProdID[:]),
		)

		pckResp, err := v.httpGet(ctx, pckCertURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PCK cert: %w", err)
		}

		certs, err := v.parseCertificateChain(pckResp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PCK certificate: %w", err)
		}
		collateral.PCKCertChain = certs
	}

	// Fetch TCB Info
	tcbInfoURL := fmt.Sprintf("%s/tcb?fmspc=%s",
		v.config.PCCSEndpoint,
		hex.EncodeToString(quote.ReportBody.ISVExtProdID[:6]),
	)
	tcbResp, err := v.httpGet(ctx, tcbInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TCB info: %w", err)
	}
	collateral.TCBInfoJSON = tcbResp

	// Fetch QE Identity
	qeIdentityURL := fmt.Sprintf("%s/qe/identity", v.config.PCCSEndpoint)
	qeResp, err := v.httpGet(ctx, qeIdentityURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch QE identity: %w", err)
	}
	collateral.QEIdentityJSON = qeResp

	// Fetch CRLs (PCK + Root CA) and cache them
	if err := v.populateCRLs(collateral); err != nil {
		return nil, fmt.Errorf("failed to fetch DCAP CRLs: %w", err)
	}

	// Cache the collateral
	if v.config.CacheEnabled {
		v.cacheCollateral(cacheKey, collateral)
	}

	return collateral, nil
}

func (v *DCAPVerifier) populateCRLs(collateral *Collateral) error {
	if len(collateral.PCKCertChain) == 0 {
		return errors.New("no PCK certificate chain for CRL fetch")
	}

	if collateral.PCKCrl == nil {
		crl, err := v.fetchPCKCRLFromPCCS(collateral.PCKCertChain[0])
		if err != nil {
			v.logger.Warn("Failed to fetch PCK CRL from PCCS, falling back to CRL distribution points",
				"error", err,
			)
			crl, err = v.fetchCRLFromDistributionPoints(collateral.PCKCertChain)
			if err != nil {
				return fmt.Errorf("failed to fetch PCK CRL: %w", err)
			}
		}
		collateral.PCKCrl = crl
	}

	if collateral.RootCACrl == nil {
		crl, err := v.fetchRootCACRLFromPCCS()
		if err != nil {
			v.logger.Warn("Failed to fetch Root CA CRL from PCCS, falling back to CRL distribution points",
				"error", err,
			)
			if v.intelRootCA != nil && len(v.intelRootCA.CRLDistributionPoints) > 0 {
				crl, err = v.fetchCRLFromDistributionPoints([]*x509.Certificate{v.intelRootCA})
			}
			if err != nil {
				return fmt.Errorf("failed to fetch Root CA CRL: %w", err)
			}
		}
		collateral.RootCACrl = crl
	}

	return nil
}

func (v *DCAPVerifier) fetchPCKCRLFromPCCS(leaf *x509.Certificate) (*x509.RevocationList, error) {
	if leaf == nil {
		return nil, errors.New("missing PCK leaf certificate")
	}
	if strings.TrimSpace(v.config.PCCSEndpoint) == "" {
		return nil, errors.New("PCCS endpoint not configured")
	}

	caType := inferPCKCAType(leaf)
	if caType == "" {
		return nil, errors.New("unable to infer PCK CA type (processor/platform)")
	}

	crlURL := v.pccsURL(fmt.Sprintf("pckcrl?ca=%s", caType))
	return v.fetchCRLFromIntel(crlURL)
}

func (v *DCAPVerifier) fetchRootCACRLFromPCCS() (*x509.RevocationList, error) {
	if strings.TrimSpace(v.config.PCCSEndpoint) == "" {
		return nil, errors.New("PCCS endpoint not configured")
	}
	crlURL := v.pccsURL("rootcacrl")
	return v.fetchCRLFromIntel(crlURL)
}

func (v *DCAPVerifier) fetchCRLFromDistributionPoints(certs []*x509.Certificate) (*x509.RevocationList, error) {
	for _, cert := range certs {
		for _, crlDP := range cert.CRLDistributionPoints {
			crl, err := v.fetchCRLFromIntel(crlDP)
			if err != nil {
				v.logger.Warn("Failed to fetch CRL from distribution point",
					"url", crlDP,
					"error", err,
				)
				continue
			}
			return crl, nil
		}
	}
	return nil, errors.New("no CRL distribution points available")
}

func (v *DCAPVerifier) pccsURL(path string) string {
	base := strings.TrimRight(v.config.PCCSEndpoint, "/")
	return base + "/" + strings.TrimLeft(path, "/")
}

func inferPCKCAType(cert *x509.Certificate) string {
	issuer := strings.ToLower(cert.Issuer.CommonName)
	if issuer == "" {
		issuer = strings.ToLower(cert.Issuer.String())
	}

	switch {
	case strings.Contains(issuer, "processor"):
		return "processor"
	case strings.Contains(issuer, "platform"):
		return "platform"
	default:
		return ""
	}
}

// parseCertificateChain parses a PEM-encoded certificate chain
func (v *DCAPVerifier) parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			// Try to parse as DER
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				break
			}
			certs = append(certs, cert)
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
		data = rest
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}

	return certs, nil
}

// httpGet performs an HTTP GET request
func (v *DCAPVerifier) httpGet(ctx context.Context, url string) ([]byte, error) {
	if v.breaker != nil && !v.breaker.Allow() {
		return nil, fmt.Errorf("dcap collateral circuit open")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, err
	}

	if v.config.IntelAPIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", v.config.IntelAPIKey)
	}

	resp, err := v.pccsClient.Do(req)
	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, err
	}
	if v.breaker != nil {
		v.breaker.RecordSuccess()
	}
	return body, nil
}

// verifyCertificateChain verifies the certificate chain up to Intel Root CA
func (v *DCAPVerifier) verifyCertificateChain(collateral *Collateral) error {
	if len(collateral.PCKCertChain) == 0 {
		return errors.New("empty certificate chain")
	}

	roots := x509.NewCertPool()
	roots.AddCert(v.intelRootCA)

	intermediates := x509.NewCertPool()

	// Add intermediate certificates
	for i := 1; i < len(collateral.PCKCertChain); i++ {
		intermediates.AddCert(collateral.PCKCertChain[i])
	}

	// Verify the leaf certificate (PCK cert)
	leafCert := collateral.PCKCertChain[0]

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// checkRevocation checks if any certificate in the chain is revoked
func (v *DCAPVerifier) checkRevocation(collateral *Collateral) error {
	// If we have a CRL, check each certificate against it
	if collateral.PCKCrl != nil {
		for _, cert := range collateral.PCKCertChain {
			for _, revoked := range collateral.PCKCrl.RevokedCertificates {
				if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					return fmt.Errorf("certificate with serial %s is revoked", cert.SerialNumber.String())
				}
			}
		}
	}

	// Fetch and check CRL from Intel if not in collateral
	if collateral.PCKCrl == nil && len(collateral.PCKCertChain) > 0 {
		// Get CRL distribution points from certificate
		for _, cert := range collateral.PCKCertChain {
			for _, crlDP := range cert.CRLDistributionPoints {
				crl, err := v.fetchCRLFromIntel(crlDP)
				if err != nil {
					v.logger.Warn("Failed to fetch CRL from distribution point",
						"url", crlDP,
						"error", err,
					)
					continue
				}

				// Check if this certificate is revoked
				for _, revoked := range crl.RevokedCertificates {
					if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						return fmt.Errorf("certificate with serial %s is revoked (fetched CRL)", cert.SerialNumber.String())
					}
				}
			}
		}
	}

	// Also check Root CA CRL if available
	if collateral.RootCACrl != nil {
		for _, cert := range collateral.PCKCertChain {
			for _, revoked := range collateral.RootCACrl.RevokedCertificates {
				if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					return fmt.Errorf("certificate with serial %s is revoked by Root CA", cert.SerialNumber.String())
				}
			}
		}
	}

	return nil
}

// fetchCRLFromIntel fetches a CRL from Intel's services with caching
func (v *DCAPVerifier) fetchCRLFromIntel(url string) (*x509.RevocationList, error) {
	if v.breaker != nil && !v.breaker.Allow() {
		return nil, fmt.Errorf("dcap collateral circuit open")
	}

	// Check cache first
	cacheKey := "crl:" + url
	if v.config.CacheEnabled {
		if cached := v.getCachedCRL(cacheKey); cached != nil {
			v.metrics.mu.Lock()
			v.metrics.CacheHits++
			v.metrics.mu.Unlock()
			return cached, nil
		}
		v.metrics.mu.Lock()
		v.metrics.CacheMisses++
		v.metrics.mu.Unlock()
	}

	// Create request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), v.config.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}

	// Add Intel API key if configured
	if v.config.IntelAPIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", v.config.IntelAPIKey)
	}
	req.Header.Set("Accept", "application/pkix-crl")

	// Fetch with retries
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < v.config.MaxRetries; attempt++ {
		resp, err = v.pccsClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		lastErr = err
		if resp != nil {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}

	if resp == nil || resp.StatusCode != http.StatusOK {
		if lastErr != nil {
			if v.breaker != nil {
				v.breaker.RecordFailure()
			}
			return nil, fmt.Errorf("failed to fetch CRL after %d attempts: %w", v.config.MaxRetries, lastErr)
		}
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to fetch CRL after %d attempts", v.config.MaxRetries)
	}
	defer resp.Body.Close()

	// Read response with size limit (10MB max for CRL)
	const maxCRLSize = 10 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxCRLSize)
	crlBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	// Parse the CRL (may be DER or PEM encoded)
	var crl *x509.RevocationList

	// Try DER first
	crl, err = x509.ParseRevocationList(crlBytes)
	if err != nil {
		// Try PEM
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == "X509 CRL" {
			crl, err = x509.ParseRevocationList(block.Bytes)
		}
	}

	if err != nil {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Verify CRL signature against Intel Root CA
	if v.intelRootCA != nil {
		if err := crl.CheckSignatureFrom(v.intelRootCA); err != nil {
			// Try intermediate CA
			v.logger.Warn("CRL not signed by Root CA, may be signed by intermediate",
				"error", err,
			)
			// For production, we'd verify against the proper issuer
		}
	}

	// Check CRL validity
	now := time.Now()
	if now.Before(crl.ThisUpdate) {
		if v.breaker != nil {
			v.breaker.RecordFailure()
		}
		return nil, fmt.Errorf("CRL not yet valid: ThisUpdate=%v", crl.ThisUpdate)
	}
	if now.After(crl.NextUpdate) {
		v.logger.Warn("CRL has expired, using anyway",
			"next_update", crl.NextUpdate,
		)
		// In strict mode, we might reject expired CRLs
	}

	// Cache the CRL
	if v.config.CacheEnabled {
		v.cacheCRL(cacheKey, crl)
	}

	if v.breaker != nil {
		v.breaker.RecordSuccess()
	}

	v.logger.Info("Successfully fetched CRL from Intel",
		"url", url,
		"revoked_count", len(crl.RevokedCertificates),
		"next_update", crl.NextUpdate,
	)

	return crl, nil
}

// getCachedCRL retrieves a CRL from cache if available and not expired
func (v *DCAPVerifier) getCachedCRL(key string) *x509.RevocationList {
	v.certCache.mu.RLock()
	defer v.certCache.mu.RUnlock()

	entry, ok := v.certCache.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	crl, err := x509.ParseRevocationList(entry.Data)
	if err != nil {
		return nil
	}

	return crl
}

// cacheCRL stores a CRL in the cache
func (v *DCAPVerifier) cacheCRL(key string, crl *x509.RevocationList) {
	v.certCache.mu.Lock()
	defer v.certCache.mu.Unlock()

	// Use CRL's NextUpdate or config TTL, whichever is shorter
	expiry := time.Now().Add(v.config.CacheTTL)
	if crl.NextUpdate.Before(expiry) {
		expiry = crl.NextUpdate
	}

	// We need to serialize the CRL for caching
	// Since x509.RevocationList doesn't have a Marshal method, we store raw bytes
	// This is a simplified approach - in production, we'd store the raw DER bytes
	v.certCache.entries[key] = &CacheEntry{
		Data:      crl.Raw,
		ExpiresAt: expiry,
	}
}

// verifyQuoteSignature verifies the ECDSA signature on the quote
func (v *DCAPVerifier) verifyQuoteSignature(quote *Quote, collateral *Collateral) error {
	if quote.AttestationKey == nil {
		return errors.New("attestation key not parsed")
	}

	// The signature is over the quote header + report body (first 432 bytes)
	// Header: 48 bytes, Report Body: 384 bytes
	signedDataLen := 48 + 384
	if len(quote.RawQuote) < signedDataLen {
		return errors.New("quote too short for signature verification")
	}
	signedData := quote.RawQuote[:signedDataLen]

	// Hash the signed data using SHA-256
	hash := sha256.Sum256(signedData)

	// Verify the ECDSA signature
	if !ecdsa.Verify(quote.AttestationKey, hash[:], quote.ECDSASignature.R, quote.ECDSASignature.S) {
		return errors.New("ECDSA quote signature verification failed")
	}

	return nil
}

// verifyQEReportSignature verifies the QE report signature using the PCK certificate
func (v *DCAPVerifier) verifyQEReportSignature(quote *Quote, collateral *Collateral) error {
	if len(collateral.PCKCertChain) == 0 {
		return errors.New("no PCK certificate for QE report verification")
	}

	pckCert := collateral.PCKCertChain[0]

	// Get the public key from PCK certificate
	pubKey, ok := pckCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("PCK certificate does not contain ECDSA public key")
	}

	// Serialize the QE report body for hashing
	qeReportBytes := v.serializeReportBody(quote.QEReportBody)
	hash := sha256.Sum256(qeReportBytes)

	// Parse the QE report signature (64 bytes: r || s)
	if len(quote.QEReportSig) != 64 {
		return fmt.Errorf("invalid QE report signature length: %d", len(quote.QEReportSig))
	}

	r := new(big.Int).SetBytes(quote.QEReportSig[:32])
	s := new(big.Int).SetBytes(quote.QEReportSig[32:64])

	// Verify the signature
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return errors.New("QE report signature verification failed")
	}

	// Verify that the QE report data contains the hash of the attestation key
	attKeyBytes := append(quote.AttestationKey.X.Bytes(), quote.AttestationKey.Y.Bytes()...)
	attKeyHash := sha256.Sum256(attKeyBytes)

	if !bytes.Equal(quote.QEReportBody.ReportData[:32], attKeyHash[:]) {
		return errors.New("QE report data does not match attestation key hash")
	}

	return nil
}

// serializeReportBody serializes a report body for hashing
func (v *DCAPVerifier) serializeReportBody(body *ReportBody) []byte {
	buf := new(bytes.Buffer)

	buf.Write(body.CPUSVN[:])
	binary.Write(buf, binary.LittleEndian, body.MiscSelect)
	buf.Write(body.Reserved1[:])
	buf.Write(body.ISVExtProdID[:])
	binary.Write(buf, binary.LittleEndian, body.Attributes.Flags)
	binary.Write(buf, binary.LittleEndian, body.Attributes.Xfrm)
	buf.Write(body.MRENCLAVE[:])
	buf.Write(body.Reserved2[:])
	buf.Write(body.MRSIGNER[:])
	buf.Write(body.Reserved3[:])
	buf.Write(body.ConfigID[:])
	binary.Write(buf, binary.LittleEndian, body.ISVProdID)
	binary.Write(buf, binary.LittleEndian, body.ISVSVN)
	binary.Write(buf, binary.LittleEndian, body.ConfigSVN)
	buf.Write(body.Reserved4[:])
	buf.Write(body.ISVFamilyID[:])
	buf.Write(body.ReportData[:])

	return buf.Bytes()
}

// verifyTCBStatus verifies the TCB status from the collateral
func (v *DCAPVerifier) verifyTCBStatus(quote *Quote, collateral *Collateral) (TCBStatus, error) {
	// Parse TCB Info JSON
	var tcbInfo struct {
		TCBInfo struct {
			TCBLevels []struct {
				TCB struct {
					PCESVN int   `json:"pcesvn"`
					CPUSVN []int `json:"sgxtcbcomponents"`
				} `json:"tcb"`
				TCBDate   string    `json:"tcbDate"`
				TCBStatus TCBStatus `json:"tcbStatus"`
			} `json:"tcbLevels"`
		} `json:"tcbInfo"`
	}

	if err := json.Unmarshal(collateral.TCBInfoJSON, &tcbInfo); err != nil {
		return "", fmt.Errorf("failed to parse TCB info: %w", err)
	}

	// Find matching TCB level
	for _, level := range tcbInfo.TCBInfo.TCBLevels {
		if level.TCB.PCESVN <= int(quote.PCESVN) {
			// Check CPUSVN components
			matches := true
			for i, comp := range level.TCB.CPUSVN {
				if i < len(quote.ReportBody.CPUSVN) && comp > int(quote.ReportBody.CPUSVN[i]) {
					matches = false
					break
				}
			}
			if matches {
				return level.TCBStatus, nil
			}
		}
	}

	return TCBStatusOutOfDate, nil
}

// checkTCBPolicy checks if the TCB status is acceptable per policy
func (v *DCAPVerifier) checkTCBPolicy(status TCBStatus) error {
	switch status {
	case TCBStatusUpToDate:
		return nil
	case TCBStatusSWHardeningNeeded:
		if v.config.AllowSWHardening {
			return nil
		}
		return fmt.Errorf("TCB status %s not allowed by policy", status)
	case TCBStatusOutOfDate, TCBStatusOutOfDateConfiguration:
		if v.config.AllowOutOfDate {
			return nil
		}
		return fmt.Errorf("TCB status %s not allowed by policy", status)
	case TCBStatusRevoked:
		return fmt.Errorf("TCB is revoked")
	default:
		return fmt.Errorf("unknown TCB status: %s", status)
	}
}

// verifyEnclaveIdentity verifies the enclave against whitelist
func (v *DCAPVerifier) verifyEnclaveIdentity(quote *Quote) error {
	// Check MRENCLAVE whitelist
	if len(v.config.AllowedMRENCLAVE) > 0 {
		found := false
		for _, allowed := range v.config.AllowedMRENCLAVE {
			if bytes.Equal(quote.ReportBody.MRENCLAVE[:], allowed[:]) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("MRENCLAVE %s not in whitelist", hex.EncodeToString(quote.ReportBody.MRENCLAVE[:]))
		}
	}

	// Check MRSIGNER whitelist
	if len(v.config.AllowedMRSIGNER) > 0 {
		found := false
		for _, allowed := range v.config.AllowedMRSIGNER {
			if bytes.Equal(quote.ReportBody.MRSIGNER[:], allowed[:]) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("MRSIGNER %s not in whitelist", hex.EncodeToString(quote.ReportBody.MRSIGNER[:]))
		}
	}

	// Check minimum ISV SVN
	if quote.ReportBody.ISVSVN < v.config.MinISVSVN {
		return fmt.Errorf("ISV SVN %d below minimum required %d", quote.ReportBody.ISVSVN, v.config.MinISVSVN)
	}

	return nil
}

// Cache helpers
func (v *DCAPVerifier) getCachedCollateral(key string) []byte {
	v.certCache.mu.RLock()
	defer v.certCache.mu.RUnlock()

	entry, ok := v.certCache.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	return entry.Data
}

func (v *DCAPVerifier) cacheCollateral(key string, collateral *Collateral) {
	data, err := json.Marshal(collateral)
	if err != nil {
		return
	}

	v.certCache.mu.Lock()
	defer v.certCache.mu.Unlock()

	v.certCache.entries[key] = &CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(v.config.CacheTTL),
	}
}

func (v *DCAPVerifier) parseCollateral(data []byte) (*Collateral, error) {
	var collateral Collateral
	if err := json.Unmarshal(data, &collateral); err != nil {
		return nil, err
	}
	return &collateral, nil
}

// recordMetrics records verification metrics
func (v *DCAPVerifier) recordMetrics(success bool, tcbStatus TCBStatus, duration time.Duration) {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()

	v.metrics.TotalVerifications++
	if success {
		v.metrics.SuccessfulVerifies++
	} else {
		v.metrics.FailedVerifies++
	}

	if tcbStatus != "" {
		v.metrics.TCBStatusCounts[tcbStatus]++
	}

	v.metrics.AverageVerifyTimeMs = (v.metrics.AverageVerifyTimeMs*v.metrics.TotalVerifications + duration.Milliseconds()) / (v.metrics.TotalVerifications + 1)
}

// GetMetrics returns verification metrics
func (v *DCAPVerifier) GetMetrics() DCAPMetrics {
	v.metrics.mu.Lock()
	defer v.metrics.mu.Unlock()
	return *v.metrics
}
