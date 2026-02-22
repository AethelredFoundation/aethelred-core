package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"cosmossdk.io/log"
	"github.com/stretchr/testify/require"
)

type testShutdownComponent struct {
	name  string
	order *[]string
	err   error
}

func (c testShutdownComponent) Name() string { return c.name }

func (c testShutdownComponent) Shutdown(ctx context.Context) error {
	if c.order != nil {
		*c.order = append(*c.order, c.name)
	}
	return c.err
}

type closeRecorder struct {
	closed bool
	err    error
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return c.err
}

type flushRecorder struct {
	flushed bool
	err     error
}

func (f *flushRecorder) Flush() error {
	f.flushed = true
	return f.err
}

type stopRecorder struct{ stopped bool }

func (s *stopRecorder) Stop() { s.stopped = true }

type shutdownRecorder struct{ called bool }

func (s *shutdownRecorder) Shutdown() { s.called = true }

func TestShutdownManagerAndAdaptersCoverage(t *testing.T) {
	order := []string{}
	sm := NewShutdownManager(log.NewNopLogger(), ShutdownConfig{
		GracePeriod:      100 * time.Millisecond,
		ComponentTimeout: 50 * time.Millisecond,
		DrainTimeout:     1 * time.Millisecond,
	})

	require.False(t, sm.IsShuttingDown())
	sm.RegisterComponent(testShutdownComponent{name: "one", order: &order})
	sm.RegisterComponent(testShutdownComponent{name: "two", order: &order})
	require.NoError(t, sm.Shutdown(context.Background()))
	require.True(t, sm.IsShuttingDown())
	require.Equal(t, []string{"two", "one"}, order)

	select {
	case <-sm.ShutdownCh():
		// expected: channel is closed after shutdown starts
	default:
		t.Fatal("shutdown channel should be closed")
	}

	// Idempotent repeat should not fail.
	require.NoError(t, sm.Shutdown(context.Background()))

	cfg := DefaultShutdownConfig()
	require.Greater(t, cfg.GracePeriod, time.Duration(0))
	require.Greater(t, cfg.ComponentTimeout, time.Duration(0))
	require.Greater(t, cfg.DrainTimeout, time.Duration(0))

	hsmCloser := &closeRecorder{}
	hsm := &HSMShutdownAdapter{manager: hsmCloser}
	require.Equal(t, "HSM", hsm.Name())
	require.NoError(t, hsm.Shutdown(context.Background()))
	require.True(t, hsmCloser.closed)

	teeCloser := &closeRecorder{err: errors.New("close failed")}
	tee := &TEEClientShutdownAdapter{client: teeCloser}
	require.Equal(t, "TEEClient", tee.Name())
	require.Error(t, tee.Shutdown(context.Background()))
	require.True(t, teeCloser.closed)

	orchRec := &shutdownRecorder{}
	orch := &OrchestratorShutdownAdapter{orchestrator: orchRec}
	require.Equal(t, "VerificationOrchestrator", orch.Name())
	require.NoError(t, orch.Shutdown(context.Background()))
	require.True(t, orchRec.called)

	stopRec := &stopRecorder{}
	scheduler := &JobSchedulerShutdownAdapter{scheduler: stopRec}
	require.Equal(t, "JobScheduler", scheduler.Name())
	require.NoError(t, scheduler.Shutdown(context.Background()))
	require.True(t, stopRec.stopped)

	metricsRec := &flushRecorder{err: errors.New("flush failed")}
	metrics := &MetricsShutdownAdapter{flusher: metricsRec}
	require.Equal(t, "Metrics", metrics.Name())
	require.Error(t, metrics.Shutdown(context.Background()))
	require.True(t, metricsRec.flushed)
}

func TestStartupHelperEnvLogic(t *testing.T) {
	t.Setenv("AETHELRED_TEST_KEY", "")
	require.Equal(t, "fallback", getEnvOrDefault("AETHELRED_TEST_KEY", "fallback"))

	t.Setenv("AETHELRED_TEST_KEY", "configured")
	require.Equal(t, "configured", getEnvOrDefault("AETHELRED_TEST_KEY", "fallback"))

	t.Setenv("AETHELRED_ALLOW_SIMULATED", "true")
	t.Setenv("AETHELRED_TEE_MODE", "")
	t.Setenv("TEE_MODE", "")
	require.True(t, startupAllowsVerificationInitFailure())

	t.Setenv("AETHELRED_ALLOW_SIMULATED", "false")
	t.Setenv("AETHELRED_TEE_MODE", "nitro-simulated")
	require.True(t, startupAllowsVerificationInitFailure())

	t.Setenv("AETHELRED_TEE_MODE", "")
	t.Setenv("TEE_MODE", "mock")
	require.True(t, startupAllowsVerificationInitFailure())

	t.Setenv("TEE_MODE", "")
	require.False(t, startupAllowsVerificationInitFailure())
}

func TestTEEQuoteSchemaValidationCoverage(t *testing.T) {
	require.Error(t, validateTEEQuoteSchema(nil))

	quotePayload := nitroQuoteSchema{
		ModuleID:  "module-1",
		Timestamp: time.Now().UTC().Unix(),
		Digest:    "sha384",
		PCRs: []nitroQuotePCR{
			{Index: 0, Value: []byte("pcr0")},
		},
		UserData: []byte("user"),
		Nonce:    []byte("nonce"),
	}
	quoteBytes, err := json.Marshal(quotePayload)
	require.NoError(t, err)

	nitro := &TEEAttestationData{
		Platform: "aws-nitro",
		Quote:    quoteBytes,
		UserData: []byte("user"),
		Nonce:    []byte("nonce"),
	}
	require.NoError(t, validateTEEQuoteSchema(nitro))

	nitro.UserData = []byte("different")
	require.ErrorContains(t, validateTEEQuoteSchema(nitro), "user_data mismatch")
	nitro.UserData = []byte("user")

	nitro.Quote = []byte("{invalid-json")
	require.ErrorContains(t, validateTEEQuoteSchema(nitro), "invalid nitro quote json")

	sgxQuote := make([]byte, sgxQuoteHeaderLen)
	binary.LittleEndian.PutUint16(sgxQuote[0:2], 3)
	require.NoError(t, validateTEEQuoteSchema(&TEEAttestationData{
		Platform: "intel-sgx",
		Quote:    sgxQuote,
	}))

	binary.LittleEndian.PutUint16(sgxQuote[0:2], 4)
	require.NoError(t, validateTEEQuoteSchema(&TEEAttestationData{
		Platform: "intel-tdx",
		Quote:    sgxQuote,
	}))

	require.ErrorContains(t, validateDCAPQuoteHeader([]byte{0x01, 0x02}), "too short")
	badVersion := make([]byte, sgxQuoteHeaderLen)
	binary.LittleEndian.PutUint16(badVersion[0:2], 2)
	require.ErrorContains(t, validateDCAPQuoteHeader(badVersion), "unsupported")

	// Unknown platforms are ignored at schema layer.
	require.NoError(t, validateTEEQuoteSchema(&TEEAttestationData{
		Platform: "custom-tee",
		Quote:    []byte("opaque"),
	}))
}
