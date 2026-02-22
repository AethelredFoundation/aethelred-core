package app

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// AethelredMetricsExporter aggregates Aethelred-specific metrics in Prometheus format.
type AethelredMetricsExporter struct {
	app *AethelredApp
}

// MetricsHandler returns an HTTP handler for Aethelred-specific metrics.
func (app *AethelredApp) MetricsHandler() http.Handler {
	return &AethelredMetricsExporter{app: app}
}

func (e *AethelredMetricsExporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	if e.app == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("aethelred_metrics_error 1\n"))
		return
	}

	chainID := ""
	if e.app.BaseApp != nil {
		chainID = e.app.BaseApp.ChainID()
	}

	writer := newMetricsWriter(chainID, Version)

	// Build info
	writer.gauge("aethelred_build_info", "Aethelred build information", 1, nil)

	// PoUW module metrics
	if metrics := e.app.PouwKeeper.Metrics(); metrics != nil {
		exporter := pouwkeeper.NewPrometheusExporter(metrics)
		if chainID != "" {
			exporter.SetDefaultLabel("chain_id", chainID)
		}
		writer.writeRaw(exporter.Render())
	}

	// Verification orchestrator metrics
	if e.app.orchestrator != nil {
		om := e.app.orchestrator.GetMetrics()
		writer.counter("aethelred_verify_orchestrator_total_verifications", "Total verifications orchestrated", om.TotalVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_successful_verifications", "Successful verifications", om.SuccessfulVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_failed_verifications", "Failed verifications", om.FailedVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_tee_verifications", "TEE verifications", om.TEEVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_zkml_verifications", "zkML verifications", om.ZKMLVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_hybrid_verifications", "Hybrid verifications", om.HybridVerifications, nil)
		writer.counter("aethelred_verify_orchestrator_cache_hits", "Orchestrator cache hits", om.CacheHits, nil)
		writer.gauge("aethelred_verify_orchestrator_avg_time_ms", "Average verification time (ms)", float64(om.AverageTimeMs), nil)

		if pm, ok := e.app.orchestrator.GetProverMetrics(); ok {
			writer.counter("aethelred_verify_prover_total_proofs", "Total zkML proofs generated", pm.TotalProofsGenerated, nil)
			writer.counter("aethelred_verify_prover_failed_proofs", "Failed zkML proofs", pm.TotalProofsFailed, nil)
			writer.counter("aethelred_verify_prover_cache_hits", "Prover cache hits", pm.CacheHits, nil)
			writer.counter("aethelred_verify_prover_cache_misses", "Prover cache misses", pm.CacheMisses, nil)
			writer.gauge("aethelred_verify_prover_avg_time_ms", "Average proof generation time (ms)", float64(pm.AverageProofTimeMs), nil)
		}

		if nm, ok := e.app.orchestrator.GetNitroMetrics(); ok {
			writer.counter("aethelred_tee_nitro_total_attestations", "Nitro attestations", nm.TotalAttestations, nil)
			writer.counter("aethelred_tee_nitro_total_executions", "Nitro executions", nm.TotalExecutions, nil)
			writer.counter("aethelred_tee_nitro_failed_attestations", "Failed Nitro attestations", nm.FailedAttestations, nil)
			writer.counter("aethelred_tee_nitro_failed_executions", "Failed Nitro executions", nm.FailedExecutions, nil)
			writer.gauge("aethelred_tee_nitro_avg_exec_time_ms", "Average Nitro execution time (ms)", float64(nm.AverageExecutionTimeMs), nil)
		}
	}

	// Rate limiter metrics
	if e.app.rateLimiter != nil {
		rm := e.app.rateLimiter.GetMetrics()
		writer.counter("aethelred_ratelimit_requests_total", "Total requests observed by rate limiter", rm.TotalRequests, nil)
		writer.counter("aethelred_ratelimit_requests_allowed_total", "Requests allowed by rate limiter", rm.AllowedRequests, nil)
		writer.counter("aethelred_ratelimit_requests_denied_total", "Requests denied by rate limiter", rm.DeniedRequests, nil)

		for endpoint, count := range rm.EndpointDenials {
			writer.counter("aethelred_ratelimit_denied_total", "Requests denied per endpoint", count,
				map[string]string{"endpoint": endpoint})
		}
	}

	// Circuit breaker metrics
	for _, snap := range collectBreakerSnapshots(e.app) {
		labels := map[string]string{"breaker": snap.Name}
		writer.gauge("aethelred_circuit_breaker_state", "Circuit breaker state (0=closed,1=open,2=half_open)", float64(snap.State), labels)
		writer.gauge("aethelred_circuit_breaker_consecutive_failures", "Consecutive failures tracked by breaker", float64(snap.ConsecutiveFailures), labels)
		writer.counter("aethelred_circuit_breaker_trips_total", "Total breaker trips", snap.TotalTrips, labels)
	}

	_, _ = w.Write([]byte(writer.String()))
}

func collectBreakerSnapshots(app *AethelredApp) []circuitbreaker.Snapshot {
	if app == nil {
		return nil
	}

	var snaps []circuitbreaker.Snapshot

	if app.orchestrator != nil {
		for _, b := range app.orchestrator.CircuitBreakers() {
			if b != nil {
				snaps = append(snaps, b.Snapshot())
			}
		}
	}

	if app.teeClient != nil {
		if provider, ok := app.teeClient.(interface {
			Breaker() *circuitbreaker.Breaker
		}); ok {
			if b := provider.Breaker(); b != nil {
				snaps = append(snaps, b.Snapshot())
			}
		}
	}

	for _, b := range app.VerifyKeeper.CircuitBreakers() {
		if b != nil {
			snaps = append(snaps, b.Snapshot())
		}
	}

	return snaps
}

type metricsWriter struct {
	sb         strings.Builder
	baseLabels map[string]string
}

func newMetricsWriter(chainID, version string) *metricsWriter {
	labels := map[string]string{}
	if chainID != "" {
		labels["chain_id"] = chainID
	}
	if version != "" {
		labels["version"] = version
	}
	return &metricsWriter{baseLabels: labels}
}

func (mw *metricsWriter) String() string {
	return mw.sb.String()
}

func (mw *metricsWriter) writeRaw(raw string) {
	if raw == "" {
		return
	}
	if !strings.HasSuffix(raw, "\n") {
		raw += "\n"
	}
	mw.sb.WriteString(raw)
}

func (mw *metricsWriter) counter(name, help string, value int64, labels map[string]string) {
	mw.writeMetric("counter", name, help, fmt.Sprintf("%d", value), labels)
}

func (mw *metricsWriter) gauge(name, help string, value float64, labels map[string]string) {
	mw.writeMetric("gauge", name, help, fmt.Sprintf("%.6f", value), labels)
}

func (mw *metricsWriter) writeMetric(metricType, name, help, value string, labels map[string]string) {
	mw.sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, help))
	mw.sb.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, metricType))
	mw.sb.WriteString(name)
	if labelStr := mw.formatLabels(labels); labelStr != "" {
		mw.sb.WriteString(labelStr)
	}
	mw.sb.WriteString(" ")
	mw.sb.WriteString(value)
	mw.sb.WriteString("\n")
}

func (mw *metricsWriter) formatLabels(extra map[string]string) string {
	if len(mw.baseLabels) == 0 && len(extra) == 0 {
		return ""
	}
	merged := make(map[string]string, len(mw.baseLabels)+len(extra))
	for k, v := range mw.baseLabels {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=\"%s\"", k, escapeLabelValue(merged[k])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
