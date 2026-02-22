package keeper

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// PrometheusExporter exports PoUW metrics in Prometheus format
type PrometheusExporter struct {
	namespace string
	subsystem string

	// Reference to module metrics
	metrics *ModuleMetrics

	// Additional custom metrics
	customCounters   map[string]*AtomicCounter
	customGauges     map[string]*AtomicGauge
	customHistograms map[string]*TimingHistogram
	customMu         sync.RWMutex

	// Labels
	defaultLabels map[string]string
}

// NewPrometheusExporter creates a new Prometheus metrics exporter
func NewPrometheusExporter(metrics *ModuleMetrics) *PrometheusExporter {
	return &PrometheusExporter{
		namespace:        "aethelred",
		subsystem:        "pouw",
		metrics:          metrics,
		customCounters:   make(map[string]*AtomicCounter),
		customGauges:     make(map[string]*AtomicGauge),
		customHistograms: make(map[string]*TimingHistogram),
		defaultLabels: map[string]string{
			"chain_id": "aethelred-1",
		},
	}
}

// SetDefaultLabel sets a default label to include with all metrics
func (pe *PrometheusExporter) SetDefaultLabel(name, value string) {
	pe.customMu.Lock()
	pe.defaultLabels[name] = value
	pe.customMu.Unlock()
}

// RegisterCounter registers a custom counter metric
func (pe *PrometheusExporter) RegisterCounter(name string) *AtomicCounter {
	pe.customMu.Lock()
	defer pe.customMu.Unlock()

	if c, exists := pe.customCounters[name]; exists {
		return c
	}
	c := &AtomicCounter{}
	pe.customCounters[name] = c
	return c
}

// RegisterGauge registers a custom gauge metric
func (pe *PrometheusExporter) RegisterGauge(name string) *AtomicGauge {
	pe.customMu.Lock()
	defer pe.customMu.Unlock()

	if g, exists := pe.customGauges[name]; exists {
		return g
	}
	g := &AtomicGauge{}
	pe.customGauges[name] = g
	return g
}

// RegisterHistogram registers a custom histogram metric
func (pe *PrometheusExporter) RegisterHistogram(name string, capacity int) *TimingHistogram {
	pe.customMu.Lock()
	defer pe.customMu.Unlock()

	if h, exists := pe.customHistograms[name]; exists {
		return h
	}
	h := NewTimingHistogram(capacity)
	pe.customHistograms[name] = h
	return h
}

// ServeHTTP implements http.Handler for Prometheus scraping
func (pe *PrometheusExporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var sb strings.Builder

	// Export built-in module metrics
	pe.exportModuleMetrics(&sb)

	// Export custom metrics
	pe.exportCustomMetrics(&sb)

	w.Write([]byte(sb.String()))
}

// Render returns the Prometheus exposition text for the current metrics snapshot.
func (pe *PrometheusExporter) Render() string {
	var sb strings.Builder
	pe.exportModuleMetrics(&sb)
	pe.exportCustomMetrics(&sb)
	return sb.String()
}

// exportModuleMetrics exports the built-in module metrics
func (pe *PrometheusExporter) exportModuleMetrics(sb *strings.Builder) {
	if pe.metrics == nil {
		return
	}

	// Job lifecycle metrics
	pe.writeCounter(sb, "jobs_submitted_total", "Total number of compute jobs submitted",
		pe.metrics.JobsSubmitted.Get())
	pe.writeCounter(sb, "jobs_completed_total", "Total number of compute jobs completed",
		pe.metrics.JobsCompleted.Get())
	pe.writeCounter(sb, "jobs_failed_total", "Total number of compute jobs failed",
		pe.metrics.JobsFailed.Get())
	pe.writeCounter(sb, "jobs_expired_total", "Total number of compute jobs expired",
		pe.metrics.JobsExpired.Get())
	pe.writeCounter(sb, "jobs_cancelled_total", "Total number of compute jobs cancelled",
		pe.metrics.JobsCancelled.Get())

	// Gauges
	pe.writeGauge(sb, "jobs_pending", "Number of pending jobs in queue",
		pe.metrics.JobsPending.Get())
	pe.writeGauge(sb, "jobs_processing", "Number of jobs currently processing",
		pe.metrics.JobsProcessing.Get())

	// Consensus metrics
	pe.writeCounter(sb, "consensus_rounds_total", "Total consensus rounds",
		pe.metrics.ConsensusRounds.Get())
	pe.writeCounter(sb, "consensus_reached_total", "Successful consensus rounds",
		pe.metrics.ConsensusReached.Get())
	pe.writeCounter(sb, "consensus_failed_total", "Failed consensus rounds",
		pe.metrics.ConsensusFailed.Get())
	pe.writeCounter(sb, "vote_extensions_processed_total", "Vote extensions processed",
		pe.metrics.VoteExtensionsProcessed.Get())
	pe.writeCounter(sb, "vote_extensions_rejected_total", "Vote extensions rejected",
		pe.metrics.VoteExtensionsRejected.Get())

	// Verification metrics
	pe.writeCounter(sb, "verifications_total", "Total verifications performed",
		pe.metrics.VerificationsTotal.Get())
	pe.writeCounter(sb, "verifications_tee_total", "TEE verifications",
		pe.metrics.VerificationsTEE.Get())
	pe.writeCounter(sb, "verifications_zkml_total", "zkML verifications",
		pe.metrics.VerificationsZKML.Get())
	pe.writeCounter(sb, "verifications_hybrid_total", "Hybrid verifications",
		pe.metrics.VerificationsHybrid.Get())
	pe.writeCounter(sb, "verifications_success_total", "Successful verifications",
		pe.metrics.VerificationsSuccess.Get())
	pe.writeCounter(sb, "verifications_failed_total", "Failed verifications",
		pe.metrics.VerificationsFailed.Get())

	// Slashing & evidence metrics
	pe.writeCounter(sb, "evidence_records_created_total", "Evidence records created",
		pe.metrics.EvidenceRecordsCreated.Get())
	pe.writeCounter(sb, "slashing_penalties_applied_total", "Slashing penalties applied",
		pe.metrics.SlashingPenaltiesApplied.Get())
	pe.writeCounter(sb, "slashing_penalties_failed_total", "Slashing penalties that failed",
		pe.metrics.SlashingPenaltiesFailed.Get())
	pe.writeCounter(sb, "invalid_outputs_detected_total", "Invalid outputs detected",
		pe.metrics.InvalidOutputsDetected.Get())
	pe.writeCounter(sb, "double_signs_detected_total", "Double signs detected",
		pe.metrics.DoubleSignsDetected.Get())
	pe.writeCounter(sb, "collusion_detected_total", "Collusion attempts detected",
		pe.metrics.CollusionDetected.Get())

	// Economics metrics
	pe.writeCounter(sb, "fees_collected_uaeth_total", "Total fees collected in uaeth",
		pe.metrics.FeesCollected.Get())
	pe.writeCounter(sb, "fees_distributed_uaeth_total", "Total fees distributed in uaeth",
		pe.metrics.FeesDistributed.Get())
	pe.writeCounter(sb, "tokens_burned_uaeth_total", "Total tokens burned in uaeth",
		pe.metrics.TokensBurned.Get())
	pe.writeCounter(sb, "rewards_distributed_uaeth_total", "Total rewards distributed in uaeth",
		pe.metrics.RewardsDistributed.Get())

	// Validator gauges
	pe.writeGauge(sb, "active_validators", "Number of active validators",
		pe.metrics.ActiveValidators.Get())
	pe.writeGauge(sb, "total_validators", "Total registered validators",
		pe.metrics.TotalValidators.Get())

	// Block metrics
	pe.writeCounter(sb, "blocks_processed_total", "Total blocks processed",
		pe.metrics.BlocksProcessed.Get())
	pe.writeGauge(sb, "last_block_height", "Last processed block height",
		pe.metrics.LastBlockHeight.Get())

	// Timing histograms
	if pe.metrics.JobCompletionTime != nil {
		summary := pe.metrics.JobCompletionTime.Summary()
		pe.writeHistogramSummary(sb, "job_completion_seconds", "Job completion time distribution", summary)
	}

	if pe.metrics.ConsensusRoundTime != nil {
		summary := pe.metrics.ConsensusRoundTime.Summary()
		pe.writeHistogramSummary(sb, "consensus_round_seconds", "Consensus round time distribution", summary)
	}

	if pe.metrics.VerificationTime != nil {
		summary := pe.metrics.VerificationTime.Summary()
		pe.writeHistogramSummary(sb, "verification_seconds", "Verification time distribution", summary)
	}

	if pe.metrics.VoteExtensionTime != nil {
		summary := pe.metrics.VoteExtensionTime.Summary()
		pe.writeHistogramSummary(sb, "vote_extension_seconds", "Vote extension processing time", summary)
	}
}

// exportCustomMetrics exports custom registered metrics
func (pe *PrometheusExporter) exportCustomMetrics(sb *strings.Builder) {
	pe.customMu.RLock()
	defer pe.customMu.RUnlock()

	// Export custom counters
	names := make([]string, 0, len(pe.customCounters))
	for name := range pe.customCounters {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		c := pe.customCounters[name]
		pe.writeCounter(sb, name, "", c.Get())
	}

	// Export custom gauges
	names = make([]string, 0, len(pe.customGauges))
	for name := range pe.customGauges {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		g := pe.customGauges[name]
		pe.writeGauge(sb, name, "", g.Get())
	}

	// Export custom histograms
	names = make([]string, 0, len(pe.customHistograms))
	for name := range pe.customHistograms {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		h := pe.customHistograms[name]
		summary := h.Summary()
		pe.writeHistogramSummary(sb, name, "", summary)
	}
}

// writeCounter writes a counter metric in Prometheus format
func (pe *PrometheusExporter) writeCounter(sb *strings.Builder, name, help string, value int64) {
	fullName := pe.fullName(name)
	if help != "" {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", fullName, help))
	}
	sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", fullName))
	sb.WriteString(fmt.Sprintf("%s%s %d\n", fullName, pe.formatLabels(), value))
}

// writeGauge writes a gauge metric in Prometheus format
func (pe *PrometheusExporter) writeGauge(sb *strings.Builder, name, help string, value int64) {
	fullName := pe.fullName(name)
	if help != "" {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", fullName, help))
	}
	sb.WriteString(fmt.Sprintf("# TYPE %s gauge\n", fullName))
	sb.WriteString(fmt.Sprintf("%s%s %d\n", fullName, pe.formatLabels(), value))
}

// writeHistogramSummary writes a histogram summary in Prometheus format
func (pe *PrometheusExporter) writeHistogramSummary(sb *strings.Builder, name, help string, summary HistogramSummary) {
	fullName := pe.fullName(name)
	if help != "" {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", fullName, help))
	}
	sb.WriteString(fmt.Sprintf("# TYPE %s summary\n", fullName))

	labels := pe.formatLabels()

	// Write quantiles
	pe.writeQuantile(sb, fullName, labels, "0.5", summary.P50)
	pe.writeQuantile(sb, fullName, labels, "0.95", summary.P95)
	pe.writeQuantile(sb, fullName, labels, "0.99", summary.P99)

	// Write sum and count
	sb.WriteString(fmt.Sprintf("%s_sum%s %f\n", fullName, labels, summary.Avg.Seconds()*float64(summary.Count)))
	sb.WriteString(fmt.Sprintf("%s_count%s %d\n", fullName, labels, summary.Count))
}

// writeQuantile writes a single quantile line
func (pe *PrometheusExporter) writeQuantile(sb *strings.Builder, name, baseLabels, quantile string, value time.Duration) {
	if baseLabels == "" {
		sb.WriteString(fmt.Sprintf("%s{quantile=\"%s\"} %f\n", name, quantile, value.Seconds()))
	} else {
		// Insert quantile into existing labels
		labels := strings.TrimSuffix(baseLabels, "}")
		sb.WriteString(fmt.Sprintf("%s,quantile=\"%s\"} %f\n", labels, quantile, value.Seconds()))
	}
}

// fullName returns the full metric name with namespace and subsystem
func (pe *PrometheusExporter) fullName(name string) string {
	return fmt.Sprintf("%s_%s_%s", pe.namespace, pe.subsystem, name)
}

// formatLabels formats default labels for Prometheus
func (pe *PrometheusExporter) formatLabels() string {
	if len(pe.defaultLabels) == 0 {
		return ""
	}

	labels := make([]string, 0, len(pe.defaultLabels))
	for k, v := range pe.defaultLabels {
		labels = append(labels, fmt.Sprintf("%s=\"%s\"", k, v))
	}
	sort.Strings(labels)

	return "{" + strings.Join(labels, ",") + "}"
}

// PrometheusHandler returns an HTTP handler for Prometheus metrics.
// Pass in the ModuleMetrics from the ConsensusHandler.
func PrometheusHandler(metrics *ModuleMetrics) http.Handler {
	return NewPrometheusExporter(metrics)
}

// RecordJobSubmission records a job submission metric
func (m *ModuleMetrics) RecordJobSubmission() {
	m.JobsSubmitted.Inc()
	m.JobsPending.Inc()
}

// RecordJobCompletion records a job completion metric
func (m *ModuleMetrics) RecordJobCompletion(duration time.Duration, success bool) {
	m.JobsPending.Dec()
	if success {
		m.JobsCompleted.Inc()
	} else {
		m.JobsFailed.Inc()
	}
	if m.JobCompletionTime != nil {
		m.JobCompletionTime.Record(duration)
	}
}

// RecordVerification records a verification metric
func (m *ModuleMetrics) RecordVerification(duration time.Duration, success bool) {
	m.VerificationsTotal.Inc()
	if success {
		m.VerificationsSuccess.Inc()
	} else {
		m.VerificationsFailed.Inc()
	}
	if m.VerificationTime != nil {
		m.VerificationTime.Record(duration)
	}
}

// RecordConsensus records a consensus round metric
func (m *ModuleMetrics) RecordConsensus(duration time.Duration, success bool) {
	m.ConsensusRounds.Inc()
	if success {
		m.ConsensusReached.Inc()
	} else {
		m.ConsensusFailed.Inc()
	}
	if m.ConsensusRoundTime != nil {
		m.ConsensusRoundTime.Record(duration)
	}
}
