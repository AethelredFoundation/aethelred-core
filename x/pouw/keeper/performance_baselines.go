package keeper

import (
	"fmt"
	"time"
)

// BenchmarkBaseline defines expected performance characteristics for a benchmark.
type BenchmarkBaseline struct {
	Name         string
	MaxAvgTime   time.Duration
	MaxP95Time   time.Duration
	MaxP99Time   time.Duration
	MinOpsPerSec float64
	Description  string
}

// BenchmarkViolation captures a baseline violation.
type BenchmarkViolation struct {
	Name     string
	Metric   string
	Expected string
	Actual   string
}

// DefaultBenchmarkBaselines defines conservative baseline targets for core benchmarks.
// These values are intended to pass in clean test environments and should be tuned
// with production benchmark runs on target hardware.
func DefaultBenchmarkBaselines() map[string]BenchmarkBaseline {
	return map[string]BenchmarkBaseline{
		"AllInvariants": {
			Name:         "AllInvariants",
			MaxAvgTime:   10 * time.Millisecond,
			MaxP95Time:   25 * time.Millisecond,
			MaxP99Time:   50 * time.Millisecond,
			MinOpsPerSec: 100,
			Description:  "End-to-end invariant scan",
		},
		"ValidateParams": {
			Name:         "ValidateParams",
			MaxAvgTime:   200 * time.Microsecond,
			MaxP95Time:   500 * time.Microsecond,
			MaxP99Time:   1 * time.Millisecond,
			MinOpsPerSec: 100000,
			Description:  "Parameter validation",
		},
		"EndBlockConsistencyChecks": {
			Name:         "EndBlockConsistencyChecks",
			MaxAvgTime:   10 * time.Millisecond,
			MaxP95Time:   25 * time.Millisecond,
			MaxP99Time:   50 * time.Millisecond,
			MinOpsPerSec: 100,
			Description:  "EndBlock consistency checks",
		},
		"PerformanceScore": {
			Name:         "PerformanceScore",
			MaxAvgTime:   50 * time.Microsecond,
			MaxP95Time:   100 * time.Microsecond,
			MaxP99Time:   200 * time.Microsecond,
			MinOpsPerSec: 1000000,
			Description:  "Validator performance scoring",
		},
	}
}

// EvaluateBenchmarkBaselines compares results against baselines.
func EvaluateBenchmarkBaselines(results []BenchmarkResult, baselines map[string]BenchmarkBaseline) []BenchmarkViolation {
	if len(results) == 0 || len(baselines) == 0 {
		return nil
	}

	violations := make([]BenchmarkViolation, 0)
	for _, result := range results {
		baseline, ok := baselines[result.Name]
		if !ok {
			continue
		}

		if baseline.MaxAvgTime > 0 && result.AvgTime > baseline.MaxAvgTime {
			violations = append(violations, BenchmarkViolation{
				Name:     result.Name,
				Metric:   "avg_time",
				Expected: baseline.MaxAvgTime.String(),
				Actual:   result.AvgTime.String(),
			})
		}
		if baseline.MaxP95Time > 0 && result.P95Time > baseline.MaxP95Time {
			violations = append(violations, BenchmarkViolation{
				Name:     result.Name,
				Metric:   "p95_time",
				Expected: baseline.MaxP95Time.String(),
				Actual:   result.P95Time.String(),
			})
		}
		if baseline.MaxP99Time > 0 && result.P99Time > baseline.MaxP99Time {
			violations = append(violations, BenchmarkViolation{
				Name:     result.Name,
				Metric:   "p99_time",
				Expected: baseline.MaxP99Time.String(),
				Actual:   result.P99Time.String(),
			})
		}
		if baseline.MinOpsPerSec > 0 && result.OpsPerSec < baseline.MinOpsPerSec {
			violations = append(violations, BenchmarkViolation{
				Name:     result.Name,
				Metric:   "ops_per_sec",
				Expected: fmt.Sprintf("%.0f", baseline.MinOpsPerSec),
				Actual:   fmt.Sprintf("%.0f", result.OpsPerSec),
			})
		}
	}
	return violations
}
