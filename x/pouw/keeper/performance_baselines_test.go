package keeper

import (
	"testing"
	"time"
)

func TestDefaultBenchmarkBaselines(t *testing.T) {
	baselines := DefaultBenchmarkBaselines()
	if len(baselines) == 0 {
		t.Fatalf("expected non-empty baselines")
	}
	if _, ok := baselines["AllInvariants"]; !ok {
		t.Fatalf("expected AllInvariants baseline")
	}
	if _, ok := baselines["ValidateParams"]; !ok {
		t.Fatalf("expected ValidateParams baseline")
	}
}

func TestEvaluateBenchmarkBaselines(t *testing.T) {
	baselines := DefaultBenchmarkBaselines()
	results := []BenchmarkResult{
		{
			Name:      "ValidateParams",
			AvgTime:   2 * time.Millisecond,
			P95Time:   2 * time.Millisecond,
			P99Time:   2 * time.Millisecond,
			OpsPerSec: 10,
		},
	}

	violations := EvaluateBenchmarkBaselines(results, baselines)
	if len(violations) == 0 {
		t.Fatalf("expected baseline violations")
	}
}
