package keeper

import (
	"testing"
	"time"
)

func TestComputeBenchmarkResultPercentiles(t *testing.T) {
	durations := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
		4 * time.Millisecond,
		5 * time.Millisecond,
	}
	result := computeBenchmarkResult("test", durations)

	if result.MinTime != 1*time.Millisecond {
		t.Fatalf("expected min 1ms, got %s", result.MinTime)
	}
	if result.MaxTime != 5*time.Millisecond {
		t.Fatalf("expected max 5ms, got %s", result.MaxTime)
	}
	if result.P95Time != 5*time.Millisecond {
		t.Fatalf("expected p95 5ms, got %s", result.P95Time)
	}
	if result.P99Time != 5*time.Millisecond {
		t.Fatalf("expected p99 5ms, got %s", result.P99Time)
	}
}

func TestPercentileDurationEdges(t *testing.T) {
	sorted := []time.Duration{
		1 * time.Millisecond,
		2 * time.Millisecond,
		3 * time.Millisecond,
	}

	if got := percentileDuration(sorted, 0); got != 1*time.Millisecond {
		t.Fatalf("expected p0 1ms, got %s", got)
	}
	if got := percentileDuration(sorted, 100); got != 3*time.Millisecond {
		t.Fatalf("expected p100 3ms, got %s", got)
	}
}
