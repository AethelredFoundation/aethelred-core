package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
)

func TestHealthHandler_NilApp(t *testing.T) {
	handler := &AethelredHealthHandler{app: nil}
	req := httptest.NewRequest(http.MethodGet, "/health/aethelred", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload["status"] != "unhealthy" {
		t.Fatalf("expected unhealthy status, got %v", payload["status"])
	}
}

func TestBoolStatus(t *testing.T) {
	if got := boolStatus(true); got != "healthy" {
		t.Fatalf("expected healthy, got %s", got)
	}
	if got := boolStatus(false); got != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", got)
	}
}

func TestOverallStatus(t *testing.T) {
	status := overallStatus([]componentStatus{{Healthy: true}, {Healthy: true}})
	if status != "healthy" {
		t.Fatalf("expected healthy, got %s", status)
	}

	status = overallStatus([]componentStatus{{Healthy: true}, {Healthy: false}})
	if status != "unhealthy" {
		t.Fatalf("expected unhealthy, got %s", status)
	}
}

func TestSummarizeBreakers(t *testing.T) {
	closed := circuitbreaker.Snapshot{Name: "closed", State: circuitbreaker.Closed}
	half := circuitbreaker.Snapshot{Name: "half", State: circuitbreaker.HalfOpen}
	open := circuitbreaker.Snapshot{Name: "open", State: circuitbreaker.Open}

	_, healthy := summarizeBreakers([]circuitbreaker.Snapshot{closed})
	if !healthy {
		t.Fatalf("expected healthy with closed breaker")
	}

	_, healthy = summarizeBreakers([]circuitbreaker.Snapshot{half})
	if healthy {
		t.Fatalf("expected unhealthy with half-open breaker")
	}

	_, healthy = summarizeBreakers([]circuitbreaker.Snapshot{open})
	if healthy {
		t.Fatalf("expected unhealthy with open breaker")
	}
}
