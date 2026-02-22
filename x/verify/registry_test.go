package verify

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func TestModelRegistryLoadExportStats(t *testing.T) {
	reg := NewModelRegistry(log.NewNopLogger(), DefaultRegistryConfig())

	modelHash := bytes.Repeat([]byte{0x01}, 32)
	circuitHash := bytes.Repeat([]byte{0x02}, 32)
	vk := bytes.Repeat([]byte{0x03}, 32)
	vkHash := sha256Hash(vk)

	model := &RegisteredModel{
		ModelHash:    modelHash,
		Name:         "model-a",
		Status:       ModelStatusActive,
		RegisteredAt: time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		CircuitHashes: [][]byte{
			circuitHash,
		},
	}

	circuit := &RegisteredCircuit{
		CircuitHash:      circuitHash,
		ModelHash:        modelHash,
		VerifyingKey:     vk,
		VerifyingKeyHash: vkHash,
		Status:           CircuitStatusActive,
		CompiledAt:       time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	reg.LoadState(&SyncState{
		Models:   map[string]*RegisteredModel{hexKey(modelHash): model},
		Circuits: map[string]*RegisteredCircuit{hexKey(circuitHash): circuit},
	})

	stats := reg.GetModelStats()
	if stats.TotalModels != 1 || stats.ActiveModels != 1 {
		t.Fatalf("unexpected model stats: %+v", stats)
	}
	if stats.TotalCircuits != 1 || stats.ActiveCircuits != 1 {
		t.Fatalf("unexpected circuit stats: %+v", stats)
	}

	exported := reg.ExportState()
	if len(exported.Models) != 1 || len(exported.Circuits) != 1 {
		t.Fatalf("unexpected exported state")
	}

	if vkOut, err := reg.GetVerifyingKey(vkHash); err != nil || !bytes.Equal(vkOut, vk) {
		t.Fatalf("expected verifying key lookup to succeed")
	}
}

func TestModelRegistryDeactivateModel(t *testing.T) {
	reg := NewModelRegistry(log.NewNopLogger(), DefaultRegistryConfig())

	modelHash := bytes.Repeat([]byte{0x11}, 32)
	circuitHash := bytes.Repeat([]byte{0x22}, 32)
	model := &RegisteredModel{
		ModelHash:     modelHash,
		Status:        ModelStatusActive,
		CircuitHashes: [][]byte{circuitHash},
		RegisteredAt:  time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	circuit := &RegisteredCircuit{
		CircuitHash: circuitHash,
		ModelHash:   modelHash,
		Status:      CircuitStatusActive,
		CompiledAt:  time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	reg.LoadState(&SyncState{
		Models:   map[string]*RegisteredModel{hexKey(modelHash): model},
		Circuits: map[string]*RegisteredCircuit{hexKey(circuitHash): circuit},
	})

	if err := reg.DeactivateModel(modelHash); err != nil {
		t.Fatalf("expected deactivate to succeed, got %v", err)
	}

	m, err := reg.GetModel(modelHash)
	if err != nil {
		t.Fatalf("expected model, got %v", err)
	}
	if m.Status != ModelStatusInactive {
		t.Fatalf("expected inactive model")
	}

	c, err := reg.GetCircuit(circuitHash)
	if err != nil {
		t.Fatalf("expected circuit, got %v", err)
	}
	if c.Status != CircuitStatusInactive {
		t.Fatalf("expected inactive circuit")
	}
}

func TestModelRegistryErrors(t *testing.T) {
	reg := NewModelRegistry(log.NewNopLogger(), DefaultRegistryConfig())

	if _, err := reg.GetModel(bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Fatalf("expected model not found error")
	}

	if _, err := reg.GetCircuit(bytes.Repeat([]byte{0x02}, 32)); err == nil {
		t.Fatalf("expected circuit not found error")
	}

	if _, err := reg.GetVerifyingKey(bytes.Repeat([]byte{0x03}, 32)); err == nil {
		t.Fatalf("expected verifying key not found error")
	}

	if _, err := reg.GetCircuitsForModel(bytes.Repeat([]byte{0x04}, 32)); err == nil {
		t.Fatalf("expected circuits for model not found error")
	}
}

func TestModelRegistrySetTEEMeasurement(t *testing.T) {
	reg := NewModelRegistry(log.NewNopLogger(), DefaultRegistryConfig())

	modelHash := bytes.Repeat([]byte{0x31}, 32)
	model := &RegisteredModel{
		ModelHash:    modelHash,
		Status:       ModelStatusActive,
		RegisteredAt: time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	reg.LoadState(&SyncState{
		Models: map[string]*RegisteredModel{hexKey(modelHash): model},
	})

	measurement := []byte{0xAA, 0xBB}
	if err := reg.SetTEEMeasurement(modelHash, measurement); err != nil {
		t.Fatalf("expected set measurement to succeed, got %v", err)
	}

	m, err := reg.GetModel(modelHash)
	if err != nil {
		t.Fatalf("expected model, got %v", err)
	}
	if !bytes.Equal(m.TEEMeasurement, measurement) {
		t.Fatalf("expected measurement to be set")
	}
}

func TestModelRegistryListActiveModels(t *testing.T) {
	reg := NewModelRegistry(log.NewNopLogger(), DefaultRegistryConfig())

	active := &RegisteredModel{ModelHash: bytes.Repeat([]byte{0x41}, 32), Status: ModelStatusActive}
	pending := &RegisteredModel{ModelHash: bytes.Repeat([]byte{0x42}, 32), Status: ModelStatusPending}
	reg.LoadState(&SyncState{
		Models: map[string]*RegisteredModel{
			hexKey(active.ModelHash):  active,
			hexKey(pending.ModelHash): pending,
		},
	})

	models := reg.ListActiveModels()
	if len(models) != 1 {
		t.Fatalf("expected 1 active model, got %d", len(models))
	}
}

func hexKey(b []byte) string {
	return fmt.Sprintf("%x", b)
}
