package app

import (
	"fmt"
	"os"
	"strings"

	"cosmossdk.io/log"
	"github.com/spf13/cast"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"

	"github.com/aethelred/aethelred/crypto/pqc"
)

func initPQCMode(logger log.Logger, appOpts servertypes.AppOptions) error {
	mode := strings.ToLower(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.pqc.mode")),
		cast.ToString(appOpts.Get("pqc.mode")),
	))
	if mode == "" {
		mode = strings.ToLower(firstNonEmpty(
			os.Getenv("AETHELRED_PQC_MODE"),
			os.Getenv("PQC_MODE"),
		))
	}
	if mode == "" {
		mode = "simulated"
	}

	switch mode {
	case "enabled", "production", "prod", "true", "1":
		if err := pqc.EnforceProductionMode(); err != nil {
			return err
		}
	case "hybrid":
		pqc.SetPQCMode(pqc.PQCModeHybrid)
		if !pqc.IsCirclAvailable() {
			return fmt.Errorf("PQC hybrid mode requires circl; build with -tags=pqc_circl")
		}
		if err := pqc.RunPQCSelfTests(); err != nil {
			return fmt.Errorf("PQC self-tests failed: %w", err)
		}
	case "simulated", "disabled", "false", "0":
		pqc.SetPQCMode(pqc.PQCModeSimulated)
	default:
		return fmt.Errorf("unsupported PQC mode: %q", mode)
	}

	logger.Info("PQC mode configured",
		"mode", pqc.GetPQCMode().String(),
		"circl_available", pqc.IsCirclAvailable(),
	)

	return nil
}
