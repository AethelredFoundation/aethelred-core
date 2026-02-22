package keeper

import (
	"math"
	"strconv"
	"strings"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	workMetadataVTOKey            = "work.vto"
	workMetadataModelParamSizeKey = "work.model_parameter_size"
	workMetadataFormulaKey        = "work.formula"
	workFormulaVTOByParamSize     = "vto_x_model_parameter_size"
)

func parsePositiveUint(raw string) (uint64, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, false
	}
	return parsed, true
}

func resolveVerifiedTokenOutput(job *types.ComputeJob, outputHash []byte) uint64 {
	if job != nil && job.Metadata != nil {
		if vto, ok := parsePositiveUint(job.Metadata[workMetadataVTOKey]); ok {
			return vto
		}
	}

	// Compatibility fallback: tie minimum VTO to cryptographic output presence.
	if len(outputHash) > 0 {
		return uint64(len(outputHash))
	}
	return 1
}

func resolveModelParameterSize(job *types.ComputeJob, model *types.RegisteredModel) uint64 {
	if model != nil && model.BaseUwuValue > 0 {
		return model.BaseUwuValue
	}
	if job != nil && job.Metadata != nil {
		if size, ok := parsePositiveUint(job.Metadata[workMetadataModelParamSizeKey]); ok {
			return size
		}
	}
	return 1
}

func saturatingMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}

func calculateUsefulWorkUnitsVTO(
	job *types.ComputeJob,
	model *types.RegisteredModel,
	outputHash []byte,
) (uwu uint64, vto uint64, modelParamSize uint64) {
	vto = resolveVerifiedTokenOutput(job, outputHash)
	modelParamSize = resolveModelParameterSize(job, model)
	uwu = saturatingMul(vto, modelParamSize)
	return uwu, vto, modelParamSize
}
