package types

const (
	// ModuleName defines the module name
	// PoUW = Proof-of-Useful-Work: Aethelred's novel consensus mechanism
	// that verifies AI computations and rewards validators based on
	// utility categories and useful work contributions.
	ModuleName = "pouw"

	// TreasuryModuleName is the dedicated module account for treasury allocations.
	TreasuryModuleName = "pouw_treasury"

	// InsuranceModuleName is the dedicated module account for insurance allocations.
	InsuranceModuleName = "pouw_insurance"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// RouterKey defines the module's message routing key
	RouterKey = ModuleName

	// QuerierRoute defines the module's query routing key
	QuerierRoute = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_pouw"
)

var (
	// JobKeyPrefix is the prefix for storing compute jobs
	JobKeyPrefix = []byte{0x01}

	// PendingJobKeyPrefix is the prefix for pending jobs queue
	PendingJobKeyPrefix = []byte{0x02}

	// CompletedJobKeyPrefix is the prefix for completed jobs
	CompletedJobKeyPrefix = []byte{0x03}

	// ModelRegistryKeyPrefix is the prefix for registered models
	ModelRegistryKeyPrefix = []byte{0x04}

	// ValidatorStatsKeyPrefix is the prefix for validator statistics
	ValidatorStatsKeyPrefix = []byte{0x05}

	// ParamsKey is the key for storing module params
	ParamsKey = []byte{0x06}

	// JobCountKey is the key for storing job count
	JobCountKey = []byte{0x07}

	// ValidatorCapabilitiesKeyPrefix is the prefix for validator capabilities
	ValidatorCapabilitiesKeyPrefix = []byte{0x08}

	// LastBlockTimeKey stores the last committed block time (unix nanos).
	LastBlockTimeKey = []byte{0x09}

	// TreasuryEarmarkKeyPrefix tracks treasury allocations by denom.
	TreasuryEarmarkKeyPrefix = []byte{0x0A}

	// InsuranceEarmarkKeyPrefix tracks insurance allocations by denom.
	InsuranceEarmarkKeyPrefix = []byte{0x0B}

	// ValidatorPCR0KeyPrefix stores validator -> PCR0 mappings for TEE attestation.
	ValidatorPCR0KeyPrefix = []byte{0x0C}

	// RegisteredPCR0KeyPrefix stores global registry membership for trusted PCR0 values.
	RegisteredPCR0KeyPrefix = []byte{0x0D}

	// ValidatorMeasurementKeyPrefix stores validator+platform -> measurement mappings.
	ValidatorMeasurementKeyPrefix = []byte{0x0E}

	// RegisteredMeasurementKeyPrefix stores platform-qualified trusted measurement membership.
	RegisteredMeasurementKeyPrefix = []byte{0x0F}
)

// JobKey returns the store key for a job with the given ID
func JobKey(id string) []byte {
	return append(JobKeyPrefix, []byte(id)...)
}

// PendingJobKey returns the key for a pending job
func PendingJobKey(id string) []byte {
	return append(PendingJobKeyPrefix, []byte(id)...)
}

// CompletedJobKey returns the key for a completed job
func CompletedJobKey(id string) []byte {
	return append(CompletedJobKeyPrefix, []byte(id)...)
}

// ModelRegistryKey returns the key for a registered model
func ModelRegistryKey(modelHash []byte) []byte {
	return append(ModelRegistryKeyPrefix, modelHash...)
}

// ValidatorStatsKey returns the key for validator statistics
func ValidatorStatsKey(validatorAddr string) []byte {
	return append(ValidatorStatsKeyPrefix, []byte(validatorAddr)...)
}

// ValidatorCapabilitiesKey returns the key for validator capabilities
func ValidatorCapabilitiesKey(validatorAddr string) []byte {
	return append(ValidatorCapabilitiesKeyPrefix, []byte(validatorAddr)...)
}

// ValidatorPCR0Key returns the key for a validator's registered PCR0 hash.
func ValidatorPCR0Key(validatorAddr string) []byte {
	return append(ValidatorPCR0KeyPrefix, []byte(validatorAddr)...)
}

// RegisteredPCR0Key returns the key for global PCR0 registry membership.
func RegisteredPCR0Key(pcr0Hex string) []byte {
	return append(RegisteredPCR0KeyPrefix, []byte(pcr0Hex)...)
}

// ValidatorMeasurementKey returns the key for a validator platform measurement binding.
func ValidatorMeasurementKey(validatorPlatformKey string) []byte {
	return append(ValidatorMeasurementKeyPrefix, []byte(validatorPlatformKey)...)
}

// RegisteredMeasurementKey returns the key for global platform measurement registry membership.
func RegisteredMeasurementKey(platformMeasurementKey string) []byte {
	return append(RegisteredMeasurementKeyPrefix, []byte(platformMeasurementKey)...)
}
