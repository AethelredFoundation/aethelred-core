package credit_scoring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"

	"cosmossdk.io/log"
	"google.golang.org/protobuf/types/known/timestamppb"

	demotypes "github.com/aethelred/aethelred/x/demo/types"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

// CreditScoringPipeline orchestrates the credit scoring verification process
type CreditScoringPipeline struct {
	logger log.Logger
	config PipelineConfig

	// Model registry
	models     map[string]*demotypes.CreditScoringModel
	modelMutex sync.RWMutex

	// Application queue
	applications     map[string]*demotypes.LoanApplication
	applicationMutex sync.RWMutex

	// Results cache
	results     map[string]*demotypes.CreditScoringResult
	resultMutex sync.RWMutex

	// Metrics
	metrics *PipelineMetrics
}

// PipelineConfig contains configuration for the pipeline
type PipelineConfig struct {
	// DefaultModelID to use when not specified
	DefaultModelID string

	// MaxConcurrentApplications to process
	MaxConcurrentApplications int

	// ApplicationTimeout for processing
	ApplicationTimeout time.Duration

	// RequireVerification enforces verification
	RequireVerification bool

	// VerificationType (tee, zkml, hybrid)
	VerificationType string

	// BaseInterestRate for calculations
	BaseInterestRate float64

	// EnableAuditTrail for compliance
	EnableAuditTrail bool
}

// DefaultPipelineConfig returns default configuration
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		DefaultModelID:            "credit-score-v1",
		MaxConcurrentApplications: 100,
		ApplicationTimeout:        60 * time.Second,
		RequireVerification:       true,
		VerificationType:          "hybrid",
		BaseInterestRate:          5.0,
		EnableAuditTrail:          true,
	}
}

// PipelineMetrics tracks pipeline metrics
type PipelineMetrics struct {
	TotalApplications       int64
	ProcessedApplications   int64
	ApprovedApplications    int64
	DeniedApplications      int64
	ReviewApplications      int64
	FailedApplications      int64
	AverageProcessingTimeMs int64
	AverageScore            float64
	mutex                   sync.Mutex
}

// NewCreditScoringPipeline creates a new pipeline
func NewCreditScoringPipeline(logger log.Logger, config PipelineConfig) *CreditScoringPipeline {
	pipeline := &CreditScoringPipeline{
		logger:       logger,
		config:       config,
		models:       make(map[string]*demotypes.CreditScoringModel),
		applications: make(map[string]*demotypes.LoanApplication),
		results:      make(map[string]*demotypes.CreditScoringResult),
		metrics:      &PipelineMetrics{},
	}

	// Register default model
	defaultModel := demotypes.DefaultCreditScoringModel()
	pipeline.RegisterModel(defaultModel)

	return pipeline
}

// RegisterModel registers a credit scoring model
func (p *CreditScoringPipeline) RegisterModel(model *demotypes.CreditScoringModel) error {
	p.modelMutex.Lock()
	defer p.modelMutex.Unlock()

	if model.ModelID == "" {
		return fmt.Errorf("model ID is required")
	}

	// Generate model hash if not set
	if len(model.ModelHash) == 0 {
		h := sha256.New()
		h.Write([]byte(model.ModelID))
		h.Write([]byte(model.Version))
		h.Write([]byte(model.Name))
		model.ModelHash = h.Sum(nil)
	}

	p.models[model.ModelID] = model

	p.logger.Info("Credit scoring model registered",
		"model_id", model.ModelID,
		"version", model.Version,
		"status", model.Status,
	)

	return nil
}

// GetModel returns a model by ID
func (p *CreditScoringPipeline) GetModel(modelID string) (*demotypes.CreditScoringModel, error) {
	p.modelMutex.RLock()
	defer p.modelMutex.RUnlock()

	model, ok := p.models[modelID]
	if !ok {
		return nil, fmt.Errorf("model not found: %s", modelID)
	}

	return model, nil
}

// SubmitApplication submits a loan application for scoring
func (p *CreditScoringPipeline) SubmitApplication(ctx context.Context, app *demotypes.LoanApplication) (*demotypes.LoanApplication, error) {
	// Validate application
	if err := p.validateApplication(app); err != nil {
		return nil, fmt.Errorf("invalid application: %w", err)
	}

	// Use default model if not specified
	if app.ModelID == "" {
		app.ModelID = p.config.DefaultModelID
	}

	// Verify model exists
	if _, err := p.GetModel(app.ModelID); err != nil {
		return nil, err
	}

	// Store application
	p.applicationMutex.Lock()
	p.applications[app.ApplicationID] = app
	p.applicationMutex.Unlock()

	// Update metrics
	p.metrics.mutex.Lock()
	p.metrics.TotalApplications++
	p.metrics.mutex.Unlock()

	p.logger.Info("Loan application submitted",
		"application_id", app.ApplicationID,
		"loan_type", app.LoanType,
		"loan_amount", app.LoanAmount,
		"model_id", app.ModelID,
	)

	return app, nil
}

// ProcessApplication processes a loan application through the verification pipeline
func (p *CreditScoringPipeline) ProcessApplication(ctx context.Context, applicationID string) (*demotypes.CreditScoringResult, error) {
	startTime := time.Now()

	// Get application
	p.applicationMutex.RLock()
	app, ok := p.applications[applicationID]
	p.applicationMutex.RUnlock()

	if !ok {
		return nil, fmt.Errorf("application not found: %s", applicationID)
	}

	// Update status
	app.Status = demotypes.ApplicationStatusProcessing

	// Get model
	model, err := p.GetModel(app.ModelID)
	if err != nil {
		app.Status = demotypes.ApplicationStatusFailed
		return nil, err
	}

	// Execute credit scoring
	result, err := p.executeScoring(ctx, app, model)
	if err != nil {
		app.Status = demotypes.ApplicationStatusFailed
		p.metrics.mutex.Lock()
		p.metrics.FailedApplications++
		p.metrics.mutex.Unlock()
		return nil, err
	}

	// Set processing time (ensure non-zero for metrics in fast execution paths)
	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
	if result.ProcessingTimeMs <= 0 {
		result.ProcessingTimeMs = 1
	}

	// Update application
	now := time.Now().UTC()
	app.ProcessedAt = &now
	app.Status = demotypes.ApplicationStatusCompleted
	app.Result = result

	// Store result
	p.resultMutex.Lock()
	p.results[applicationID] = result
	p.resultMutex.Unlock()

	// Update model usage
	p.modelMutex.Lock()
	model.LastUsedAt = &now
	model.UsageCount++
	p.modelMutex.Unlock()

	// Update metrics
	p.updateMetrics(result)

	p.logger.Info("Loan application processed",
		"application_id", applicationID,
		"score", result.Score,
		"decision", result.Decision,
		"processing_time_ms", result.ProcessingTimeMs,
	)

	return result, nil
}

// executeScoring executes the credit scoring model
func (p *CreditScoringPipeline) executeScoring(ctx context.Context, app *demotypes.LoanApplication, model *demotypes.CreditScoringModel) (*demotypes.CreditScoringResult, error) {
	// Convert features to vector
	inputVector := app.Features.ToVector()

	// Execute scoring (simulated neural network inference)
	score, probability := p.computeScore(inputVector, app.Features)

	// Get category and decision
	category := demotypes.GetScoreCategory(score)
	decision := demotypes.GetLoanDecision(score, app.Features.DebtToIncomeRatio, app.Features.NumBankruptcies)

	// Calculate risk factors
	riskFactors := p.analyzeRiskFactors(app.Features, score)

	// Calculate positive factors
	positiveFactors := p.analyzePositiveFactors(app.Features)

	// Calculate recommended rate if approved
	var recommendedRate *float64
	var recommendedLimit *float64
	if decision == demotypes.LoanDecisionApproved || decision == demotypes.LoanDecisionReview {
		rate := demotypes.CalculateRecommendedRate(score, p.config.BaseInterestRate)
		recommendedRate = &rate

		limit := p.calculateCreditLimit(app.Features, score)
		recommendedLimit = &limit
	}

	// Build result
	result := &demotypes.CreditScoringResult{
		ApplicationID:      app.ApplicationID,
		Score:              score,
		ScoreCategory:      category,
		DefaultProbability: probability,
		Decision:           decision,
		RecommendedRate:    recommendedRate,
		RecommendedLimit:   recommendedLimit,
		RiskFactors:        riskFactors,
		PositiveFactors:    positiveFactors,
		Confidence:         p.calculateConfidence(app.Features),
		ModelID:            model.ModelID,
		ModelVersion:       model.Version,
		VerificationType:   p.config.VerificationType,
		ProcessedAt:        time.Now().UTC(),
	}

	// Compute output hash
	result.OutputHash = result.Hash()

	return result, nil
}

// computeScore simulates neural network credit scoring
func (p *CreditScoringPipeline) computeScore(inputVector []float64, features *demotypes.CreditFeatures) (int, float64) {
	// Base score starts at 650
	baseScore := 650.0

	// Positive factors
	if features.CreditHistoryLength > 120 { // > 10 years
		baseScore += 50
	} else if features.CreditHistoryLength > 60 { // > 5 years
		baseScore += 25
	}

	if features.CreditUtilization < 0.30 {
		baseScore += 40
	} else if features.CreditUtilization < 0.50 {
		baseScore += 20
	}

	if features.NumLatePayments == 0 {
		baseScore += 35
	}

	if features.EmploymentLength > 36 { // > 3 years
		baseScore += 20
	}

	if features.DebtToIncomeRatio < 0.28 {
		baseScore += 30
	} else if features.DebtToIncomeRatio < 0.36 {
		baseScore += 15
	}

	// Negative factors
	if features.NumLatePayments > 0 {
		baseScore -= float64(features.NumLatePayments) * 15
	}

	if features.NumDelinquencies > 0 {
		baseScore -= float64(features.NumDelinquencies) * 30
	}

	if features.NumBankruptcies > 0 {
		baseScore -= float64(features.NumBankruptcies) * 100
	}

	if features.NumCollections > 0 {
		baseScore -= float64(features.NumCollections) * 50
	}

	if features.CreditUtilization > 0.70 {
		baseScore -= 40
	}

	if features.NumRecentInquiries > 5 {
		baseScore -= float64(features.NumRecentInquiries-5) * 5
	}

	if features.DebtToIncomeRatio > 0.43 {
		baseScore -= 40
	}

	// Clamp score to valid range
	score := int(math.Round(baseScore))
	if score < demotypes.CreditScoreMin {
		score = demotypes.CreditScoreMin
	}
	if score > demotypes.CreditScoreMax {
		score = demotypes.CreditScoreMax
	}

	// Calculate default probability (inverse relationship with score)
	normalizedScore := float64(score-demotypes.CreditScoreMin) / float64(demotypes.CreditScoreMax-demotypes.CreditScoreMin)
	defaultProbability := 1.0 - normalizedScore
	defaultProbability = math.Pow(defaultProbability, 2) // Make it more realistic

	return score, defaultProbability
}

// analyzeRiskFactors identifies risk factors in the application
func (p *CreditScoringPipeline) analyzeRiskFactors(features *demotypes.CreditFeatures, score int) []demotypes.RiskFactor {
	var factors []demotypes.RiskFactor

	if features.NumLatePayments > 0 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "late_payments",
			Impact:         -features.NumLatePayments * 15,
			Description:    fmt.Sprintf("%d late payment(s) on record", features.NumLatePayments),
			Recommendation: "Ensure all payments are made on time for at least 12 months",
		})
	}

	if features.CreditUtilization > 0.50 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "high_credit_utilization",
			Impact:         -int((features.CreditUtilization - 0.30) * 100),
			Description:    fmt.Sprintf("Credit utilization at %.0f%%", features.CreditUtilization*100),
			Recommendation: "Reduce credit card balances to below 30% of limits",
		})
	}

	if features.DebtToIncomeRatio > 0.36 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "high_debt_to_income",
			Impact:         -int((features.DebtToIncomeRatio - 0.36) * 200),
			Description:    fmt.Sprintf("Debt-to-income ratio at %.0f%%", features.DebtToIncomeRatio*100),
			Recommendation: "Pay down existing debts or increase income",
		})
	}

	if features.CreditHistoryLength < 24 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "short_credit_history",
			Impact:         -25,
			Description:    fmt.Sprintf("Credit history only %d months", features.CreditHistoryLength),
			Recommendation: "Maintain existing accounts to build credit history",
		})
	}

	if features.NumRecentInquiries > 3 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "recent_inquiries",
			Impact:         -features.NumRecentInquiries * 3,
			Description:    fmt.Sprintf("%d credit inquiries in last 6 months", features.NumRecentInquiries),
			Recommendation: "Limit new credit applications for 6-12 months",
		})
	}

	if features.NumBankruptcies > 0 {
		factors = append(factors, demotypes.RiskFactor{
			Factor:         "bankruptcy_history",
			Impact:         -100,
			Description:    "Bankruptcy on record",
			Recommendation: "Continue rebuilding credit; impact diminishes over time",
		})
	}

	return factors
}

// analyzePositiveFactors identifies positive factors
func (p *CreditScoringPipeline) analyzePositiveFactors(features *demotypes.CreditFeatures) []string {
	var factors []string

	if features.NumLatePayments == 0 {
		factors = append(factors, "Perfect payment history")
	}

	if features.CreditHistoryLength > 120 {
		factors = append(factors, "Long credit history (10+ years)")
	} else if features.CreditHistoryLength > 60 {
		factors = append(factors, "Established credit history (5+ years)")
	}

	if features.CreditUtilization < 0.30 {
		factors = append(factors, "Low credit utilization")
	}

	if features.DebtToIncomeRatio < 0.28 {
		factors = append(factors, "Healthy debt-to-income ratio")
	}

	if features.EmploymentLength > 60 {
		factors = append(factors, "Stable employment (5+ years)")
	} else if features.EmploymentLength > 24 {
		factors = append(factors, "Consistent employment (2+ years)")
	}

	if features.NumCreditAccounts >= 5 && features.NumCreditAccounts <= 10 {
		factors = append(factors, "Good mix of credit accounts")
	}

	return factors
}

// calculateCreditLimit calculates recommended credit limit
func (p *CreditScoringPipeline) calculateCreditLimit(features *demotypes.CreditFeatures, score int) float64 {
	// Base on income and score
	baseLimit := features.AnnualIncome * 0.10 // 10% of annual income

	// Adjust based on score
	scoreMultiplier := 1.0
	switch {
	case score >= 800:
		scoreMultiplier = 2.0
	case score >= 740:
		scoreMultiplier = 1.5
	case score >= 670:
		scoreMultiplier = 1.0
	case score >= 580:
		scoreMultiplier = 0.5
	default:
		scoreMultiplier = 0.25
	}

	// Adjust for existing debt
	debtAdjustment := 1.0 - features.DebtToIncomeRatio

	limit := baseLimit * scoreMultiplier * debtAdjustment

	// Cap at reasonable maximum
	if limit > 100000 {
		limit = 100000
	}

	return math.Round(limit/100) * 100 // Round to nearest $100
}

// calculateConfidence calculates confidence in the prediction
func (p *CreditScoringPipeline) calculateConfidence(features *demotypes.CreditFeatures) float64 {
	confidence := 0.85 // Base confidence

	// Higher confidence with more data
	if features.CreditHistoryLength > 60 {
		confidence += 0.05
	}

	if features.NumCreditAccounts >= 5 {
		confidence += 0.03
	}

	// Lower confidence for edge cases
	if features.NumBankruptcies > 0 {
		confidence -= 0.10
	}

	if features.CreditUtilization > 0.80 {
		confidence -= 0.05
	}

	// Clamp to valid range
	if confidence > 0.99 {
		confidence = 0.99
	}
	if confidence < 0.50 {
		confidence = 0.50
	}

	return confidence
}

// validateApplication validates a loan application
func (p *CreditScoringPipeline) validateApplication(app *demotypes.LoanApplication) error {
	if app == nil {
		return fmt.Errorf("application is nil")
	}

	if app.ApplicantID == "" {
		return fmt.Errorf("applicant ID is required")
	}

	if app.LoanAmount <= 0 {
		return fmt.Errorf("loan amount must be positive")
	}

	if app.LoanTerm <= 0 {
		return fmt.Errorf("loan term must be positive")
	}

	if app.Features == nil {
		return fmt.Errorf("credit features are required")
	}

	// Validate features
	if app.Features.AnnualIncome <= 0 {
		return fmt.Errorf("annual income must be positive")
	}

	if app.Features.Age < 18 {
		return fmt.Errorf("applicant must be at least 18 years old")
	}

	if app.Features.CreditUtilization < 0 || app.Features.CreditUtilization > 1 {
		return fmt.Errorf("credit utilization must be between 0 and 1")
	}

	return nil
}

// updateMetrics updates pipeline metrics
func (p *CreditScoringPipeline) updateMetrics(result *demotypes.CreditScoringResult) {
	p.metrics.mutex.Lock()
	defer p.metrics.mutex.Unlock()

	p.metrics.ProcessedApplications++

	switch result.Decision {
	case demotypes.LoanDecisionApproved:
		p.metrics.ApprovedApplications++
	case demotypes.LoanDecisionDenied:
		p.metrics.DeniedApplications++
	case demotypes.LoanDecisionReview:
		p.metrics.ReviewApplications++
	}

	// Update average processing time
	p.metrics.AverageProcessingTimeMs = (p.metrics.AverageProcessingTimeMs*(p.metrics.ProcessedApplications-1) + result.ProcessingTimeMs) / p.metrics.ProcessedApplications

	// Update average score
	p.metrics.AverageScore = (p.metrics.AverageScore*float64(p.metrics.ProcessedApplications-1) + float64(result.Score)) / float64(p.metrics.ProcessedApplications)
}

// GetMetrics returns current metrics
func (p *CreditScoringPipeline) GetMetrics() *PipelineMetrics {
	p.metrics.mutex.Lock()
	defer p.metrics.mutex.Unlock()
	return p.metrics
}

// GetApplication returns an application by ID
func (p *CreditScoringPipeline) GetApplication(applicationID string) (*demotypes.LoanApplication, error) {
	p.applicationMutex.RLock()
	defer p.applicationMutex.RUnlock()

	app, ok := p.applications[applicationID]
	if !ok {
		return nil, fmt.Errorf("application not found: %s", applicationID)
	}

	return app, nil
}

// GetResult returns a result by application ID
func (p *CreditScoringPipeline) GetResult(applicationID string) (*demotypes.CreditScoringResult, error) {
	p.resultMutex.RLock()
	defer p.resultMutex.RUnlock()

	result, ok := p.results[applicationID]
	if !ok {
		return nil, fmt.Errorf("result not found for application: %s", applicationID)
	}

	return result, nil
}

// CreateComputeJob creates a PoUW compute job for the application
func (p *CreditScoringPipeline) CreateComputeJob(application *demotypes.LoanApplication) (*pouwtypes.ComputeJob, error) {
	model, err := p.GetModel(application.ModelID)
	if err != nil {
		return nil, err
	}

	// Map verification type string to ProofType enum
	var proofType pouwtypes.ProofType
	switch p.config.VerificationType {
	case "tee":
		proofType = pouwtypes.ProofType_PROOF_TYPE_TEE
	case "zkml":
		proofType = pouwtypes.ProofType_PROOF_TYPE_ZKML
	case "hybrid":
		proofType = pouwtypes.ProofType_PROOF_TYPE_HYBRID
	default:
		proofType = pouwtypes.ProofType_PROOF_TYPE_TEE
	}

	job := &pouwtypes.ComputeJob{
		ModelHash:   model.ModelHash,
		InputHash:   application.FeatureHash,
		RequestedBy: application.Submitter,
		Purpose:     fmt.Sprintf("credit_scoring:%s", application.LoanType),
		ProofType:   proofType,
		Priority:    0, // Default priority
		Status:      pouwtypes.JobStatus_JOB_STATUS_PENDING,
		CreatedAt:   timestamppb.Now(),
		Metadata:    make(map[string]string),
	}

	// Generate job ID
	h := sha256.New()
	h.Write(model.ModelHash)
	h.Write(application.FeatureHash)
	h.Write([]byte(application.ApplicationID))
	job.Id = "job-" + hex.EncodeToString(h.Sum(nil))[:16]

	return job, nil
}

// CreateDigitalSeal creates a Digital Seal from the result
func (p *CreditScoringPipeline) CreateDigitalSeal(app *demotypes.LoanApplication, result *demotypes.CreditScoringResult) (*sealtypes.DigitalSeal, error) {
	model, err := p.GetModel(app.ModelID)
	if err != nil {
		return nil, err
	}

	seal := &sealtypes.DigitalSeal{
		ModelCommitment:  model.ModelHash,
		InputCommitment:  app.FeatureHash,
		OutputCommitment: result.OutputHash,
		RequestedBy:      app.Submitter,
		Purpose:          fmt.Sprintf("credit_scoring:%s", app.LoanType),
		Status:           sealtypes.SealStatusPending,
		Timestamp:        timestamppb.Now(),
		TeeAttestations:  make([]*sealtypes.TEEAttestation, 0),
		ValidatorSet:     make([]string, 0),
		RegulatoryInfo: &sealtypes.RegulatoryInfo{
			ComplianceFrameworks:     model.Compliance.Frameworks,
			DataClassification:       "confidential",
			AuditRequired:            true,
			JurisdictionRestrictions: []string{"US"},
		},
	}

	// Generate seal ID
	seal.Id = seal.GenerateID()

	return seal, nil
}

// ListModels returns all registered models
func (p *CreditScoringPipeline) ListModels() []*demotypes.CreditScoringModel {
	p.modelMutex.RLock()
	defer p.modelMutex.RUnlock()

	models := make([]*demotypes.CreditScoringModel, 0, len(p.models))
	for _, model := range p.models {
		models = append(models, model)
	}
	return models
}

// ListApplications returns all applications
func (p *CreditScoringPipeline) ListApplications() []*demotypes.LoanApplication {
	p.applicationMutex.RLock()
	defer p.applicationMutex.RUnlock()

	apps := make([]*demotypes.LoanApplication, 0, len(p.applications))
	for _, app := range p.applications {
		apps = append(apps, app)
	}
	return apps
}
