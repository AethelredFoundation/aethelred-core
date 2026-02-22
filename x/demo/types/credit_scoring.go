package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// CreditScoreRange defines the score range
const (
	CreditScoreMin = 300
	CreditScoreMax = 850
)

// CreditScoreCategory represents score categories
type CreditScoreCategory string

const (
	CreditScorePoor      CreditScoreCategory = "poor"       // 300-579
	CreditScoreFair      CreditScoreCategory = "fair"       // 580-669
	CreditScoreGood      CreditScoreCategory = "good"       // 670-739
	CreditScoreVeryGood  CreditScoreCategory = "very_good"  // 740-799
	CreditScoreExcellent CreditScoreCategory = "excellent"  // 800-850
)

// LoanDecision represents the loan decision
type LoanDecision string

const (
	LoanDecisionApproved LoanDecision = "approved"
	LoanDecisionDenied   LoanDecision = "denied"
	LoanDecisionReview   LoanDecision = "manual_review"
)

// CreditScoringModel represents a registered credit scoring model
type CreditScoringModel struct {
	// ModelID is the unique identifier
	ModelID string `json:"model_id"`

	// Name of the model
	Name string `json:"name"`

	// Version of the model
	Version string `json:"version"`

	// Description of the model
	Description string `json:"description"`

	// ModelHash is the SHA-256 hash of model weights
	ModelHash []byte `json:"model_hash"`

	// CircuitHash for zkML verification
	CircuitHash []byte `json:"circuit_hash,omitempty"`

	// InputSchema describes expected input format
	InputSchema *CreditInputSchema `json:"input_schema"`

	// OutputSchema describes expected output format
	OutputSchema *CreditOutputSchema `json:"output_schema"`

	// Metrics from validation
	Metrics *ModelMetrics `json:"metrics"`

	// Regulatory compliance
	Compliance *ModelCompliance `json:"compliance"`

	// Status of the model
	Status ModelStatus `json:"status"`

	// RegisteredAt when model was registered
	RegisteredAt time.Time `json:"registered_at"`

	// RegisteredBy who registered the model
	RegisteredBy string `json:"registered_by"`

	// LastUsedAt when model was last used
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	// UsageCount total times used
	UsageCount int64 `json:"usage_count"`
}

// ModelStatus represents model status
type ModelStatus string

const (
	ModelStatusPending  ModelStatus = "pending"
	ModelStatusActive   ModelStatus = "active"
	ModelStatusInactive ModelStatus = "inactive"
	ModelStatusRevoked  ModelStatus = "revoked"
)

// CreditInputSchema defines the input format for credit scoring
type CreditInputSchema struct {
	// Features list with their types and constraints
	Features []FeatureDefinition `json:"features"`

	// RequiredFeatures that must be provided
	RequiredFeatures []string `json:"required_features"`

	// FeatureCount total number of features
	FeatureCount int `json:"feature_count"`
}

// FeatureDefinition describes a single feature
type FeatureDefinition struct {
	// Name of the feature
	Name string `json:"name"`

	// Type of the feature (numeric, categorical, boolean)
	Type string `json:"type"`

	// Description of the feature
	Description string `json:"description"`

	// Min value (for numeric)
	Min *float64 `json:"min,omitempty"`

	// Max value (for numeric)
	Max *float64 `json:"max,omitempty"`

	// Categories (for categorical)
	Categories []string `json:"categories,omitempty"`

	// Required indicates if feature is mandatory
	Required bool `json:"required"`

	// Sensitive indicates if feature contains PII
	Sensitive bool `json:"sensitive"`
}

// CreditOutputSchema defines the output format
type CreditOutputSchema struct {
	// OutputType (score, probability, decision)
	OutputType string `json:"output_type"`

	// ScoreRange for score outputs
	ScoreRange *ScoreRange `json:"score_range,omitempty"`

	// ProbabilityRange for probability outputs
	ProbabilityRange *ProbabilityRange `json:"probability_range,omitempty"`

	// DecisionClasses for classification outputs
	DecisionClasses []string `json:"decision_classes,omitempty"`
}

// ScoreRange defines score output range
type ScoreRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// ProbabilityRange defines probability output range
type ProbabilityRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// ModelMetrics contains model performance metrics
type ModelMetrics struct {
	// AUC-ROC score
	AUCROC float64 `json:"auc_roc"`

	// Accuracy
	Accuracy float64 `json:"accuracy"`

	// Precision
	Precision float64 `json:"precision"`

	// Recall
	Recall float64 `json:"recall"`

	// F1 Score
	F1Score float64 `json:"f1_score"`

	// Gini coefficient
	Gini float64 `json:"gini"`

	// KS statistic
	KSStatistic float64 `json:"ks_statistic"`

	// ValidationDate when metrics were computed
	ValidationDate time.Time `json:"validation_date"`

	// ValidationDataset description
	ValidationDataset string `json:"validation_dataset"`
}

// ModelCompliance contains regulatory compliance information
type ModelCompliance struct {
	// Frameworks the model complies with
	Frameworks []string `json:"frameworks"`

	// FairLendingChecked indicates fair lending compliance
	FairLendingChecked bool `json:"fair_lending_checked"`

	// BiasAuditDate last bias audit
	BiasAuditDate *time.Time `json:"bias_audit_date,omitempty"`

	// BiasAuditResult summary of bias audit
	BiasAuditResult string `json:"bias_audit_result,omitempty"`

	// ExplainabilityLevel (low, medium, high)
	ExplainabilityLevel string `json:"explainability_level"`

	// ApprovedJurisdictions where model can be used
	ApprovedJurisdictions []string `json:"approved_jurisdictions"`
}

// LoanApplication represents a loan application for credit scoring
type LoanApplication struct {
	// ApplicationID unique identifier
	ApplicationID string `json:"application_id"`

	// ApplicantID anonymized identifier
	ApplicantID string `json:"applicant_id"`

	// LoanType (personal, mortgage, auto, business)
	LoanType string `json:"loan_type"`

	// LoanAmount requested
	LoanAmount float64 `json:"loan_amount"`

	// LoanTerm in months
	LoanTerm int `json:"loan_term"`

	// Features for credit scoring
	Features *CreditFeatures `json:"features"`

	// EncryptedFeatures if features are encrypted
	EncryptedFeatures []byte `json:"encrypted_features,omitempty"`

	// FeatureHash SHA-256 of original features
	FeatureHash []byte `json:"feature_hash"`

	// ModelID to use for scoring
	ModelID string `json:"model_id"`

	// Submitter who submitted the application
	Submitter string `json:"submitter"`

	// Status of the application
	Status ApplicationStatus `json:"status"`

	// CreatedAt timestamp
	CreatedAt time.Time `json:"created_at"`

	// ProcessedAt when processed
	ProcessedAt *time.Time `json:"processed_at,omitempty"`

	// Result of scoring
	Result *CreditScoringResult `json:"result,omitempty"`

	// SealID linking to Digital Seal
	SealID string `json:"seal_id,omitempty"`
}

// ApplicationStatus represents application status
type ApplicationStatus string

const (
	ApplicationStatusPending    ApplicationStatus = "pending"
	ApplicationStatusProcessing ApplicationStatus = "processing"
	ApplicationStatusCompleted  ApplicationStatus = "completed"
	ApplicationStatusFailed     ApplicationStatus = "failed"
	ApplicationStatusExpired    ApplicationStatus = "expired"
)

// CreditFeatures contains the features for credit scoring
type CreditFeatures struct {
	// Financial features
	AnnualIncome          float64 `json:"annual_income"`
	MonthlyDebt           float64 `json:"monthly_debt"`
	TotalAssets           float64 `json:"total_assets"`
	TotalLiabilities      float64 `json:"total_liabilities"`
	SavingsBalance        float64 `json:"savings_balance"`
	CheckingBalance       float64 `json:"checking_balance"`

	// Credit history
	CreditHistoryLength   int     `json:"credit_history_length"`   // months
	NumCreditAccounts     int     `json:"num_credit_accounts"`
	NumOpenAccounts       int     `json:"num_open_accounts"`
	CreditUtilization     float64 `json:"credit_utilization"`      // 0-1
	NumLatePayments       int     `json:"num_late_payments"`
	NumDelinquencies      int     `json:"num_delinquencies"`
	NumBankruptcies       int     `json:"num_bankruptcies"`
	NumCollections        int     `json:"num_collections"`
	AvgAccountAge         int     `json:"avg_account_age"`         // months

	// Employment
	EmploymentLength      int     `json:"employment_length"`       // months
	EmploymentStatus      string  `json:"employment_status"`       // employed, self_employed, unemployed, retired
	EmployerType          string  `json:"employer_type"`           // private, government, nonprofit

	// Demographics (anonymized)
	Age                   int     `json:"age"`
	DependentsCount       int     `json:"dependents_count"`
	HousingStatus         string  `json:"housing_status"`          // own, rent, mortgage
	ResidenceLength       int     `json:"residence_length"`        // months

	// Loan-specific
	DebtToIncomeRatio     float64 `json:"debt_to_income_ratio"`
	LoanToValueRatio      float64 `json:"loan_to_value_ratio,omitempty"`
	DownPaymentPercent    float64 `json:"down_payment_percent,omitempty"`

	// Inquiry data
	NumRecentInquiries    int     `json:"num_recent_inquiries"`    // last 6 months
	NumRecentAccounts     int     `json:"num_recent_accounts"`     // last 12 months
}

// ToVector converts features to a float64 slice for model input
func (cf *CreditFeatures) ToVector() []float64 {
	return []float64{
		cf.AnnualIncome / 1000000,          // Normalize to millions
		cf.MonthlyDebt / 10000,             // Normalize
		cf.TotalAssets / 1000000,
		cf.TotalLiabilities / 1000000,
		cf.SavingsBalance / 100000,
		cf.CheckingBalance / 100000,
		float64(cf.CreditHistoryLength) / 360, // Normalize to 30 years
		float64(cf.NumCreditAccounts) / 20,
		float64(cf.NumOpenAccounts) / 10,
		cf.CreditUtilization,
		float64(cf.NumLatePayments) / 10,
		float64(cf.NumDelinquencies) / 5,
		float64(cf.NumBankruptcies),
		float64(cf.NumCollections) / 5,
		float64(cf.AvgAccountAge) / 120,
		float64(cf.EmploymentLength) / 240,
		encodeEmploymentStatus(cf.EmploymentStatus),
		float64(cf.Age) / 100,
		float64(cf.DependentsCount) / 5,
		encodeHousingStatus(cf.HousingStatus),
		cf.DebtToIncomeRatio,
		float64(cf.NumRecentInquiries) / 10,
	}
}

// Hash computes the SHA-256 hash of the features
func (cf *CreditFeatures) Hash() []byte {
	data, _ := json.Marshal(cf)
	hash := sha256.Sum256(data)
	return hash[:]
}

func encodeEmploymentStatus(status string) float64 {
	switch status {
	case "employed":
		return 1.0
	case "self_employed":
		return 0.8
	case "retired":
		return 0.6
	case "unemployed":
		return 0.2
	default:
		return 0.5
	}
}

func encodeHousingStatus(status string) float64 {
	switch status {
	case "own":
		return 1.0
	case "mortgage":
		return 0.8
	case "rent":
		return 0.5
	default:
		return 0.3
	}
}

// CreditScoringResult contains the result of credit scoring
type CreditScoringResult struct {
	// ApplicationID for correlation
	ApplicationID string `json:"application_id"`

	// Score is the credit score (300-850)
	Score int `json:"score"`

	// ScoreCategory is the category
	ScoreCategory CreditScoreCategory `json:"score_category"`

	// Probability of default (0-1)
	DefaultProbability float64 `json:"default_probability"`

	// Decision (approved, denied, manual_review)
	Decision LoanDecision `json:"decision"`

	// RecommendedRate if approved
	RecommendedRate *float64 `json:"recommended_rate,omitempty"`

	// RecommendedLimit if approved
	RecommendedLimit *float64 `json:"recommended_limit,omitempty"`

	// RiskFactors contributing to the score
	RiskFactors []RiskFactor `json:"risk_factors"`

	// PositiveFactors helping the score
	PositiveFactors []string `json:"positive_factors"`

	// Confidence in the prediction (0-1)
	Confidence float64 `json:"confidence"`

	// ModelID used for scoring
	ModelID string `json:"model_id"`

	// ModelVersion
	ModelVersion string `json:"model_version"`

	// OutputHash SHA-256 of the result
	OutputHash []byte `json:"output_hash"`

	// VerificationType (tee, zkml, hybrid)
	VerificationType string `json:"verification_type"`

	// ProcessedAt timestamp
	ProcessedAt time.Time `json:"processed_at"`

	// ProcessingTimeMs how long it took
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// SealID for verification
	SealID string `json:"seal_id,omitempty"`
}

// RiskFactor describes a factor affecting the score
type RiskFactor struct {
	// Factor name
	Factor string `json:"factor"`

	// Impact on score (negative value)
	Impact int `json:"impact"`

	// Description of the factor
	Description string `json:"description"`

	// Recommendation to improve
	Recommendation string `json:"recommendation"`
}

// Hash computes the SHA-256 hash of the result
func (r *CreditScoringResult) Hash() []byte {
	data, _ := json.Marshal(r)
	hash := sha256.Sum256(data)
	return hash[:]
}

// GetScoreCategory returns the category for a score
func GetScoreCategory(score int) CreditScoreCategory {
	switch {
	case score >= 800:
		return CreditScoreExcellent
	case score >= 740:
		return CreditScoreVeryGood
	case score >= 670:
		return CreditScoreGood
	case score >= 580:
		return CreditScoreFair
	default:
		return CreditScorePoor
	}
}

// GetLoanDecision returns the loan decision based on score and other factors
func GetLoanDecision(score int, debtToIncome float64, bankruptcies int) LoanDecision {
	// Automatic denial criteria
	if bankruptcies > 0 && score < 620 {
		return LoanDecisionDenied
	}
	if debtToIncome > 0.50 {
		return LoanDecisionDenied
	}
	if score < 500 {
		return LoanDecisionDenied
	}

	// Automatic approval criteria
	if score >= 720 && debtToIncome < 0.36 {
		return LoanDecisionApproved
	}

	// Manual review for edge cases
	if score >= 580 && score < 720 {
		return LoanDecisionReview
	}
	if debtToIncome >= 0.36 && debtToIncome <= 0.50 {
		return LoanDecisionReview
	}

	// Default to manual review
	return LoanDecisionReview
}

// CalculateRecommendedRate calculates interest rate based on score
func CalculateRecommendedRate(score int, baseRate float64) float64 {
	// Risk premium based on credit score
	var riskPremium float64
	switch {
	case score >= 800:
		riskPremium = 0.0
	case score >= 740:
		riskPremium = 0.5
	case score >= 670:
		riskPremium = 1.5
	case score >= 580:
		riskPremium = 3.0
	default:
		riskPremium = 6.0
	}

	return baseRate + riskPremium
}

// NewLoanApplication creates a new loan application
func NewLoanApplication(
	applicantID string,
	loanType string,
	loanAmount float64,
	loanTerm int,
	features *CreditFeatures,
	modelID string,
	submitter string,
) *LoanApplication {
	app := &LoanApplication{
		ApplicantID: applicantID,
		LoanType:    loanType,
		LoanAmount:  loanAmount,
		LoanTerm:    loanTerm,
		Features:    features,
		FeatureHash: features.Hash(),
		ModelID:     modelID,
		Submitter:   submitter,
		Status:      ApplicationStatusPending,
		CreatedAt:   time.Now().UTC(),
	}

	// Generate application ID
	h := sha256.New()
	h.Write([]byte(applicantID))
	h.Write([]byte(loanType))
	h.Write([]byte(fmt.Sprintf("%f", loanAmount)))
	h.Write([]byte(submitter))
	h.Write([]byte(time.Now().String()))
	app.ApplicationID = "app-" + hex.EncodeToString(h.Sum(nil))[:16]

	return app
}

// DefaultCreditScoringModel returns the default credit scoring model definition
func DefaultCreditScoringModel() *CreditScoringModel {
	minIncome := float64(0)
	maxIncome := float64(10000000)
	minAge := float64(18)
	maxAge := float64(100)

	return &CreditScoringModel{
		ModelID:     "credit-score-v1",
		Name:        "Aethelred Credit Score Model v1",
		Version:     "1.0.0",
		Description: "Neural network-based credit scoring model for consumer lending",
		InputSchema: &CreditInputSchema{
			Features: []FeatureDefinition{
				{Name: "annual_income", Type: "numeric", Description: "Annual income in USD", Min: &minIncome, Max: &maxIncome, Required: true, Sensitive: true},
				{Name: "monthly_debt", Type: "numeric", Description: "Monthly debt payments", Required: true, Sensitive: true},
				{Name: "credit_history_length", Type: "numeric", Description: "Credit history in months", Required: true},
				{Name: "num_credit_accounts", Type: "numeric", Description: "Number of credit accounts", Required: true},
				{Name: "credit_utilization", Type: "numeric", Description: "Credit utilization ratio (0-1)", Required: true},
				{Name: "num_late_payments", Type: "numeric", Description: "Number of late payments", Required: true},
				{Name: "employment_length", Type: "numeric", Description: "Employment length in months", Required: true},
				{Name: "age", Type: "numeric", Description: "Age in years", Min: &minAge, Max: &maxAge, Required: true, Sensitive: true},
				{Name: "debt_to_income_ratio", Type: "numeric", Description: "Debt to income ratio", Required: true},
			},
			RequiredFeatures: []string{"annual_income", "credit_history_length", "credit_utilization", "debt_to_income_ratio"},
			FeatureCount:     22,
		},
		OutputSchema: &CreditOutputSchema{
			OutputType: "score",
			ScoreRange: &ScoreRange{Min: 300, Max: 850},
		},
		Metrics: &ModelMetrics{
			AUCROC:            0.85,
			Accuracy:          0.82,
			Precision:         0.80,
			Recall:            0.78,
			F1Score:           0.79,
			Gini:              0.70,
			KSStatistic:       0.45,
			ValidationDate:    time.Now().UTC(),
			ValidationDataset: "credit_bureau_sample_2024",
		},
		Compliance: &ModelCompliance{
			Frameworks:            []string{"FCRA", "ECOA", "Basel_III"},
			FairLendingChecked:    true,
			ExplainabilityLevel:   "high",
			ApprovedJurisdictions: []string{"US", "UAE", "UK", "EU"},
		},
		Status:       ModelStatusActive,
		RegisteredAt: time.Now().UTC(),
	}
}
