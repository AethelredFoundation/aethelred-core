//go:build !race
// +build !race

package credit_scoring_test

import (
	"context"
	"testing"
	"time"

	"cosmossdk.io/log"

	cs "github.com/aethelred/aethelred/x/demo/credit_scoring"
	demotypes "github.com/aethelred/aethelred/x/demo/types"
)

// TestPipelineCreation tests pipeline creation
func TestPipelineCreation(t *testing.T) {
	logger := log.NewNopLogger()
	config := cs.DefaultPipelineConfig()

	pipeline := cs.NewCreditScoringPipeline(logger, config)
	if pipeline == nil {
		t.Fatal("Pipeline should not be nil")
	}

	// Check default model is registered
	model, err := pipeline.GetModel("credit-score-v1")
	if err != nil {
		t.Fatalf("Default model should be registered: %v", err)
	}

	if model.Status != demotypes.ModelStatusActive {
		t.Errorf("Default model should be active, got %s", model.Status)
	}
}

// TestApplicationSubmission tests application submission
func TestApplicationSubmission(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	features := createTestFeatures(80000, 0.25, 0, 0.30)
	app := demotypes.NewLoanApplication(
		"test-applicant-1",
		"personal",
		25000,
		48,
		features,
		"credit-score-v1",
		"test",
	)

	submitted, err := pipeline.SubmitApplication(ctx, app)
	if err != nil {
		t.Fatalf("Failed to submit application: %v", err)
	}

	if submitted.ApplicationID == "" {
		t.Error("Application ID should be generated")
	}

	if submitted.Status != demotypes.ApplicationStatusPending {
		t.Errorf("Status should be pending, got %s", submitted.Status)
	}
}

// TestApplicationProcessing tests application processing
func TestApplicationProcessing(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	features := createTestFeatures(100000, 0.20, 0, 0.25)
	app := demotypes.NewLoanApplication(
		"test-applicant-2",
		"auto",
		35000,
		60,
		features,
		"credit-score-v1",
		"test",
	)

	// Submit
	submitted, err := pipeline.SubmitApplication(ctx, app)
	if err != nil {
		t.Fatalf("Failed to submit: %v", err)
	}

	// Process
	result, err := pipeline.ProcessApplication(ctx, submitted.ApplicationID)
	if err != nil {
		t.Fatalf("Failed to process: %v", err)
	}

	// Validate result
	if result.Score < demotypes.CreditScoreMin || result.Score > demotypes.CreditScoreMax {
		t.Errorf("Score out of range: %d", result.Score)
	}

	if result.DefaultProbability < 0 || result.DefaultProbability > 1 {
		t.Errorf("Default probability out of range: %f", result.DefaultProbability)
	}

	if result.Decision == "" {
		t.Error("Decision should not be empty")
	}

	if result.Confidence < 0.5 || result.Confidence > 1 {
		t.Errorf("Confidence out of range: %f", result.Confidence)
	}
}

// TestExcellentCreditScore tests excellent credit scenario
func TestExcellentCreditScore(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	// Create excellent credit features
	features := &demotypes.CreditFeatures{
		AnnualIncome:        200000,
		MonthlyDebt:         2000,
		TotalAssets:         500000,
		TotalLiabilities:    100000,
		SavingsBalance:      100000,
		CheckingBalance:     30000,
		CreditHistoryLength: 180,
		NumCreditAccounts:   10,
		NumOpenAccounts:     5,
		CreditUtilization:   0.10,
		NumLatePayments:     0,
		NumDelinquencies:    0,
		NumBankruptcies:     0,
		NumCollections:      0,
		AvgAccountAge:       96,
		EmploymentLength:    120,
		EmploymentStatus:    "employed",
		Age:                 45,
		DependentsCount:     2,
		HousingStatus:       "own",
		ResidenceLength:     84,
		DebtToIncomeRatio:   0.12,
		NumRecentInquiries:  0,
		NumRecentAccounts:   0,
	}

	app := demotypes.NewLoanApplication(
		"excellent-credit-test",
		"mortgage",
		500000,
		360,
		features,
		"credit-score-v1",
		"test",
	)

	pipeline.SubmitApplication(ctx, app)
	result, err := pipeline.ProcessApplication(ctx, app.ApplicationID)
	if err != nil {
		t.Fatalf("Failed to process: %v", err)
	}

	// Should have excellent score
	if result.Score < 750 {
		t.Errorf("Expected excellent score (750+), got %d", result.Score)
	}

	// Should be approved
	if result.Decision != demotypes.LoanDecisionApproved {
		t.Errorf("Expected approved, got %s", result.Decision)
	}

	// Should have low default probability
	if result.DefaultProbability > 0.05 {
		t.Errorf("Expected low default probability, got %f", result.DefaultProbability)
	}
}

// TestPoorCreditScore tests poor credit scenario
func TestPoorCreditScore(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	// Create poor credit features
	features := &demotypes.CreditFeatures{
		AnnualIncome:        35000,
		MonthlyDebt:         1500,
		TotalAssets:         5000,
		TotalLiabilities:    25000,
		SavingsBalance:      500,
		CheckingBalance:     200,
		CreditHistoryLength: 24,
		NumCreditAccounts:   3,
		NumOpenAccounts:     3,
		CreditUtilization:   0.90,
		NumLatePayments:     6,
		NumDelinquencies:    2,
		NumBankruptcies:     1,
		NumCollections:      2,
		AvgAccountAge:       12,
		EmploymentLength:    6,
		EmploymentStatus:    "employed",
		Age:                 28,
		DependentsCount:     1,
		HousingStatus:       "rent",
		ResidenceLength:     6,
		DebtToIncomeRatio:   0.51,
		NumRecentInquiries:  8,
		NumRecentAccounts:   3,
	}

	app := demotypes.NewLoanApplication(
		"poor-credit-test",
		"personal",
		5000,
		24,
		features,
		"credit-score-v1",
		"test",
	)

	pipeline.SubmitApplication(ctx, app)
	result, err := pipeline.ProcessApplication(ctx, app.ApplicationID)
	if err != nil {
		t.Fatalf("Failed to process: %v", err)
	}

	// Should have poor score
	if result.Score > 580 {
		t.Errorf("Expected poor score (<580), got %d", result.Score)
	}

	// Should be denied
	if result.Decision != demotypes.LoanDecisionDenied {
		t.Errorf("Expected denied, got %s", result.Decision)
	}

	// Should have high default probability
	if result.DefaultProbability < 0.30 {
		t.Errorf("Expected high default probability, got %f", result.DefaultProbability)
	}

	// Should have risk factors
	if len(result.RiskFactors) == 0 {
		t.Error("Expected risk factors for poor credit")
	}
}

// TestRiskFactorAnalysis tests risk factor identification
func TestRiskFactorAnalysis(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	// Features with specific risk factors
	features := &demotypes.CreditFeatures{
		AnnualIncome:        75000,
		MonthlyDebt:         2000,
		TotalAssets:         50000,
		TotalLiabilities:    30000,
		SavingsBalance:      10000,
		CheckingBalance:     5000,
		CreditHistoryLength: 12, // Short history - should flag
		NumCreditAccounts:   4,
		NumOpenAccounts:     3,
		CreditUtilization:   0.75, // High utilization - should flag
		NumLatePayments:     3,    // Late payments - should flag
		NumDelinquencies:    0,
		NumBankruptcies:     0,
		NumCollections:      0,
		AvgAccountAge:       8,
		EmploymentLength:    24,
		EmploymentStatus:    "employed",
		Age:                 30,
		DependentsCount:     1,
		HousingStatus:       "rent",
		ResidenceLength:     12,
		DebtToIncomeRatio:   0.40, // High DTI - should flag
		NumRecentInquiries:  5,    // Many inquiries - should flag
		NumRecentAccounts:   2,
	}

	app := demotypes.NewLoanApplication(
		"risk-factor-test",
		"personal",
		15000,
		36,
		features,
		"credit-score-v1",
		"test",
	)

	pipeline.SubmitApplication(ctx, app)
	result, err := pipeline.ProcessApplication(ctx, app.ApplicationID)
	if err != nil {
		t.Fatalf("Failed to process: %v", err)
	}

	// Check for expected risk factors
	expectedFactors := []string{
		"short_credit_history",
		"high_credit_utilization",
		"late_payments",
		"high_debt_to_income",
		"recent_inquiries",
	}

	foundFactors := make(map[string]bool)
	for _, rf := range result.RiskFactors {
		foundFactors[rf.Factor] = true
	}

	for _, expected := range expectedFactors {
		if !foundFactors[expected] {
			t.Errorf("Expected risk factor '%s' not found", expected)
		}
	}
}

// TestScoreCategories tests score category assignment
func TestScoreCategories(t *testing.T) {
	tests := []struct {
		score    int
		expected demotypes.CreditScoreCategory
	}{
		{820, demotypes.CreditScoreExcellent},
		{750, demotypes.CreditScoreVeryGood},
		{700, demotypes.CreditScoreGood},
		{620, demotypes.CreditScoreFair},
		{500, demotypes.CreditScorePoor},
	}

	for _, tc := range tests {
		category := demotypes.GetScoreCategory(tc.score)
		if category != tc.expected {
			t.Errorf("Score %d: expected %s, got %s", tc.score, tc.expected, category)
		}
	}
}

// TestLoanDecisions tests loan decision logic
func TestLoanDecisions(t *testing.T) {
	tests := []struct {
		score        int
		dti          float64
		bankruptcies int
		expected     demotypes.LoanDecision
	}{
		{780, 0.25, 0, demotypes.LoanDecisionApproved},
		{650, 0.35, 0, demotypes.LoanDecisionReview},
		{500, 0.45, 1, demotypes.LoanDecisionDenied},
		{720, 0.55, 0, demotypes.LoanDecisionDenied}, // High DTI
		{600, 0.30, 1, demotypes.LoanDecisionDenied}, // Bankruptcy + low score
	}

	for _, tc := range tests {
		decision := demotypes.GetLoanDecision(tc.score, tc.dti, tc.bankruptcies)
		if decision != tc.expected {
			t.Errorf("Score %d, DTI %.2f, Bankruptcies %d: expected %s, got %s",
				tc.score, tc.dti, tc.bankruptcies, tc.expected, decision)
		}
	}
}

// TestRateCalculation tests interest rate calculation
func TestRateCalculation(t *testing.T) {
	baseRate := 5.0

	tests := []struct {
		score   int
		minRate float64
		maxRate float64
	}{
		{820, 5.0, 5.5},
		{750, 5.0, 6.0},
		{700, 6.0, 7.0},
		{620, 7.5, 9.0},
		{500, 10.0, 12.0},
	}

	for _, tc := range tests {
		rate := demotypes.CalculateRecommendedRate(tc.score, baseRate)
		if rate < tc.minRate || rate > tc.maxRate {
			t.Errorf("Score %d: rate %.2f not in range [%.2f, %.2f]",
				tc.score, rate, tc.minRate, tc.maxRate)
		}
	}
}

// TestProcessor tests the application processor
func TestProcessor(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())
	processor := cs.NewApplicationProcessor(logger, pipeline, cs.DefaultProcessorConfig())

	// Start processor
	processor.Start()
	defer processor.Stop()

	ctx := context.Background()

	features := createTestFeatures(90000, 0.22, 0, 0.28)
	app := demotypes.NewLoanApplication(
		"processor-test",
		"auto",
		30000,
		60,
		features,
		"credit-score-v1",
		"test",
	)

	// Submit
	task, err := processor.Submit(ctx, app)
	if err != nil {
		t.Fatalf("Failed to submit: %v", err)
	}

	if task == nil {
		t.Fatal("Task should not be nil")
	}

	// Wait for completion
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := processor.WaitForCompletion(ctx2, app.ApplicationID)
	if err != nil {
		t.Fatalf("Failed to wait for completion: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Score == 0 {
		t.Error("Score should not be zero")
	}
}

// TestVerificationOrchestrator tests the verification orchestrator
func TestVerificationOrchestrator(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())
	processor := cs.NewApplicationProcessor(logger, pipeline, cs.DefaultProcessorConfig())
	processor.Start()
	defer processor.Stop()

	orchestrator := cs.NewVerificationOrchestrator(logger, processor, pipeline)

	ctx := context.Background()

	features := createTestFeatures(85000, 0.18, 0, 0.25)
	app := demotypes.NewLoanApplication(
		"verification-test",
		"personal",
		20000,
		36,
		features,
		"credit-score-v1",
		"test",
	)

	// Process with verification
	verifiedResult, err := orchestrator.ProcessWithVerification(ctx, app)
	if err != nil {
		t.Fatalf("Failed to process with verification: %v", err)
	}

	if verifiedResult.SealID == "" {
		t.Error("Seal ID should be generated")
	}

	if verifiedResult.Result == nil {
		t.Fatal("Result should not be nil")
	}

	// Verify consensus
	consensusResult, err := orchestrator.SimulateConsensusVerification(ctx, verifiedResult.SealID)
	if err != nil {
		t.Fatalf("Failed to simulate consensus: %v", err)
	}

	if !consensusResult.Verified {
		t.Error("Consensus should be verified")
	}

	if len(consensusResult.Attestations) < 3 {
		t.Error("Should have multiple validator attestations")
	}
}

// TestDemoScenarios tests that all demo scenarios run successfully
func TestDemoScenarios(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()
	scenarios := cs.GetDemoScenarios()

	for _, scenario := range scenarios {
		t.Run(scenario.ID, func(t *testing.T) {
			app := demotypes.NewLoanApplication(
				scenario.ApplicantID,
				scenario.LoanType,
				scenario.LoanAmount,
				scenario.LoanTerm,
				scenario.Features,
				"credit-score-v1",
				"test",
			)

			pipeline.SubmitApplication(ctx, app)
			result, err := pipeline.ProcessApplication(ctx, app.ApplicationID)
			if err != nil {
				t.Fatalf("Failed to process scenario %s: %v", scenario.ID, err)
			}

			// Verify score is in expected range
			if result.Score < scenario.ExpectedScoreMin || result.Score > scenario.ExpectedScoreMax {
				t.Errorf("Score %d not in expected range [%d, %d]",
					result.Score, scenario.ExpectedScoreMin, scenario.ExpectedScoreMax)
			}

			// Verify decision matches expected
			if result.Decision != scenario.ExpectedDecision {
				t.Errorf("Expected decision %s, got %s", scenario.ExpectedDecision, result.Decision)
			}
		})
	}
}

// TestMetrics tests metrics collection
func TestMetrics(t *testing.T) {
	logger := log.NewNopLogger()
	pipeline := cs.NewCreditScoringPipeline(logger, cs.DefaultPipelineConfig())

	ctx := context.Background()

	// Process several applications
	for i := 0; i < 5; i++ {
		features := createTestFeatures(float64(60000+i*10000), 0.25, 0, 0.30)
		app := demotypes.NewLoanApplication(
			"metrics-test-"+string(rune('a'+i)),
			"personal",
			float64(10000+i*5000),
			36,
			features,
			"credit-score-v1",
			"test",
		)

		pipeline.SubmitApplication(ctx, app)
		pipeline.ProcessApplication(ctx, app.ApplicationID)
	}

	metrics := pipeline.GetMetrics()

	if metrics.TotalApplications != 5 {
		t.Errorf("Expected 5 total applications, got %d", metrics.TotalApplications)
	}

	if metrics.ProcessedApplications != 5 {
		t.Errorf("Expected 5 processed applications, got %d", metrics.ProcessedApplications)
	}

	if metrics.AverageScore < 300 || metrics.AverageScore > 850 {
		t.Errorf("Average score out of range: %f", metrics.AverageScore)
	}

	if metrics.AverageProcessingTimeMs <= 0 {
		t.Error("Average processing time should be positive")
	}
}

// TestFeatureVector tests feature vector conversion
func TestFeatureVector(t *testing.T) {
	features := &demotypes.CreditFeatures{
		AnnualIncome:      100000,
		MonthlyDebt:       2000,
		CreditUtilization: 0.30,
		DebtToIncomeRatio: 0.24,
		EmploymentStatus:  "employed",
		Age:               35,
		HousingStatus:     "mortgage",
	}

	vector := features.ToVector()

	if len(vector) == 0 {
		t.Error("Vector should not be empty")
	}

	// First element is normalized income
	if vector[0] != 0.1 { // 100000 / 1000000
		t.Errorf("Expected normalized income 0.1, got %f", vector[0])
	}
}

// TestFeatureHash tests feature hashing
func TestFeatureHash(t *testing.T) {
	features1 := createTestFeatures(80000, 0.25, 0, 0.30)
	features2 := createTestFeatures(80000, 0.25, 0, 0.30)
	features3 := createTestFeatures(90000, 0.25, 0, 0.30) // Different income

	hash1 := features1.Hash()
	hash2 := features2.Hash()
	hash3 := features3.Hash()

	if len(hash1) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(hash1))
	}

	// Same features should produce same hash
	if string(hash1) != string(hash2) {
		t.Error("Same features should produce same hash")
	}

	// Different features should produce different hash
	if string(hash1) == string(hash3) {
		t.Error("Different features should produce different hash")
	}
}

// Helper function to create test features
func createTestFeatures(income float64, utilization float64, latePayments int, dti float64) *demotypes.CreditFeatures {
	return &demotypes.CreditFeatures{
		AnnualIncome:        income,
		MonthlyDebt:         income * dti / 12,
		TotalAssets:         income * 2,
		TotalLiabilities:    income * 0.5,
		SavingsBalance:      income * 0.25,
		CheckingBalance:     income * 0.1,
		CreditHistoryLength: 72,
		NumCreditAccounts:   5,
		NumOpenAccounts:     3,
		CreditUtilization:   utilization,
		NumLatePayments:     latePayments,
		NumDelinquencies:    0,
		NumBankruptcies:     0,
		NumCollections:      0,
		AvgAccountAge:       48,
		EmploymentLength:    36,
		EmploymentStatus:    "employed",
		EmployerType:        "private",
		Age:                 35,
		DependentsCount:     1,
		HousingStatus:       "mortgage",
		ResidenceLength:     24,
		DebtToIncomeRatio:   dti,
		NumRecentInquiries:  1,
		NumRecentAccounts:   0,
	}
}
