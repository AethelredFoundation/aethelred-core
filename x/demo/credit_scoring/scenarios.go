package credit_scoring

import (
	demotypes "github.com/aethelred/aethelred/x/demo/types"
)

// DemoScenario represents a pre-defined demo scenario
type DemoScenario struct {
	// ID unique identifier
	ID string `json:"id"`

	// Name of the scenario
	Name string `json:"name"`

	// Description of the scenario
	Description string `json:"description"`

	// ExpectedOutcome what should happen
	ExpectedOutcome string `json:"expected_outcome"`

	// ExpectedScore range
	ExpectedScoreMin int `json:"expected_score_min"`
	ExpectedScoreMax int `json:"expected_score_max"`

	// ExpectedDecision
	ExpectedDecision demotypes.LoanDecision `json:"expected_decision"`

	// ApplicantID for the scenario
	ApplicantID string `json:"applicant_id"`

	// LoanType
	LoanType string `json:"loan_type"`

	// LoanAmount
	LoanAmount float64 `json:"loan_amount"`

	// LoanTerm in months
	LoanTerm int `json:"loan_term"`

	// Features for the application
	Features *demotypes.CreditFeatures `json:"features"`

	// Category of the scenario
	Category string `json:"category"`

	// Tags for filtering
	Tags []string `json:"tags"`
}

// GetDemoScenarios returns all pre-defined demo scenarios
func GetDemoScenarios() []*DemoScenario {
	return []*DemoScenario{
		// Excellent Credit Scenarios
		{
			ID:               "excellent-prime-borrower",
			Name:             "Prime Borrower - Auto Loan",
			Description:      "High-income professional with excellent credit history applying for auto loan",
			ExpectedOutcome:  "Automatic approval with best rates",
			ExpectedScoreMin: 780,
			ExpectedScoreMax: 850,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-001",
			LoanType:         "auto",
			LoanAmount:       45000,
			LoanTerm:         60,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        185000,
				MonthlyDebt:         2500,
				TotalAssets:         450000,
				TotalLiabilities:    120000,
				SavingsBalance:      85000,
				CheckingBalance:     25000,
				CreditHistoryLength: 180, // 15 years
				NumCreditAccounts:   8,
				NumOpenAccounts:     5,
				CreditUtilization:   0.12,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       96,
				EmploymentLength:    120, // 10 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 42,
				DependentsCount:     2,
				HousingStatus:       "own",
				ResidenceLength:     84,
				DebtToIncomeRatio:   0.16,
				NumRecentInquiries:  1,
				NumRecentAccounts:   0,
			},
			Category: "excellent",
			Tags:     []string{"auto", "prime", "high-income"},
		},

		{
			ID:               "excellent-mortgage-refinance",
			Name:             "Mortgage Refinance - Established Professional",
			Description:      "Doctor with long credit history refinancing home mortgage",
			ExpectedOutcome:  "Automatic approval with competitive rates",
			ExpectedScoreMin: 800,
			ExpectedScoreMax: 850,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-002",
			LoanType:         "mortgage",
			LoanAmount:       350000,
			LoanTerm:         360,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        320000,
				MonthlyDebt:         4200,
				TotalAssets:         1200000,
				TotalLiabilities:    380000,
				SavingsBalance:      150000,
				CheckingBalance:     45000,
				CreditHistoryLength: 240, // 20 years
				NumCreditAccounts:   12,
				NumOpenAccounts:     6,
				CreditUtilization:   0.08,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       144,
				EmploymentLength:    180, // 15 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 48,
				DependentsCount:     3,
				HousingStatus:       "mortgage",
				ResidenceLength:     120,
				DebtToIncomeRatio:   0.16,
				LoanToValueRatio:    0.65,
				NumRecentInquiries:  0,
				NumRecentAccounts:   0,
			},
			Category: "excellent",
			Tags:     []string{"mortgage", "refinance", "high-income"},
		},

		// Good Credit Scenarios
		{
			ID:               "good-personal-loan",
			Name:             "Personal Loan - Mid-Career Professional",
			Description:      "Software engineer with good credit seeking personal loan for home improvement",
			ExpectedOutcome:  "Approval with favorable rates",
			ExpectedScoreMin: 780,
			ExpectedScoreMax: 820,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-003",
			LoanType:         "personal",
			LoanAmount:       25000,
			LoanTerm:         48,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        115000,
				MonthlyDebt:         1800,
				TotalAssets:         180000,
				TotalLiabilities:    65000,
				SavingsBalance:      35000,
				CheckingBalance:     12000,
				CreditHistoryLength: 96, // 8 years
				NumCreditAccounts:   6,
				NumOpenAccounts:     4,
				CreditUtilization:   0.28,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       60,
				EmploymentLength:    60, // 5 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 32,
				DependentsCount:     1,
				HousingStatus:       "mortgage",
				ResidenceLength:     36,
				DebtToIncomeRatio:   0.19,
				NumRecentInquiries:  2,
				NumRecentAccounts:   1,
			},
			Category: "good",
			Tags:     []string{"personal", "home-improvement"},
		},

		{
			ID:               "good-small-business",
			Name:             "Small Business Loan - Entrepreneur",
			Description:      "Established small business owner seeking expansion capital",
			ExpectedOutcome:  "Approval with standard business rates",
			ExpectedScoreMin: 720,
			ExpectedScoreMax: 760,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-004",
			LoanType:         "business",
			LoanAmount:       100000,
			LoanTerm:         84,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        145000,
				MonthlyDebt:         3500,
				TotalAssets:         320000,
				TotalLiabilities:    95000,
				SavingsBalance:      45000,
				CheckingBalance:     28000,
				CreditHistoryLength: 144, // 12 years
				NumCreditAccounts:   9,
				NumOpenAccounts:     5,
				CreditUtilization:   0.35,
				NumLatePayments:     1,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       84,
				EmploymentLength:    96, // 8 years self-employed
				EmploymentStatus:    "self_employed",
				EmployerType:        "private",
				Age:                 45,
				DependentsCount:     2,
				HousingStatus:       "own",
				ResidenceLength:     60,
				DebtToIncomeRatio:   0.29,
				NumRecentInquiries:  3,
				NumRecentAccounts:   1,
			},
			Category: "good",
			Tags:     []string{"business", "self-employed", "expansion"},
		},

		// Fair Credit - Manual Review Scenarios
		{
			ID:               "fair-credit-rebuilding",
			Name:             "Credit Rebuilding - Recent Improvement",
			Description:      "Applicant recovering from past financial difficulties, showing recent improvement",
			ExpectedOutcome:  "Manual review recommended due to past issues but positive recent trend",
			ExpectedScoreMin: 650,
			ExpectedScoreMax: 690,
			ExpectedDecision: demotypes.LoanDecisionReview,
			ApplicantID:      "applicant-005",
			LoanType:         "personal",
			LoanAmount:       10000,
			LoanTerm:         36,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        58000,
				MonthlyDebt:         950,
				TotalAssets:         35000,
				TotalLiabilities:    22000,
				SavingsBalance:      8000,
				CheckingBalance:     3500,
				CreditHistoryLength: 72, // 6 years
				NumCreditAccounts:   4,
				NumOpenAccounts:     3,
				CreditUtilization:   0.45,
				NumLatePayments:     3,
				NumDelinquencies:    1,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       42,
				EmploymentLength:    48, // 4 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 35,
				DependentsCount:     1,
				HousingStatus:       "rent",
				ResidenceLength:     24,
				DebtToIncomeRatio:   0.20,
				NumRecentInquiries:  2,
				NumRecentAccounts:   2,
			},
			Category: "fair",
			Tags:     []string{"rebuilding", "improvement", "personal"},
		},

		{
			ID:               "fair-high-dti",
			Name:             "High Debt-to-Income - Consolidation",
			Description:      "Good income but high existing debt seeking consolidation loan",
			ExpectedOutcome:  "Manual review due to debt-to-income ratio concerns",
			ExpectedScoreMin: 650,
			ExpectedScoreMax: 690,
			ExpectedDecision: demotypes.LoanDecisionReview,
			ApplicantID:      "applicant-006",
			LoanType:         "personal",
			LoanAmount:       35000,
			LoanTerm:         60,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        78000,
				MonthlyDebt:         2800,
				TotalAssets:         95000,
				TotalLiabilities:    75000,
				SavingsBalance:      12000,
				CheckingBalance:     5500,
				CreditHistoryLength: 84, // 7 years
				NumCreditAccounts:   7,
				NumOpenAccounts:     5,
				CreditUtilization:   0.62,
				NumLatePayments:     1,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       48,
				EmploymentLength:    36, // 3 years
				EmploymentStatus:    "employed",
				EmployerType:        "government",
				Age:                 38,
				DependentsCount:     2,
				HousingStatus:       "rent",
				ResidenceLength:     18,
				DebtToIncomeRatio:   0.43,
				NumRecentInquiries:  4,
				NumRecentAccounts:   2,
			},
			Category: "fair",
			Tags:     []string{"consolidation", "high-dti"},
		},

		// Poor Credit - Denial Scenarios
		{
			ID:               "poor-recent-bankruptcy",
			Name:             "Recent Bankruptcy - High Risk",
			Description:      "Applicant with recent bankruptcy and ongoing financial stress",
			ExpectedOutcome:  "Denial due to bankruptcy and credit profile",
			ExpectedScoreMin: 300,
			ExpectedScoreMax: 420,
			ExpectedDecision: demotypes.LoanDecisionDenied,
			ApplicantID:      "applicant-007",
			LoanType:         "personal",
			LoanAmount:       5000,
			LoanTerm:         24,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        42000,
				MonthlyDebt:         600,
				TotalAssets:         8000,
				TotalLiabilities:    15000,
				SavingsBalance:      1500,
				CheckingBalance:     800,
				CreditHistoryLength: 36, // 3 years (post-bankruptcy)
				NumCreditAccounts:   2,
				NumOpenAccounts:     2,
				CreditUtilization:   0.85,
				NumLatePayments:     5,
				NumDelinquencies:    2,
				NumBankruptcies:     1,
				NumCollections:      1,
				AvgAccountAge:       18,
				EmploymentLength:    12, // 1 year
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 29,
				DependentsCount:     0,
				HousingStatus:       "rent",
				ResidenceLength:     6,
				DebtToIncomeRatio:   0.17,
				NumRecentInquiries:  6,
				NumRecentAccounts:   2,
			},
			Category: "poor",
			Tags:     []string{"bankruptcy", "high-risk", "rebuilding"},
		},

		{
			ID:               "poor-excessive-debt",
			Name:             "Excessive Debt Load - Overextended",
			Description:      "Applicant severely overextended with high utilization and delinquencies",
			ExpectedOutcome:  "Denial due to excessive debt and payment history",
			ExpectedScoreMin: 300,
			ExpectedScoreMax: 360,
			ExpectedDecision: demotypes.LoanDecisionDenied,
			ApplicantID:      "applicant-008",
			LoanType:         "personal",
			LoanAmount:       15000,
			LoanTerm:         36,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        52000,
				MonthlyDebt:         2400,
				TotalAssets:         25000,
				TotalLiabilities:    48000,
				SavingsBalance:      2000,
				CheckingBalance:     1200,
				CreditHistoryLength: 60, // 5 years
				NumCreditAccounts:   8,
				NumOpenAccounts:     6,
				CreditUtilization:   0.92,
				NumLatePayments:     8,
				NumDelinquencies:    3,
				NumBankruptcies:     0,
				NumCollections:      2,
				AvgAccountAge:       36,
				EmploymentLength:    24, // 2 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 34,
				DependentsCount:     2,
				HousingStatus:       "rent",
				ResidenceLength:     12,
				DebtToIncomeRatio:   0.55,
				NumRecentInquiries:  8,
				NumRecentAccounts:   4,
			},
			Category: "poor",
			Tags:     []string{"overextended", "high-utilization", "delinquent"},
		},

		// Edge Cases
		{
			ID:               "edge-thin-file",
			Name:             "Thin Credit File - New Graduate",
			Description:      "Recent graduate with limited credit history but good income",
			ExpectedOutcome:  "Approval with standard rates (thin file but strong profile)",
			ExpectedScoreMin: 740,
			ExpectedScoreMax: 780,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-009",
			LoanType:         "auto",
			LoanAmount:       22000,
			LoanTerm:         60,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        72000,
				MonthlyDebt:         450,
				TotalAssets:         15000,
				TotalLiabilities:    28000,
				SavingsBalance:      8000,
				CheckingBalance:     4500,
				CreditHistoryLength: 18, // 1.5 years
				NumCreditAccounts:   2,
				NumOpenAccounts:     2,
				CreditUtilization:   0.22,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       12,
				EmploymentLength:    12, // 1 year
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 24,
				DependentsCount:     0,
				HousingStatus:       "rent",
				ResidenceLength:     12,
				DebtToIncomeRatio:   0.08,
				NumRecentInquiries:  3,
				NumRecentAccounts:   2,
			},
			Category: "edge",
			Tags:     []string{"thin-file", "new-graduate", "limited-history"},
		},

		{
			ID:               "edge-retired-assets",
			Name:             "Retired with Assets",
			Description:      "Retired applicant with substantial assets but fixed income",
			ExpectedOutcome:  "Approval based on asset strength",
			ExpectedScoreMin: 790,
			ExpectedScoreMax: 830,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-010",
			LoanType:         "personal",
			LoanAmount:       30000,
			LoanTerm:         48,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        68000, // Pension + SS
				MonthlyDebt:         800,
				TotalAssets:         850000,
				TotalLiabilities:    45000,
				SavingsBalance:      250000,
				CheckingBalance:     35000,
				CreditHistoryLength: 420, // 35 years
				NumCreditAccounts:   10,
				NumOpenAccounts:     4,
				CreditUtilization:   0.05,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       240,
				EmploymentLength:    0,
				EmploymentStatus:    "retired",
				EmployerType:        "private",
				Age:                 68,
				DependentsCount:     0,
				HousingStatus:       "own",
				ResidenceLength:     240,
				DebtToIncomeRatio:   0.14,
				NumRecentInquiries:  0,
				NumRecentAccounts:   0,
			},
			Category: "edge",
			Tags:     []string{"retired", "assets", "fixed-income"},
		},

		// UAE/Abu Dhabi Specific Scenarios
		{
			ID:               "uae-expat-professional",
			Name:             "UAE Expat Professional",
			Description:      "Expatriate professional in Abu Dhabi with established banking history",
			ExpectedOutcome:  "Approval for UAE market",
			ExpectedScoreMin: 760,
			ExpectedScoreMax: 790,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-uae-001",
			LoanType:         "personal",
			LoanAmount:       150000, // AED equivalent
			LoanTerm:         48,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        250000, // ~$68k USD
				MonthlyDebt:         5000,
				TotalAssets:         400000,
				TotalLiabilities:    100000,
				SavingsBalance:      80000,
				CheckingBalance:     25000,
				CreditHistoryLength: 60, // 5 years in UAE
				NumCreditAccounts:   4,
				NumOpenAccounts:     3,
				CreditUtilization:   0.25,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       36,
				EmploymentLength:    60, // 5 years
				EmploymentStatus:    "employed",
				EmployerType:        "private",
				Age:                 38,
				DependentsCount:     2,
				HousingStatus:       "rent",
				ResidenceLength:     48,
				DebtToIncomeRatio:   0.24,
				NumRecentInquiries:  1,
				NumRecentAccounts:   0,
			},
			Category: "uae",
			Tags:     []string{"uae", "expat", "abu-dhabi"},
		},

		{
			ID:               "uae-sme-financing",
			Name:             "UAE SME Financing",
			Description:      "Small business owner in UAE Free Zone seeking growth capital",
			ExpectedOutcome:  "Approval with SME-specific terms",
			ExpectedScoreMin: 690,
			ExpectedScoreMax: 740,
			ExpectedDecision: demotypes.LoanDecisionApproved,
			ApplicantID:      "applicant-uae-002",
			LoanType:         "business",
			LoanAmount:       500000, // AED
			LoanTerm:         60,
			Features: &demotypes.CreditFeatures{
				AnnualIncome:        450000, // Business revenue
				MonthlyDebt:         12000,
				TotalAssets:         750000,
				TotalLiabilities:    200000,
				SavingsBalance:      120000,
				CheckingBalance:     65000,
				CreditHistoryLength: 48, // 4 years
				NumCreditAccounts:   5,
				NumOpenAccounts:     4,
				CreditUtilization:   0.32,
				NumLatePayments:     0,
				NumDelinquencies:    0,
				NumBankruptcies:     0,
				NumCollections:      0,
				AvgAccountAge:       30,
				EmploymentLength:    48, // Business age
				EmploymentStatus:    "self_employed",
				EmployerType:        "private",
				Age:                 42,
				DependentsCount:     3,
				HousingStatus:       "rent",
				ResidenceLength:     36,
				DebtToIncomeRatio:   0.32,
				NumRecentInquiries:  2,
				NumRecentAccounts:   1,
			},
			Category: "uae",
			Tags:     []string{"uae", "sme", "free-zone", "business"},
		},
	}
}

// GetScenarioByID returns a scenario by ID
func GetScenarioByID(id string) *DemoScenario {
	scenarios := GetDemoScenarios()
	for _, s := range scenarios {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// GetScenariosByCategory returns scenarios by category
func GetScenariosByCategory(category string) []*DemoScenario {
	scenarios := GetDemoScenarios()
	filtered := make([]*DemoScenario, 0)
	for _, s := range scenarios {
		if s.Category == category {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// GetScenariosByTag returns scenarios by tag
func GetScenariosByTag(tag string) []*DemoScenario {
	scenarios := GetDemoScenarios()
	filtered := make([]*DemoScenario, 0)
	for _, s := range scenarios {
		for _, t := range s.Tags {
			if t == tag {
				filtered = append(filtered, s)
				break
			}
		}
	}
	return filtered
}
